// SPDX-License-Identifier: MIT
/*
$info$
category: code buffer ~ Thread shared code buffer management
tags: backend|shared
$end_info$
*/
#pragma once

#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace FEXCore {
struct GuestToHostMap;
}

namespace FEXCore::CPU {
struct CodeBuffer {
  // Shared by every buffer of one overflow chain; see SharedCodeBufferManager::StartOverflowCodeBuffer.
  fextl::shared_ptr<GuestToHostMap> LookupCache;

  // The buffer this one continues. The shared map hands out code from every buffer of the chain,
  // so holding any of them keeps all older ones alive.
  const fextl::shared_ptr<CodeBuffer> PrevInChain;

  // Allocation size of this buffer and all older ones in its chain.
  const size_t ChainBytes;

  CodeBuffer(size_t Size, bool ShouldBeNamed, fextl::shared_ptr<CodeBuffer> Prev = nullptr);
  CodeBuffer(const CodeBuffer&) = delete;
  CodeBuffer& operator=(const CodeBuffer&) = delete;
  CodeBuffer(CodeBuffer&& oth) = delete;
  CodeBuffer& operator=(CodeBuffer&&) = delete;

  ~CodeBuffer();

  // Atomically allocate a fixed size buffer out of the current allocated codebuffer.
  // Lockless because it's just a linear allocator.
  struct CodeBufferAllocation {
    const uint8_t* BufferBase;
    uint8_t* BufferAllocationOffset;
  };

  CodeBufferAllocation AtomicAllocateBuffer(size_t Size) {
    Size = FEXCore::AlignUp(Size, 16);
    LOGMAN_THROW_A_FMT(reinterpret_cast<uintptr_t>(CodeBufferOffset.load()) % 16 == 0, "Buffer needs to always be 16B aligned!");

    auto ExpectedOffset = CodeBufferOffset.load(std::memory_order_relaxed);
    auto DesiredOffset = ExpectedOffset + Size;

    if (DesiredOffset > CodeBufferEnd) {
      // Couldn't fit.
      return {};
    }

    while (!CodeBufferOffset.compare_exchange_strong(ExpectedOffset, DesiredOffset)) {
      DesiredOffset = ExpectedOffset + Size;

      if (DesiredOffset > CodeBufferEnd) {
        // Couldn't fit.
        return {};
      }
    }

    // Managed to fit.
    return {
      .BufferBase = Ptr,
      .BufferAllocationOffset = ExpectedOffset,
    };
  }

  // Returns the total number of bytes available for storing code
  size_t UsableSize() const {
    return AllocatedSize - FEXCore::Utils::FEX_PAGE_SIZE;
  }

  // Returns the full size of the buffer, including the guard page.
  size_t TotalAllocationSize() const {
    return AllocatedSize;
  }

  // Returns the num of bytes currently allocated from the allocator.
  size_t AllocatedSpaceUsed() const {
    return CodeBufferOffset - Ptr;
  }

  // Trivially reset the allocator.
  void Reset() {
    CodeBufferOffset = Ptr;
  }

  // Returns the base of the buffer.
  uint8_t* GetBufferBase() const {
    return Ptr;
  }

  // True if Address is in any code buffer still allocated, whichever chain it belongs to. A thread that
  // moved to a newer chain can still be running linked blocks or call-ret returns in an older one. Signal-safe.
  static bool AnyLiveContains(uintptr_t Address);

  // True if Address is code in this buffer or an older one of its chain. Signal-safe.
  bool ChainContains(uintptr_t Address) const {
    for (const CodeBuffer* Buffer = this; Buffer; Buffer = Buffer->PrevInChain.get()) {
      const auto Begin = reinterpret_cast<uintptr_t>(Buffer->Ptr);
      if (Address >= Begin && Address < Begin + Buffer->UsableSize()) {
        return true;
      }
    }
    return false;
  }

private:
  uint8_t* Ptr;
  uint8_t* CodeBufferEnd;
  size_t AllocatedSize; // including guard page; see UsableSize()

  // Code buffer allocation information.
  std::atomic<uint8_t*> CodeBufferOffset {};
};

/**
 * A manager that coordinates access to the CodeBuffer used for compiling new code across threads.
 *
 * The CodeBuffer is managed as a partially persistent data structure:
 * - Exactly one CodeBuffer is now designated as "active", which means data can be appended to it
 * - Lossy modifications to the active CodeBuffer will not invalidate any data in use by other threads (which is what enables save CodeBuffer sharing across threads)
 * - Instead, such lossy modifications trigger a new "version" of the data in the modifying thread. Old versions of the CodeBuffer persist as read-only data for use by the other threads.
 * - The other threads can update their version of the CodeBuffer. This will decrease the reference count and eventually trigger deallocation of the old version
 */
class SharedCodeBufferManager {
public:
  SharedCodeBufferManager();
  virtual ~SharedCodeBufferManager() = default;

  // Get the CodeBuffer that was most recently allocated.
  // This is the only CodeBuffer that data may be written to.
  fextl::shared_ptr<CodeBuffer> GetLatest();

  // Allocate a new CodeBuffer with geometric growth up to an internal maximum.
  // Subsequent calls to GetLatest will point to the returned buffer.
  fextl::shared_ptr<CodeBuffer> StartLargerCodeBuffer();

  // Allocate a new CodeBuffer with maximum internal size.
  // Subsequent calls to GetLatest will point to the returned buffer.
  fextl::shared_ptr<CodeBuffer> StartMaximalCodeBuffer();

  // The latest buffer is full: allocate fresh code memory that shares its GuestToHostMap, so
  // every translation stays reachable instead of being recompiled. Returns the current latest
  // instead if another thread already replaced `Prev`, or null once the chain would exceed the
  // code budget (FEX_CODE_BUDGET_MB), in which case the caller clears the code cache.
  fextl::shared_ptr<CodeBuffer> StartOverflowCodeBuffer(const CodeBuffer* Prev);

  virtual void OnCodeBufferAllocated(const std::shared_ptr<CodeBuffer>&) {};

private:
  std::mutex LatestMutex;
  fextl::shared_ptr<CodeBuffer> Latest;
  size_t CodeBudget;

  fextl::shared_ptr<CodeBuffer> AllocateNew(size_t Size, fextl::shared_ptr<CodeBuffer> Prev = nullptr);

  bool NameJITBuffers {true};
};
} // namespace FEXCore::CPU
