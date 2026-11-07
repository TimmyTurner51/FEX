// SPDX-License-Identifier: MIT
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/SharedCodeBufferManager.h"

#include <FEXCore/fextl/memory.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>

#include <cstdlib>

#ifndef _WIN32
#include <FEXCore/Utils/PrctlUtils.h>
#endif

namespace FEXCore::CPU {
static constexpr size_t INITIAL_CODE_SIZE = 1024 * 1024 * 16;
// We don't want to move above 128MB atm because that means we will have to encode longer jumps
static constexpr size_t MAX_CODE_SIZE = 1024 * 1024 * 128;

CodeBuffer::CodeBuffer(size_t Size, bool ShouldBeNamed, fextl::shared_ptr<CodeBuffer> Prev)
  : LookupCache(Prev ? Prev->LookupCache : fextl::make_shared<GuestToHostMap>())
  , PrevInChain(std::move(Prev))
  , ChainBytes(Size + (PrevInChain ? PrevInChain->ChainBytes : 0))
  , AllocatedSize(Size) {
  Ptr = static_cast<uint8_t*>(FEXCore::Allocator::VirtualAlloc(Size, true));
  LOGMAN_THROW_A_FMT(!!Ptr, "Couldn't allocate code buffer");

  // Protect the last page of the allocated buffer to trigger SIGSEGV on write access
  uintptr_t LastPageAddr = AlignDown(reinterpret_cast<uintptr_t>(Ptr) + Size - 1, FEXCore::Utils::FEX_PAGE_SIZE);
  if (!FEXCore::Allocator::VirtualProtect(reinterpret_cast<void*>(LastPageAddr), FEXCore::Utils::FEX_PAGE_SIZE,
                                          FEXCore::Allocator::ProtectOptions::None)) {
    LogMan::Msg::EFmt("Failed to mprotect last page of code buffer.");
  }

  if (ShouldBeNamed) {
    FEXCore::Allocator::VirtualName("FEXMemJIT", Ptr, Size);
  }

  // Huge-pages reduce the amount of iTLB misses dramatically when it works.
  FEXCore::Allocator::VirtualTHPControl(Ptr, Size, FEXCore::Allocator::THPControl::Enable);

  CodeBufferEnd = Ptr + UsableSize();
  CodeBufferOffset = Ptr;
}

CodeBuffer::~CodeBuffer() {
  FEXCore::Allocator::VirtualFree(Ptr, AllocatedSize);
}

SharedCodeBufferManager::SharedCodeBufferManager() {
  FEX_CONFIG_OPT(GlobalJITNaming, GLOBALJITNAMING);
  FEX_CONFIG_OPT(LibraryJITNaming, LIBRARYJITNAMING);
  FEX_CONFIG_OPT(BlockJITNaming, BLOCKJITNAMING);

  // Only name the JIT buffers if perf JIT naming is disabled.
  // `perf top` prefers VMA names over the JIT symbols file for some reason.
  // Breaks memory tracking when naming is enabled, but it's a debug feature so it isn't expected to be enabled by default.
  NameJITBuffers = !(GlobalJITNaming || LibraryJITNaming || BlockJITNaming);

  const char* Budget = getenv("FEX_CODE_BUDGET_MB");
  CodeBudget = size_t {Budget ? strtoull(Budget, nullptr, 10) : 1024} * 1024 * 1024;
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::AllocateNew(size_t Size, fextl::shared_ptr<CodeBuffer> Prev) {
#ifndef _WIN32
  // MDWE (Memory-Deny-Write-Execute) is a new Linux 6.3 feature.
  // It's equivalent to systemd's `MemoryDenyWriteExecute` but implemented entirely in the kernel.
  //
  // MDWE prevents applications from creating RWX memory mappings.
  // This prevents FEX from doing anything JIT related, as FEX uses RWX for JIT memory mappings.
  //
  // A potential workaround to make FEX work with MDWE is to call mprotect every time we need to write or modify code.
  // Alternatively, FEX could use a memory mirror where one half is mapped as RW and the other is RX.
  //
  // Once MDWE is enabled with the prctl, the feature is sealed and it can /NOT/ be turned off.
  //
  // Status of MDWE is queried through prctl using `PR_GET_MDWE`:
  // -1: The kernel doesn't support MDWE
  // 0: MDWE is supported but disabled
  // >0: MDWE is enabled, hence prohibiting RWX mappings
  int MDWE = ::prctl(PR_GET_MDWE, 0, 0, 0, 0);
  if (MDWE != -1 && MDWE != 0) {
    LogMan::Msg::EFmt("MDWE was set to 0x{:x} which means FEX can't allocate executable memory", MDWE);
  }
#endif

  auto Buffer = fextl::make_shared<CodeBuffer>(Size, NameJITBuffers, std::move(Prev));

  Latest = Buffer;

  OnCodeBufferAllocated(Buffer);

  return Buffer;
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::GetLatest() {
  std::scoped_lock lk {LatestMutex};
  if (!Latest) {
    AllocateNew(INITIAL_CODE_SIZE);
  }
  return Latest;
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartLargerCodeBuffer() {
  std::scoped_lock lk {LatestMutex};
  if (!Latest) {
    return AllocateNew(INITIAL_CODE_SIZE);
  }

  auto NewCodeBufferSize = Latest->TotalAllocationSize();
  NewCodeBufferSize = std::min<size_t>(NewCodeBufferSize * 2, MAX_CODE_SIZE);
  return AllocateNew(NewCodeBufferSize);
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartMaximalCodeBuffer() {
  std::scoped_lock lk {LatestMutex};
  return AllocateNew(MAX_CODE_SIZE);
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartOverflowCodeBuffer(const CodeBuffer* Prev) {
  std::scoped_lock lk {LatestMutex};
  if (!Latest) {
    return AllocateNew(INITIAL_CODE_SIZE);
  }
  if (Latest.get() != Prev) {
    return Latest;
  }

  const auto NewCodeBufferSize = std::min<size_t>(Latest->TotalAllocationSize() * 2, MAX_CODE_SIZE);
  if (Latest->ChainBytes + NewCodeBufferSize > CodeBudget) {
    return nullptr;
  }
  return AllocateNew(NewCodeBufferSize, Latest);
}
} // namespace FEXCore::CPU
