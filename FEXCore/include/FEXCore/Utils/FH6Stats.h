// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>

// Process-wide event counters for translation churn. Written by FEX::Windows when
// FEX_FH6_STATS=1; counting is always on and only happens on slow paths.
extern "C" uint64_t fh6_stats[55];
extern "C" uint64_t fh6_pool_keys[65536];
// First clone/compile mismatch: {guest rip, copy size, compiled size, first differing offset}, then both images.
extern "C" uint64_t fh6_clone_bad_info[4];
extern "C" uint8_t fh6_clone_bad[2][1024];
extern "C" uint64_t fh6_smc[4096][3];
// Guest exceptions raised from JIT code, keyed by guest rip: {rip, count, exception code, first 8 guest bytes}.
// Slot 0's count holds the overflow.
extern "C" uint64_t fh6_exc[256][4];
// Sampled shape rejects: {rip, blocks, block0 insns, block0 size, compile length, entry points, 32 guest bytes}.
extern "C" uint64_t fh6_shape[64][10];
extern "C" uint64_t fh6_shape_tick;
// Ring of {guest rip, host code} for every block entered into a GuestToHostMap, for attributing
// host profile samples to guest code. Null (and skipped) unless the stats writer allocated it.
extern "C" uint64_t (*fh6_blockmap)[2];
extern "C" uint64_t fh6_blockmap_count;

namespace FEXCore::FH6Stats {
enum Counter : uint32_t {
  CompileBlockMiss = 0,  // CompileBlock found nothing in L1/L2/L3
  JITCompiles = 1,       // backend compiles that produced new code
  JITGuestBytes = 2,     // guest bytes covered by those compiles
  ReviveAttempts = 3,    // misses that had dormant translations for the RIP
  CodeBufferOverflows = 4, // full code buffer continued in fresh memory on the same map
  ReviveHashMiss = 5,    // guest bytes differed
  ReviveSigMiss = 6,     // page executability/writability differed
  DormantStored = 7,     // erased translations kept for reuse
  SMCMismatch = 8,       // in-block CRC check failed
  ProtNotify = 9,        // NtProtectVirtualMemory notifications
  ProtInvalidate = 10,   // notifications that invalidated
  RWXFaultInvalidate = 11,
  AlignedInvalidate = 12, // InvalidateAlignedInterval calls
  IntervalInvalidate = 13, // all-thread invalidations
  ThreadInvalidateRun = 14,
  ThreadInvalidateSkipped = 15, // thread had no cached code on those pages
  ClearCacheNewBuffer = 16,
  ClearCacheKeepBuffer = 17,
  IntervalInvalidateTicks = 18,
  JITCompileTicks = 19,
  DiskCacheHits = 20,
  ProtInvalidateBytes = 21,
  DR7SingleStepCompiles = 22,  // CompileBlock forced MaxInst=1 for an x86 execute breakpoint
  FreeInvalidate = 23,         // NotifyMemoryFree calls
  FreeSkippedNonExec = 24, // frees and writes skipped: no executable page in range
  FlushICacheInvalidate = 25,  // FlushInstructionCache / NotifyMemoryDirty calls
  SetContextPendingFlush = 26, // SetContext calls that flushed pending RWX intervals
  BoundaryEvicts = 27,         // GenerateIR mid-block invalid/dispatch boundary evictions
  RacedCompiles = 28,          // CompileCode found another thread already compiled the block
  CodeBufferUpdates = 29,      // threads migrated to a newer SharedCodeBuffer
  BlockInvalidate = 30,        // SMC mismatches that dropped one block instead of its page
  StaleSMCMismatch = 31,       // SMC mismatch from an old copy; current translation kept
  JITHostBytes = 32,           // host code bytes produced by JITCompiles
  PoolCompiles = 33,           // compiles of code outside any image section
  PoolJmpForm = 34,            // ... whose guest bytes end in jmp rel32
  PoolKeyRepeat = 35,          // ... whose bytes (jmp target made absolute) were compiled recently
  PoolCloneHits = 36,          // pool stubs translated by patching a copy of an earlier translation
  PoolVerifyOK = 37,           // FEX_POOL_CLONE=2: patched copy identical to the fresh compile
  PoolVerifyBad = 38,          // ... different (first one kept in fh6_clone_bad)
  PoolTemplatesStored = 39,
  PoolRejectNotCandidate = 40, // non-image fresh compiles that weren't pool candidates
  PoolRejectShape = 41,        // not exactly one block of two instructions ending at a 5-byte jmp
  PoolRejectInsn = 42,         // first instruction branches or is RIP-relative
  PoolRejectBytes = 43,        // re-read bytes have no jmp, or the target is next to the slot
  PoolRejectReloc = 44,        // unexpected relocation type or offset
  PoolRejectRelocValue = 45,   // a guest RIP constant that is neither in the slot nor the jump target
  PoolRejectCrc = 46,          // no entry CRC, or it doesn't match the re-read bytes
  PoolRejectNotWritable = 47,
  LinkCalls = 48,              // ExitFunctionLink entries (unlinked exits taken)
  LinkCompiled = 49,           // ... that had to call CompileBlock for the target
  LinkNotPinned = 50,          // ... returned without linking: an end outside the code buffers
  LinkNotOwned = 51,           // ... returned without linking: target not what the lookup cache holds
  LinkSharedMismatch = 52,     // ... returned without linking: shared map holds another block
  LinkMade = 53,               // links written (direct branch or far HostCode pointer)
  LinkAdopted = 54,            // ... to the shared map's block after dropping a stale L1 copy
  NumCounters = 55,
};

// SMC mismatch histogram keyed by guest page: {page, count, last block entry}. Open
// addressing with a short probe; misses past the probe are counted in slot 0's count.
static constexpr size_t SMCSlots = 4096;

inline void NoteSMC(uint64_t Rip, uint64_t Resume) {
  size_t Slot = static_cast<size_t>((Rip * 0x9E3779B97F4A7C15ULL) >> 52) & (SMCSlots - 1);
  for (size_t Probe = 0; Probe < 16; ++Probe, Slot = (Slot + 1) & (SMCSlots - 1)) {
    if (Slot == 0) {
      continue;
    }
    uint64_t Key = __atomic_load_n(&fh6_smc[Slot][0], __ATOMIC_RELAXED);
    if (Key == 0) {
      uint64_t Expected = 0;
      if (__atomic_compare_exchange_n(&fh6_smc[Slot][0], &Expected, Rip, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        Key = Rip;
      } else {
        Key = Expected;
      }
    }
    if (Key == Rip) {
      __atomic_fetch_add(&fh6_smc[Slot][1], 1, __ATOMIC_RELAXED);
      __atomic_store_n(&fh6_smc[Slot][2], Resume, __ATOMIC_RELAXED);
      return;
    }
  }
  __atomic_fetch_add(&fh6_smc[0][1], 1, __ATOMIC_RELAXED);
}

inline void NoteException(uint64_t Rip, uint32_t Code) {
  size_t Slot = static_cast<size_t>((Rip * 0x9E3779B97F4A7C15ULL) >> 56);
  for (size_t Probe = 0; Probe < 16; ++Probe, Slot = (Slot + 1) & 255) {
    if (Slot == 0) {
      continue;
    }
    uint64_t Key = __atomic_load_n(&fh6_exc[Slot][0], __ATOMIC_RELAXED);
    if (Key == 0) {
      uint64_t Expected = 0;
      if (__atomic_compare_exchange_n(&fh6_exc[Slot][0], &Expected, Rip, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        // Only instructions the frontend just decoded are known to be readable.
        if (Code == 0xC000001D || Code == 0xC0000096 || Code == 0x80000003) {
          uint64_t Bytes;
          __builtin_memcpy(&Bytes, reinterpret_cast<const void*>(Rip), sizeof(Bytes));
          __atomic_store_n(&fh6_exc[Slot][3], Bytes, __ATOMIC_RELAXED);
        }
        Key = Rip;
      } else {
        Key = Expected;
      }
    }
    if (Key == Rip) {
      __atomic_store_n(&fh6_exc[Slot][2], Code, __ATOMIC_RELAXED);
      __atomic_fetch_add(&fh6_exc[Slot][1], 1, __ATOMIC_RELAXED);
      return;
    }
  }
  __atomic_fetch_add(&fh6_exc[0][1], 1, __ATOMIC_RELAXED);
}

static constexpr size_t BlockMapSlots = size_t {1} << 21;

inline void NoteBlock(uint64_t Rip, uint64_t HostCode) {
  auto* Map = __atomic_load_n(&fh6_blockmap, __ATOMIC_ACQUIRE);
  if (!Map) {
    return;
  }
  const uint64_t Slot = __atomic_fetch_add(&fh6_blockmap_count, 1, __ATOMIC_RELAXED) & (BlockMapSlots - 1);
  __atomic_store_n(&Map[Slot][1], HostCode, __ATOMIC_RELAXED);
  __atomic_store_n(&Map[Slot][0], Rip, __ATOMIC_RELEASE);
}

inline void Add(Counter C, uint64_t V = 1) {
  __atomic_fetch_add(&fh6_stats[C], V, __ATOMIC_RELAXED);
}

inline void NoteCloneMismatch(uint64_t Rip, const uint8_t* Copy, uint64_t CopySize, const uint8_t* Compiled, uint64_t CompiledSize) {
  uint64_t Expected = 0;
  if (!__atomic_compare_exchange_n(&fh6_clone_bad_info[0], &Expected, ~0ULL, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
    return;
  }
  uint64_t Diff = 0;
  while (Diff < CopySize && Diff < CompiledSize && Copy[Diff] == Compiled[Diff]) {
    ++Diff;
  }
  __builtin_memcpy(fh6_clone_bad[0], Copy, CopySize < 1024 ? CopySize : 1024);
  __builtin_memcpy(fh6_clone_bad[1], Compiled, CompiledSize < 1024 ? CompiledSize : 1024);
  fh6_clone_bad_info[1] = CopySize;
  fh6_clone_bad_info[2] = CompiledSize;
  fh6_clone_bad_info[3] = Diff;
  __atomic_store_n(&fh6_clone_bad_info[0], Rip, __ATOMIC_RELEASE);
}

// One reject in 512 overwrites a slot of fh6_shape; rows may tear, which only matters for display.
inline void NoteShape(uint64_t Rip, uint64_t Blocks, uint64_t Insns, uint64_t BlockSize, uint64_t Length, uint64_t EntryPoints) {
  const uint64_t Tick = __atomic_fetch_add(&fh6_shape_tick, 1, __ATOMIC_RELAXED);
  if (Tick & 511) {
    return;
  }
  auto& Row = fh6_shape[(Tick >> 9) & 63];
  Row[1] = Blocks;
  Row[2] = Insns;
  Row[3] = BlockSize;
  Row[4] = Length;
  Row[5] = EntryPoints;
  __builtin_memset(&Row[6], 0, 32);
  __builtin_memcpy(&Row[6], reinterpret_cast<const void*>(Rip), Length < 32 ? Length : 32);
  __atomic_store_n(&Row[0], Rip, __ATOMIC_RELEASE);
}

// Direct-mapped set of recent content keys, so a repeat means "same bytes compiled not long ago".
inline void NotePoolCompile(const uint8_t* Code, uint64_t Length) {
  Add(PoolCompiles);
  uint64_t Body = Length;
  uint64_t Key = 0x9E3779B97F4A7C15ULL;
  if (Length >= 5 && Code[Length - 5] == 0xE9) {
    int32_t Rel;
    __builtin_memcpy(&Rel, Code + Length - 4, sizeof(Rel));
    Key ^= reinterpret_cast<uint64_t>(Code) + Length + static_cast<int64_t>(Rel);
    Body = Length - 5;
    Add(PoolJmpForm);
  } else {
    Key ^= reinterpret_cast<uint64_t>(Code);
  }
  for (uint64_t i = 0; i < Body; ++i) {
    Key = (Key ^ Code[i]) * 0x100000001B3ULL;
  }
  Key = (Key ^ (Key >> 29)) * 0xBF58476D1CE4E5B9ULL;
  Key |= 1;
  auto& Slot = fh6_pool_keys[(Key >> 40) & 65535];
  if (__atomic_exchange_n(&Slot, Key, __ATOMIC_RELAXED) == Key) {
    Add(PoolKeyRepeat);
  }
}

inline uint64_t Ticks() {
  uint64_t T;
  __asm volatile("mrs %0, cntvct_el0" : "=r"(T));
  return T;
}
} // namespace FEXCore::FH6Stats
