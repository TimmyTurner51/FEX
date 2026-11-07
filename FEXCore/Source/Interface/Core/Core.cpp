// SPDX-License-Identifier: MIT
/*
$info$
category: glue ~ Logic that binds various parts together
meta: glue|driver ~ Emulation mainloop related glue logic
tags: glue|driver
desc: Glues Frontend, OpDispatcher and IR Opts & Compilation, LookupCache, Dispatcher and provides the Execution loop entrypoint
$end_info$
*/

#include <cstdint>
#ifdef ZYDIS_DISASSEMBLER
#include <Zydis/Zydis.h>
#endif
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/CPUID.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/OpcodeDispatcher.h"
#include "Interface/Core/JIT/JITClass.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#include "Interface/Core/X86Tables/X86Tables.h"
#include <Interface/GDBJIT/GDBJIT.h>
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "Utils/Allocator.h"
#include "Utils/Allocator/HostAllocator.h"
#include "Utils/crc32.h"
#include <FEXCore/Utils/SpinWaitLock.h>
#include "Utils/variable_length_integer.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/Event.h>
#include <FEXCore/Utils/File.h>
#include <FEXCore/Utils/LogManager.h>
#include "FEXCore/Utils/SignalScopeGuards.h"
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/FH6Stats.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/sstream.h>
#include <FEXCore/fextl/unordered_map.h>
#include <FEXCore/fextl/vector.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <signal.h>
#include <stdio.h>
#include <string_view>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <xxhash.h>

namespace FEXCore::Context {
namespace {
// Read once here: getenv takes the CRT environment lock, which must not be taken while compiling.
int PoolCloneModeValue = 1;
} // namespace

ContextImpl::ContextImpl(const FEXCore::HostFeatures& Features)
  : HostFeatures {Features}
  , CPUID {this}
  , CodeCache {*this} {
  if (const char* Env = getenv("FEX_POOL_CLONE")) {
    PoolCloneModeValue = atoi(Env);
  }
  if (!Config.Is64BitMode()) {
    // When operating in 32-bit mode, the virtual memory we care about is only the lower 32-bits.
    Config.VirtualMemSize = 1ULL << 32;
  }

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Only initialize symbols file if enabled. Ensures we don't pollute /tmp with empty files.
    Symbols.InitFile(Features.ProcessPID);
  }

  uint64_t FrequencyCounter = FEXCore::GetCycleCounterFrequency();
  if (FrequencyCounter && FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM && Config.SmallTSCScale()) {
    // Scale TSC until it is at the minimum required.
    while (FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM) {
      FrequencyCounter <<= 1;
      ++Config.TSCScale;
    }
  }

  // Track atomic TSO emulation configuration.
  UpdateAtomicTSOEmulationConfig();

#ifndef _WIN32
  // Check if the kernel supports getrandom().
  uint64_t Probe {};
  HostRNGAvailable = FHU::Syscalls::getrandom(&Probe, sizeof(Probe), 0) == sizeof(Probe);
#else
  HostRNGAvailable = true;
#endif

  DiskCache.Init(this);
}

struct GetFrameBlockInfoResult {
  const CPU::CPUBackend::JITCodeHeader* InlineHeader;
  const CPU::CPUBackend::JITCodeTail* InlineTail;
};
static GetFrameBlockInfoResult GetFrameBlockInfo(FEXCore::Core::CpuStateFrame* Frame) {
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto InlineHeader = reinterpret_cast<const CPU::CPUBackend::JITCodeHeader*>(BlockBegin);

  if (InlineHeader) {
    auto InlineTail = reinterpret_cast<const CPU::CPUBackend::JITCodeTail*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail);
    return {InlineHeader, InlineTail};
  }

  return {InlineHeader, nullptr};
}

bool ContextImpl::IsAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && (Address + Size > InlineTail->RIP && Address < InlineTail->RIP + InlineTail->GuestSize);
}

bool ContextImpl::IsCurrentBlockSingleInst(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && InlineTail->SingleInst;
}

uint64_t ContextImpl::GetGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail ? InlineTail->RIP : 0;
}

uint64_t ContextImpl::RestoreRIPFromHostPC(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) {
  const auto Frame = Thread->CurrentFrame;
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto [InlineHeader, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);

  if (InlineHeader) {
    // Check if the host PC is currently within a code block.
    // If it is then RIP can be reconstructed from the beginning of the code block.
    // This is currently as close as FEX can get RIP reconstructions.
    if (HostPC >= reinterpret_cast<uint64_t>(BlockBegin) && HostPC < reinterpret_cast<uint64_t>(BlockBegin + InlineTail->Size)) {

      auto RIPEntry =
        reinterpret_cast<const uint8_t*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail + InlineTail->OffsetToRIPEntries);

      // Reconstruct RIP from JIT entries for this block.
      uint64_t StartingHostPC = BlockBegin;
      uint64_t StartingGuestRIP = InlineTail->RIP;

      for (uint32_t i = 0; i < InlineTail->NumberOfRIPEntries; ++i) {
        auto Offset = FEXCore::Utils::vl64pair::Decode(RIPEntry);
        RIPEntry += Offset.Size;
        if (HostPC >= (StartingHostPC + Offset.IntegerARMPC)) {
          // We are beyond this entry, keep going forward.
          StartingHostPC += Offset.IntegerARMPC;
          StartingGuestRIP += Offset.IntegerX86RIP;
        } else {
          // Passed where the Host PC is at. Break now.
          break;
        }
      }
      return StartingGuestRIP;
    }
  }

  // Fallback to what is stored in the RIP currently.
  return Frame->State.rip;
}

uint32_t ContextImpl::ReconstructCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, bool WasInJIT, const uint64_t* HostGPRs,
                                                 uint64_t PSTATE) {
  const auto Frame = Thread->CurrentFrame;
  uint32_t EFLAGS {};

  // Currently these flags just map 1:1 inside of the resulting value.
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_PF_RAW_LOC:
    case X86State::RFLAG_AF_RAW_LOC:
    case X86State::RFLAG_TF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_DF_RAW_LOC:
      // Intentionally do nothing.
      // These contain multiple bits which can corrupt other members when compacted.
      break;
    default: EFLAGS |= uint32_t {Frame->State.flags[i]} << i; break;
    }
  }

  uint32_t Packed_NZCV {};
  if (WasInJIT) {
    // If we were in the JIT then NZCV is in the CPU's PSTATE object.
    // Packed in to the same bit locations as RFLAG_NZCV_LOC.
    Packed_NZCV = PSTATE;

    // If we were in the JIT then PF and AF are in registers.
    // Move them to the CPUState frame now.
    Frame->State.pf_raw = HostGPRs[CPU::REG_PF.Idx()];
    Frame->State.af_raw = HostGPRs[CPU::REG_AF.Idx()];
  } else {
    // If we were not in the JIT then the NZCV state is stored in the CPUState RFLAG_NZCV_LOC.
    // SF/ZF/CF/OF are packed in a 32-bit value in RFLAG_NZCV_LOC.
    memcpy(&Packed_NZCV, &Frame->State.flags[X86State::RFLAG_NZCV_LOC], sizeof(Packed_NZCV));
  }

  uint32_t OF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC)) & 1;
  uint32_t CF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC)) & 1;
  uint32_t ZF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC)) & 1;
  uint32_t SF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC)) & 1;

  // CF is inverted in our representation, undo the invert here.
  CF ^= 1;

  // Pack in to EFLAGS
  EFLAGS |= OF << X86State::RFLAG_OF_RAW_LOC;
  EFLAGS |= CF << X86State::RFLAG_CF_RAW_LOC;
  EFLAGS |= ZF << X86State::RFLAG_ZF_RAW_LOC;
  EFLAGS |= SF << X86State::RFLAG_SF_RAW_LOC;

  // PF calculation is deferred, calculate it now.
  // Popcount the 8-bit flag and then extract the lower bit.
  uint32_t PFByte = Frame->State.pf_raw & 0xff;
  uint32_t PF = std::popcount(PFByte ^ 1) & 1;
  EFLAGS |= PF << X86State::RFLAG_PF_RAW_LOC;

  // AF calculation is deferred, calculate it now.
  // XOR with PF byte and extract bit 4.
  uint32_t AF = ((Frame->State.af_raw ^ PFByte) & (1 << 4)) ? 1 : 0;
  EFLAGS |= AF << X86State::RFLAG_AF_RAW_LOC;

  uint8_t TFByte = Frame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  EFLAGS |= (TFByte & 1) << X86State::RFLAG_TF_RAW_LOC;

  // DF is pretransformed, undo the transform from 1/-1 back to 0/1
  uint8_t DFByte = Frame->State.flags[X86State::RFLAG_DF_RAW_LOC];
  if (DFByte & 0x80) {
    EFLAGS |= 1 << X86State::RFLAG_DF_RAW_LOC;
  }

  return EFLAGS;
}

void ContextImpl::ReconstructXMMRegisters(const FEXCore::Core::InternalThreadState* Thread, __uint128_t* XMM_Low, __uint128_t* YMM_High) {
  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;

  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.avx.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.xmm.avx.data[i][2], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.sse.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.avx_high[i][0], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(XMM_Low, Thread->CurrentFrame->State.xmm.sse.data, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetXMMRegistersFromState(FEXCore::Core::InternalThreadState* Thread, const __uint128_t* XMM_Low, const __uint128_t* YMM_High) {
  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;
  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][2], &YMM_High[i], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.sse.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.avx_high[i][0], &YMM_High[i], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(Thread->CurrentFrame->State.xmm.sse.data, XMM_Low, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetFlagsFromCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, uint32_t EFLAGS) {
  const auto Frame = Thread->CurrentFrame;
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
      // Intentionally do nothing.
      break;
    case X86State::RFLAG_AF_RAW_LOC:
      // AF stored in bit 4 in our internal representation. It is also
      // XORed with byte 4 of the PF byte, but we write that as zero here so
      // we don't need any special handling for that.
      Frame->State.af_raw = (EFLAGS & (1U << i)) ? (1 << 4) : 0;
      break;
    case X86State::RFLAG_PF_RAW_LOC:
      // PF is inverted in our internal representation.
      Frame->State.pf_raw = (EFLAGS & (1U << i)) ? 0 : 1;
      break;
    case X86State::RFLAG_DF_RAW_LOC:
      // DF is encoded as 1/-1
      Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 0xff : 1;
      break;
    default: Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 1 : 0; break;
    }
  }

  // Calculate packed NZCV. Note CF is inverted.
  uint32_t Packed_NZCV {};
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_OF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_CF_RAW_LOC)) ? 0 : 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC);
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_ZF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_SF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC) : 0;
  memcpy(&Frame->State.flags[X86State::RFLAG_NZCV_LOC], &Packed_NZCV, sizeof(Packed_NZCV));

  // Reserved, Read-As-1, Write-as-1
  Frame->State.flags[X86State::RFLAG_RESERVED_LOC] = 1;
  // Interrupt Flag. Can't be written by CPL-3 userland.
  Frame->State.flags[X86State::RFLAG_IF_LOC] = 1;
}

bool ContextImpl::InitCore() {
  if (CodeCache.IsGeneratingCache || FEXCore::Config::Get_ENABLECODECACHINGWIP()) {
    // Start with a larger code buffer to avoid resizes that would discard code
    StartMaximalCodeBuffer();
  }

  // Initialize the CPU core signal handlers & DispatcherConfig
  Dispatcher = FEXCore::CPU::Dispatcher::Create(this);

  // Set up the SignalDelegator config since core is initialized.
  SignalDelegation->SetConfig(Dispatcher->MakeSignalDelegatorConfig());

  if (Config.GdbServer) {
    // If gdbserver is enabled then this needs to be enabled.
    Config.NeedsPendingInterruptFaultCheck = true;
  }

  if constexpr (BLOCK_DEBUGGING) {
    // If the developer wants to do any single-stepping points or watch points.
    // Add them here.
    //
    // eg:
    // BlockDebuggerTracker.AllTargetSingleStep();
    // BlockDebuggerTracker.AddSingleStepTarget(0x14000'0000ULL);
    // BlockDebuggerTracker.AddWriteWatchPoint(0x420BA5ED);
  }

  return true;
}

void ContextImpl::HandleCallback(FEXCore::Core::InternalThreadState* Thread, uint64_t RIP) {
  static_cast<ContextImpl*>(Thread->CTX)->Dispatcher->ExecuteJITCallback(Thread->CurrentFrame, RIP);
}

void ContextImpl::ExecuteThread(FEXCore::Core::InternalThreadState* Thread) {
  // Update the thread pointer for Thunk return to the latest.
  Thread->CurrentFrame->Pointers.ThunkCallbackRet = SignalDelegation->GetThunkCallbackRET();

  Dispatcher->ExecuteDispatch(Thread->CurrentFrame);

  // If it is the parent thread that died then just leave
  // TODO: This doesn't make sense when the parent thread doesn't outlive its children
}

void ContextImpl::InitializeCompiler(FEXCore::Core::InternalThreadState* Thread) {
  Thread->OpDispatcher = fextl::make_unique<FEXCore::IR::OpDispatchBuilder>(this, Thread);
  Thread->OpDispatcher->SetMultiblock(Config.Multiblock);
  Thread->LookupCache = fextl::make_unique<FEXCore::LookupCache>(this);
  Thread->FrontendDecoder = fextl::make_unique<FEXCore::Frontend::Decoder>(Thread);
  Thread->PassManager = fextl::make_unique<FEXCore::IR::PassManager>(this);

  Thread->CurrentFrame->State.L1Pointer = Thread->LookupCache->GetL1Pointer();
  Thread->CurrentFrame->State.L1Mask = Thread->LookupCache->GetScaledL1PointerMask();

  Thread->CurrentFrame->Pointers.L2Pointer = Thread->LookupCache->GetPagePointer();

  Dispatcher->InitThreadPointers(Thread);

  // Create CPU backend
  Thread->CPUBackend = FEXCore::CPU::CreateArm64JITCore(this, Thread);

  // We finalize *after* the CPU backend is initialized, as the CPU backend will
  // provide necessary register information to the register allocation pass.
  Thread->PassManager->Finalize();
}

FEXCore::Core::InternalThreadState* ContextImpl::CreateThread(const FEXCore::Core::CPUState* NewThreadState) {
  FEXCore::Core::InternalThreadState* Thread = new FEXCore::Core::InternalThreadState {
    .CTX = this,
  };
  FEXCore::Allocator::VirtualName("FEXMem_ThreadState", Thread, sizeof(*Thread));

  // Copy over the new thread state to the new object
  if (NewThreadState) {
    memcpy(&Thread->CurrentFrame->State, NewThreadState, sizeof(FEXCore::Core::CPUState));
  }

  // Set up the thread manager state
  Thread->CurrentFrame->Thread = Thread;

  InitializeCompiler(Thread);

  Thread->CurrentFrame->State.DeferredSignalRefCount.Store(0);

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Allocate a JIT symbol buffer only if enabled.
    Thread->SymbolBuffer = JITSymbols::AllocateBuffer();
  }

  return Thread;
}

void ContextImpl::DestroyThread(FEXCore::Core::InternalThreadState* Thread) {
  FEXCore::Allocator::VirtualProtect(&Thread->InterruptFaultPage, sizeof(Thread->InterruptFaultPage),
                                     Allocator::ProtectOptions::Read | Allocator::ProtectOptions::Write);
  delete Thread;
}

#ifndef _WIN32
void ContextImpl::UnlockAfterFork(FEXCore::Core::InternalThreadState* LiveThread, bool Child) {
  Allocator::UnlockAfterFork(LiveThread, Child);

  Profiler::PostForkAction(Child);
  if (Child) {
    if (CodeMapWriter) {
      CodeMapWriter->ResetAfterFork();
    }

    CodeInvalidationMutex.StealAndDropActiveLocks();
    if (Config.StrictInProcessSplitLocks) {
      StrictSplitLockMutex = 0;
    }
  } else {
    CodeInvalidationMutex.unlock();
    if (Config.StrictInProcessSplitLocks) {
      FEXCore::Utils::SpinWaitLock::unlock(&StrictSplitLockMutex);
    }
  }
}

void ContextImpl::LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) {
  CodeInvalidationMutex.lock();
  Allocator::LockBeforeFork(Thread);
  if (Config.StrictInProcessSplitLocks) {
    FEXCore::Utils::SpinWaitLock::lock(&StrictSplitLockMutex);
  }
}
#endif

void ContextImpl::OnCodeBufferAllocated(const fextl::shared_ptr<CPU::CodeBuffer>& Buffer) {
  if (Config.GlobalJITNaming()) {
    Symbols.RegisterJITSpace(Buffer->GetBufferBase(), Buffer->TotalAllocationSize());
  }

  {
    std::scoped_lock lk {CodeBufferListLock};
    // Overflow buffers share their predecessor's map; invalidating it once is enough.
    if (!CodeBufferList.empty()) {
      if (auto Last = CodeBufferList.back().lock(); Last && Last->LookupCache == Buffer->LookupCache) {
        return;
      }
    }
    CodeBufferList.emplace_back(Buffer);
  }
}

extern "C" {
uint64_t fh6_stats[55] {};
uint64_t fh6_pool_keys[65536] {};
uint64_t fh6_clone_bad_info[4] {};
uint8_t fh6_clone_bad[2][1024] {};
uint64_t fh6_shape[64][10] {};
uint64_t fh6_shape_tick {};
uint64_t fh6_smc[4096][3] {};
uint64_t (*fh6_blockmap)[2] {};
uint64_t fh6_blockmap_count {};
}

namespace {
constexpr uint64_t MaxX86InstSize = 15;

// Trampoline pools keep rewriting slots with "one instruction; jmp rel32" stubs whose instruction and
// absolute jump target recur at other slots. Such a translation depends on its address only through
// relocated constants: entry-relative RIPs move with the slot, the jump target stays, and the entry CRC
// covers the slot bytes. FEX_POOL_CLONE: 0 off, 1 (default) publish copies, 2 build copies and compare
// them with a fresh compile without using them.

struct PoolTemplate {
  uint64_t Entry;
  uint64_t Target;
  uint32_t InsnLen;
  uint32_t EntryOffset;
  bool Writable;
  std::array<uint8_t, MaxX86InstSize> Insn;
  fextl::vector<uint8_t> Host;
  fextl::vector<FEXCore::CPU::Relocation> Relocs;
};

struct PoolTemplateShard {
  std::mutex Mutex;
  fextl::unordered_map<uint64_t, fextl::shared_ptr<const PoolTemplate>> Map;
};
constexpr size_t PoolShards = 128;
constexpr size_t PoolShardLimit = 512;
PoolTemplateShard PoolTemplates[PoolShards];

std::atomic<uint32_t> PoolVerifyTick {};

uint64_t PoolKey(const uint8_t* Insn, uint64_t Len, uint64_t Target) {
  uint64_t Key = 0x9E3779B97F4A7C15ULL ^ Target;
  for (uint64_t i = 0; i < Len; ++i) {
    Key = (Key ^ Insn[i]) * 0x100000001B3ULL;
  }
  Key = (Key ^ (Key >> 29)) * 0xBF58476D1CE4E5B9ULL;
  return Key ^ (Key >> 32);
}

uint64_t PoolJmpTarget(const uint8_t* Code, uint64_t Entry, uint64_t InsnLen) {
  int32_t Rel;
  memcpy(&Rel, Code + InsnLen + 1, sizeof(Rel));
  return Entry + InsnLen + 5 + static_cast<int64_t>(Rel);
}

fextl::shared_ptr<const PoolTemplate> FindPoolTemplate(uint64_t Key) {
  auto& Shard = PoolTemplates[Key % PoolShards];
  std::scoped_lock Lock(Shard.Mutex);
  auto It = Shard.Map.find(Key);
  return It == Shard.Map.end() ? nullptr : It->second;
}

void StorePoolTemplate(uint64_t Key, fextl::shared_ptr<const PoolTemplate> Template) {
  auto& Shard = PoolTemplates[Key % PoolShards];
  std::scoped_lock Lock(Shard.Mutex);
  if (Shard.Map.size() >= PoolShardLimit) {
    Shard.Map.clear();
  }
  Shard.Map[Key] = std::move(Template);
}

// Value of a padded 64-bit constant load (movz/movk/nop), as emitted for relocatable constants.
std::optional<uint64_t> ReadPaddedConstant(const uint8_t* Code) {
  uint64_t Value = 0;
  bool Any = false;
  for (int i = 0; i < 4; ++i) {
    uint32_t Inst;
    memcpy(&Inst, Code + i * 4, sizeof(Inst));
    if (Inst == 0xD503201F) {
      continue;
    }
    const uint32_t Op = Inst & 0xFF800000;
    if (Op != 0xD2800000 && Op != 0xF2800000) {
      return std::nullopt;
    }
    const uint32_t Shift = ((Inst >> 21) & 3) * 16;
    const uint64_t Imm = (Inst >> 5) & 0xFFFF;
    Value = (Op == 0xD2800000 ? 0 : Value & ~(0xFFFFULL << Shift)) | (Imm << Shift);
    Any = true;
  }
  return Any ? std::optional<uint64_t>(Value) : std::nullopt;
}

// What the disk cache would patch in for a patchable relocation, computed from a snapshot of the slot
// at Entry instead of live memory. Offset is the site's offset in the slot.
uint64_t PoolPatchableValue(CPU::RelocationTypes Type, uint64_t Offset, uint64_t Entry, uint8_t Size, const uint8_t* Snapshot) {
  if (Type == CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_CRC_MOVE) {
    return FEXCore::Utils::crc32(Snapshot + Offset, Size);
  }
  uint64_t Raw = 0;
  memcpy(&Raw, Snapshot + Offset, Size);
  const int64_t Data = Size == 1 ? int64_t(int8_t(Raw)) : Size == 2 ? int64_t(int16_t(Raw)) : Size == 4 ? int64_t(int32_t(Raw)) : int64_t(Raw);
  if (Type == CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_DATA_MOVE) {
    return Data;
  }
  return Entry + Offset + Size + Data;
}

bool PatchPoolCopy(ContextImpl* CTX, const PoolTemplate& Template, uint64_t NewEntry, const uint8_t* Snapshot, uint8_t* Out) {
  memcpy(Out, Template.Host.data(), Template.Host.size());
  CPU::Arm64Emitter Emitter(CTX, Out, Template.Host.size());
  const auto Move = [&](uint64_t Old) {
    return Old == Template.Target ? Old : Old - Template.Entry + NewEntry;
  };
  for (const auto& Reloc : Template.Relocs) {
    Emitter.SetCursorOffset(Reloc.Header.Offset);
    switch (Reloc.Header.Type) {
    case CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL:
    case CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE: break;
    case CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL: Emitter.dc64(Move(Reloc.GuestRIP.GuestRIP)); break;
    case CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE:
      Emitter.LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Register(Reloc.GuestRIP.RegisterIndex), Move(Reloc.GuestRIP.GuestRIP),
                           CPU::Arm64Emitter::PadType::DOPAD);
      break;
    case CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_CRC_MOVE:
    case CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_DATA_MOVE:
    case CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_RIP_MOVE:
    case CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_RIP_LITERAL: {
      const auto& Data = Reloc.GuestPatchableData;
      const uint64_t Value = PoolPatchableValue(Reloc.Header.Type, Data.SiteAddress - Template.Entry, NewEntry, Data.ValueSize, Snapshot);
      if (Reloc.Header.Type == CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_RIP_LITERAL) {
        Emitter.dc64(Value);
      } else {
        Emitter.LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Register(Data.RegisterIndex), Value, CPU::Arm64Emitter::PadType::DOPAD);
      }
      break;
    }
    default: return false;
    }
  }
  return true;
}

// Builds a template from a fresh compile of a pool stub, or returns null if the block isn't one.
// The guest bytes are re-read here, so the embedded entry CRC must match them: otherwise the slot was
// rewritten after decoding and the code belongs to other bytes.
fextl::shared_ptr<PoolTemplate> MakePoolTemplate(const Frontend::Decoder::DecodedBlockInformation& BlockInfo, uint64_t GuestRIP,
                                                 uint64_t Length, bool Writable, const CPU::CPUBackend::CompiledCode& Code,
                                                 std::span<const CPU::Relocation> Relocs) {
  const auto Reject = [](FH6Stats::Counter Reason) -> fextl::shared_ptr<PoolTemplate> {
    FH6Stats::Add(Reason);
    return nullptr;
  };
  if (!Writable) {
    return Reject(FH6Stats::PoolRejectNotWritable);
  }
  if (BlockInfo.Blocks.size() != 1 || Code.EntryPoints.size() != 1) {
    return Reject(FH6Stats::PoolRejectShape);
  }
  const auto& Block = BlockInfo.Blocks[0];
  if (Block.Entry != GuestRIP || Block.Size != Length || Block.ForceFullSMCDetection) {
    return Reject(FH6Stats::PoolRejectShape);
  }
  // A lone ret: no jump target, so Target stays 0 and nothing in the copy is kept fixed.
  const bool RetStub = Block.NumInstructions == 1 && Length == 1;
  uint64_t InsnLen = 1;
  if (!RetStub) {
    if (Block.NumInstructions != 2) {
      return Reject(FH6Stats::PoolRejectShape);
    }
    const auto& Insn = Block.DecodedInstructions[0];
    const auto& Jmp = Block.DecodedInstructions[1];
    InsnLen = Insn.InstSize;
    if (InsnLen == 0 || InsnLen > MaxX86InstSize || Jmp.InstSize != 5 || InsnLen + 5 != Length) {
      return Reject(FH6Stats::PoolRejectShape);
    }
    if (Insn.TableInfo == nullptr ||
        (Insn.TableInfo->Flags & (X86Tables::InstFlags::FLAGS_BLOCK_END | X86Tables::InstFlags::FLAGS_SETS_RIP | X86Tables::InstFlags::FLAGS_CALL))) {
      return Reject(FH6Stats::PoolRejectInsn);
    }
    const auto RipRelative = [](const X86Tables::DecodedOperand& Operand) {
      return Operand.IsRIPRelative() || Operand.IsRIPRelativeRelocation();
    };
    if (RipRelative(Insn.Dest) || RipRelative(Insn.Src[0]) || RipRelative(Insn.Src[1]) || RipRelative(Insn.Src[2])) {
      return Reject(FH6Stats::PoolRejectInsn);
    }
  }

  std::array<uint8_t, MaxX86InstSize + 5> Snapshot;
  memcpy(Snapshot.data(), reinterpret_cast<const void*>(GuestRIP), Length);
  uint64_t Target = 0;
  if (RetStub) {
    if (Snapshot[0] != 0xC3) {
      return Reject(FH6Stats::PoolRejectBytes);
    }
  } else {
    if (Snapshot[InsnLen] != 0xE9) {
      return Reject(FH6Stats::PoolRejectBytes);
    }
    Target = PoolJmpTarget(Snapshot.data(), GuestRIP, InsnLen);
    if (Target >= GuestRIP - 32 && Target < GuestRIP + Length + 32) {
      return Reject(FH6Stats::PoolRejectBytes);
    }
  }

  const auto EntryHost = Code.EntryPoints.begin()->second;
  auto Template = fextl::make_shared<PoolTemplate>();
  Template->Entry = GuestRIP;
  Template->Target = Target;
  Template->InsnLen = InsnLen;
  Template->EntryOffset = EntryHost - Code.BlockBegin;
  Template->Writable = Writable;
  memcpy(Template->Insn.data(), Snapshot.data(), InsnLen);
  Template->Host.assign(Code.BlockBegin, Code.BlockBegin + Code.Size);

  bool HasCrc = false;
  for (const auto& Reloc : Relocs) {
    const bool Literal = Reloc.Header.Type == CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL ||
                         Reloc.Header.Type == CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL ||
                         Reloc.Header.Type == CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_RIP_LITERAL;
    if (Reloc.Header.Offset + (Literal ? 8 : 16) > Code.Size) {
      return Reject(FH6Stats::PoolRejectReloc);
    }
    switch (Reloc.Header.Type) {
    case CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL:
    case CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE: break;
    case CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL:
    case CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE: {
      const uint64_t Value = Reloc.GuestRIP.GuestRIP;
      if (Value != Target && (Value < GuestRIP || Value > GuestRIP + Length)) {
        return Reject(FH6Stats::PoolRejectRelocValue);
      }
      if (Reloc.Header.Type == CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE && ReadPaddedConstant(Template->Host.data() + Reloc.Header.Offset) != Value) {
        return Reject(FH6Stats::PoolRejectRelocValue);
      }
      break;
    }
    case CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_CRC_MOVE:
    case CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_DATA_MOVE:
    case CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_RIP_MOVE:
    case CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_RIP_LITERAL: {
      const bool Crc = Reloc.Header.Type == CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_CRC_MOVE;
      const uint64_t Site = Reloc.GuestPatchableData.SiteAddress;
      const uint64_t Size = Reloc.GuestPatchableData.ValueSize;
      if (Site < GuestRIP || Site + Size > GuestRIP + Length || (!Crc && Size != 1 && Size != 2 && Size != 4 && Size != 8)) {
        return Reject(Crc ? FH6Stats::PoolRejectCrc : FH6Stats::PoolRejectReloc);
      }
      const uint64_t Expected = PoolPatchableValue(Reloc.Header.Type, Site - GuestRIP, GuestRIP, Size, Snapshot.data());
      std::optional<uint64_t> Embedded;
      if (Reloc.Header.Type == CPU::RelocationTypes::RELOC_GUEST_PATCHABLE_RIP_LITERAL) {
        uint64_t Lit;
        memcpy(&Lit, Template->Host.data() + Reloc.Header.Offset, sizeof(Lit));
        Embedded = Lit;
      } else {
        Embedded = ReadPaddedConstant(Template->Host.data() + Reloc.Header.Offset);
      }
      if (!Embedded || *Embedded != Expected) {
        return Reject(Crc ? FH6Stats::PoolRejectCrc : FH6Stats::PoolRejectRelocValue);
      }
      HasCrc |= Crc;
      break;
    }
    default: return Reject(FH6Stats::PoolRejectReloc);
    }
  }
  if (!HasCrc) {
    return Reject(FH6Stats::PoolRejectCrc);
  }
  Template->Relocs.assign(Relocs.begin(), Relocs.end());
  return Template;
}
} // namespace

void ContextImpl::ClearCodeCache(FEXCore::Core::InternalThreadState* Thread, bool NewCodeBuffer) {
  FEXCORE_PROFILE_INSTANT("ClearCodeCache");
  FEXCore::FH6Stats::Add(NewCodeBuffer ? FEXCore::FH6Stats::ClearCacheNewBuffer : FEXCore::FH6Stats::ClearCacheKeepBuffer);

  if (NewCodeBuffer) {
    // Allocate new CodeBuffer + L3 LookupCache and clear L1+L2 caches
    Thread->CPUBackend->ClearCache();
  } else {
    // Clear L1+L2 cache of this thread, and clear L3 cache across any threads using it
    auto lk = Thread->LookupCache->AcquireWriteLock();
    Thread->LookupCache->ClearCache(lk);
  }
  Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
}

static void IRDumper(FEXCore::Core::InternalThreadState* Thread, IR::IREmitter* IREmitter, uint64_t GuestRIP) {
  FEXCore::File::File FD = FEXCore::File::File::GetStdERR();
  fextl::ostringstream out;
  auto NewIR = IREmitter->ViewIR();
  FEXCore::IR::Dump(&out, &NewIR);
  fextl::fmt::print(FD, "IR-ShouldDump-{} 0x{:x}:\n{}\n@@@@@\n", NewIR.PostRA() ? "post" : "pre", GuestRIP, out.str());
}

bool ContextImpl::CheckIfBlockIsCacheable(FEXCore::Core::InternalThreadState& Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  return Thread.FrontendDecoder->CheckIfCacheable(Thread, reinterpret_cast<const uint8_t*>(GuestRIP), GuestRIP, MaxInst);
}

ContextImpl::GenerateIRResult
ContextImpl::GenerateIR(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, bool ExtendedDebugInfo, uint64_t MaxInst) {
  FEXCORE_PROFILE_SCOPED("GenerateIR");

  Thread->OpDispatcher->ResetWorkingList();

  uint64_t TotalInstructions {0};
  uint64_t TotalInstructionsLength {0};

  bool HasCustomIR {};

  bool WantsDiskCachePatching = DiskCache.IsReadingDiskCache() || DiskCache.IsWritingDiskCache() || Thread->PoolPatchable;

  if (HasCustomIRHandlers.load(std::memory_order_relaxed)) {
    std::shared_lock lk(CustomIRMutex);
    auto Handler = CustomIRHandlers.find(GuestRIP);
    if (Handler != CustomIRHandlers.end()) {
      TotalInstructions = 1;
      TotalInstructionsLength = 1;
      Handler->second.Handler(GuestRIP, Thread->OpDispatcher.get());
      HasCustomIR = true;
    }
  }

  if (!HasCustomIR) {
    const auto* GuestCode = reinterpret_cast<const uint8_t*>(GuestRIP);

    Thread->FrontendDecoder->DecodeLoop(GuestCode);

    const auto* BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    const auto& CodeBlocks = BlockInfo->Blocks;

    Thread->OpDispatcher->BeginFunction(GuestRIP, &CodeBlocks, BlockInfo->TotalInstructionCount, BlockInfo->Is64BitMode,
                                        AreMonoHacksActive() && MonoBackpatcherBlock.load(std::memory_order_relaxed) == GuestRIP);

    const auto GPRSize = Thread->OpDispatcher->GetGPROpSize();

#ifdef ZYDIS_DISASSEMBLER
    const auto ZydisMachineMode = Config.Is64BitMode ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    if (FEXCore::Config::Get_X86DISASSEMBLE()) {
      const uint64_t DecodedMin = Thread->FrontendDecoder->DecodedMinAddress;
      const uint64_t DecodedMax = Thread->FrontendDecoder->DecodedMaxAddress;
      LogMan::Msg::IFmt("Guest x86 Begin (RIP={:#x}, {:#x}-{:#x})", GuestRIP, DecodedMin, DecodedMax);
    }
#endif

    for (size_t j = 0; j < CodeBlocks.size(); ++j) {
      const auto& Block = CodeBlocks[j];

      // Dispatch failures and invalid instructions terminate only the decoded
      // block that contains them. Other block targets in the same multiblock
      // compilation unit are independent entry paths.
      bool HadDispatchError {false};
      bool HadInvalidInst {false};

#ifdef ZYDIS_DISASSEMBLER
      if (FEXCore::Config::Get_X86DISASSEMBLE() && CodeBlocks.size() > 1) {
        LogMan::Msg::IFmt("  Block {} Entry={:#x} NumInsts={}", j, Block.Entry, Block.NumInstructions);
      }
#endif

      bool BlockInForceTSOValidRange = false;
      auto InstForceTSOIt = ForceTSOInstructions.end();
      if (ForceTSOValidRanges.Contains({Block.Entry, Block.Entry + Block.Size})) {
        if (auto It = ForceTSOInstructions.lower_bound(Block.Entry); It != ForceTSOInstructions.end() && *It < Block.Entry + Block.Size) {
          InstForceTSOIt = It;
          BlockInForceTSOValidRange = true;
        }
      }

      // Set the block entry point
      Thread->OpDispatcher->SetNewBlockIfChanged(Block.Entry);

      // Reset any block-specific state
      Thread->OpDispatcher->StartNewBlock();

      const uint64_t InstsInBlock = Block.NumInstructions;
      if (InstsInBlock == 0) {
        // Special case for an empty instruction block.
        Thread->OpDispatcher->ExitFunction(Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry - GuestRIP));
      }

      uint64_t BlockInstructionsLength {};

      // One CRC of the decoded bytes per 255-byte chunk, instead of one CRC per instruction. A
      // mismatch throws the block away and recompiles. Code that rewrites its own next instruction
      // inside this block is not seen until the block is entered again; function-entry decrypt is.
      static int fh6_smc_block = -1;
      if (fh6_smc_block < 0) {
        const char* env = std::getenv("FEX_SMC_BLOCK");
        fh6_smc_block = !(env && env[0] == '0' && env[1] == '\0');
      }
      const bool BlockSMC = fh6_smc_block && Block.Size != 0 &&
                            ((Config.SMCChecks == FEXCore::Config::CONFIG_SMC_FULL && BlockInfo->ContainsWritableCode) ||
                             Block.ForceFullSMCDetection);
      if (BlockSMC) {
        for (uint64_t off = 0; off < Block.Size;) {
          const uint64_t chunk = std::min<uint64_t>(255, Block.Size - off);
          const auto bytes = reinterpret_cast<const uint8_t*>(Block.Entry + off);
          const auto value = FEXCore::Utils::crc32(bytes, chunk);
          auto addr = Thread->OpDispatcher->_EntrypointOffset(GPRSize, Block.Entry + off - GuestRIP);
          auto crc = WantsDiskCachePatching ?
                       Thread->OpDispatcher->_PatchableGuestCRC(IR::OpSize::i64Bit, value, (int64_t)bytes, chunk) :
                       Thread->OpDispatcher->Constant(value);
          auto changed = Thread->OpDispatcher->_ValidateCode(crc, addr, static_cast<uint8_t>(chunk));
          auto mismatch = Thread->OpDispatcher->CondJump(changed);
          auto current = Thread->OpDispatcher->GetCurrentBlock();
          auto fail = Thread->OpDispatcher->CreateNewCodeBlockAtEnd();
          Thread->OpDispatcher->SetTrueJumpTarget(mismatch, fail);
          Thread->OpDispatcher->SetCurrentCodeBlock(fail);
          Thread->OpDispatcher->StartNewBlock();
          Thread->OpDispatcher->_ThreadRemoveCodeEntry(Thread->OpDispatcher->_EntrypointOffset(GPRSize, 0),
                                                        Thread->OpDispatcher->_EntrypointOffset(GPRSize, Block.Entry - GuestRIP));
          auto next = Thread->OpDispatcher->CreateNewCodeBlockAfter(current);
          Thread->OpDispatcher->SetFalseJumpTarget(mismatch, next);
          Thread->OpDispatcher->SetCurrentCodeBlock(next);
          Thread->OpDispatcher->StartNewBlock();
          off += chunk;
        }
      }

      for (size_t i = 0; i < InstsInBlock; ++i) {
        uint64_t InstAddress = Block.Entry + BlockInstructionsLength;
        const FEXCore::X86Tables::X86InstInfo* TableInfo {nullptr};
        const FEXCore::X86Tables::DecodedInst* DecodedInfo {nullptr};

        TableInfo = Block.DecodedInstructions[i].TableInfo;
        DecodedInfo = &Block.DecodedInstructions[i];

#ifdef ZYDIS_DISASSEMBLER
        if (FEXCore::Config::Get_X86DISASSEMBLE()) {
          const uint8_t* InstBytes = reinterpret_cast<const uint8_t*>(InstAddress);
          ZydisDisassembledInstruction ZydisInst;
          if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZydisMachineMode, InstAddress, InstBytes, DecodedInfo->InstSize, &ZydisInst))) {
            LogMan::Msg::IFmt("    {:#x}: {}", InstAddress, ZydisInst.text);
          } else {
            LogMan::Msg::IFmt("    {:#x}: (decode failed, {} bytes)", InstAddress, DecodedInfo->InstSize);
          }
        }
#endif

        bool IsLocked = DecodedInfo->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK;

        // Do a partial register cache flush before every instruction. This
        // prevents cross-instruction static register caching, while allowing
        // context load/stores to be optimized within a block. Theoretically,
        // this flush is not required for correctness, all mandatory flushes are
        // included in instruction-specific handlers. Instead, this is a blunt
        // heuristic to make the register cache less aggressive, as the current
        // RA generates bad code in common cases with tied registers otherwise.
        //
        // However, it makes our exception handling behaviour more predictable.
        // It is potentially correctness bearing in that sense, but that is a
        // side effect here and (if that behaviour is required) we should handle
        // that more explicitly later.
        Thread->OpDispatcher->FlushRegisterCache(true);

        if (ExtendedDebugInfo || Thread->OpDispatcher->CanHaveSideEffects(TableInfo, DecodedInfo)) {
          Thread->OpDispatcher->_GuestOpcode(InstAddress - GuestRIP);
        }

        // Non-writable code can only change through a protection change or remap, which the
        // frontend invalidates, so FULL only needs per-instruction validation for writable code.
        // FEX_SMC_BLOCK=0 keeps that per-instruction CRC; the default checks the whole block once
        // at entry (see above).
        if (!fh6_smc_block && ((Config.SMCChecks == FEXCore::Config::CONFIG_SMC_FULL && BlockInfo->ContainsWritableCode) ||
                               Block.ForceFullSMCDetection) &&
            DecodedInfo->InstSize != 0) {
          auto ExistingCodePtr = reinterpret_cast<uint8_t*>(Block.Entry + BlockInstructionsLength);
          auto InstAddressReg = Thread->OpDispatcher->_EntrypointOffset(GPRSize, InstAddress - GuestRIP);

          auto Value = FEXCore::Utils::crc32(ExistingCodePtr, DecodedInfo->InstSize);
          auto CRC = WantsDiskCachePatching ?
                       Thread->OpDispatcher->_PatchableGuestCRC(IR::OpSize::i64Bit, Value, (int64_t)ExistingCodePtr, DecodedInfo->InstSize) :
                       Thread->OpDispatcher->Constant(Value);
          auto CodeChanged = Thread->OpDispatcher->_ValidateCode(CRC, InstAddressReg, DecodedInfo->InstSize);

          auto InvalidateCodeCond = Thread->OpDispatcher->CondJump(CodeChanged);

          auto CurrentBlock = Thread->OpDispatcher->GetCurrentBlock();
          auto CodeWasChangedBlock = Thread->OpDispatcher->CreateNewCodeBlockAtEnd();
          Thread->OpDispatcher->SetTrueJumpTarget(InvalidateCodeCond, CodeWasChangedBlock);

          Thread->OpDispatcher->SetCurrentCodeBlock(CodeWasChangedBlock);
          Thread->OpDispatcher->StartNewBlock();

          // Generate a relocatable entry for invalidation purposes.
          auto EntryToInvalidate = Thread->OpDispatcher->_EntrypointOffset(GPRSize, 0);
          auto NewRIP = Thread->OpDispatcher->_EntrypointOffset(GPRSize, InstAddress - GuestRIP);
          // Invalidate and exit the function
          Thread->OpDispatcher->_ThreadRemoveCodeEntry(EntryToInvalidate, NewRIP);

          auto NextOpBlock = Thread->OpDispatcher->CreateNewCodeBlockAfter(CurrentBlock);

          Thread->OpDispatcher->SetFalseJumpTarget(InvalidateCodeCond, NextOpBlock);
          Thread->OpDispatcher->SetCurrentCodeBlock(NextOpBlock);
          Thread->OpDispatcher->StartNewBlock();
        }

        if (TableInfo && TableInfo->OpcodeDispatcher.OpDispatch) {
          auto Fn = TableInfo->OpcodeDispatcher.OpDispatch;
          Thread->OpDispatcher->ResetHandledLock();
          Thread->OpDispatcher->ResetDecodeFailure();
          IR::ForceTSOMode ForceTSO = IR::ForceTSOMode::NoOverride;
          if (BlockInForceTSOValidRange) {
            if (InstForceTSOIt != ForceTSOInstructions.end() && *InstForceTSOIt == InstAddress) {
              ForceTSO = IR::ForceTSOMode::ForceEnabled;
            } else {
              ForceTSO = IR::ForceTSOMode::ForceDisabled;
            }
          } else if (DecodedInfo->Flags & X86Tables::DecodeFlags::FLAG_FORCE_TSO) {
            ForceTSO = IR::ForceTSOMode::ForceEnabled;
          }

          Thread->OpDispatcher->SetForceTSO(ForceTSO);
          std::invoke(Fn, Thread->OpDispatcher, DecodedInfo);
          if (Thread->OpDispatcher->HadDecodeFailure()) {
            HadDispatchError = true;
          } else {
            if (Thread->OpDispatcher->HasHandledLock() != IsLocked) {
              HadDispatchError = true;
              LogMan::Msg::EFmt("Missing LOCK HANDLER at 0x{:x}{{'{}'}}", InstAddress, TableInfo->Name ?: "UND");
            }
            BlockInstructionsLength += DecodedInfo->InstSize;
            TotalInstructionsLength += DecodedInfo->InstSize;
            ++TotalInstructions;

            // Walk InstForceTSOIt forward past the handled instruction
            InstForceTSOIt =
              std::find_if(InstForceTSOIt, ForceTSOInstructions.end(), [&](auto Val) { return Val >= Block.Entry + BlockInstructionsLength; });
          }
        } else {
          // Invalid instruction
          if (!BlockInstructionsLength) {
            // SMC can modify block contents and patch invalid instructions to valid ones inline.
            // End blocks upon encountering them and only emit an invalid opcode exception if there are no prior instructions in the block (that could have modified it to be valid).

            if (TableInfo) {
              LogMan::Msg::EFmt("Invalid or Unknown instruction: {} 0x{:x}", TableInfo->Name ?: "UND", Block.Entry - GuestRIP);
            }

            if (Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::INVALID_INST ||
                Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::BAD_RELOCATION) {
              Thread->OpDispatcher->InvalidOp(DecodedInfo);
            } else if (Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::UNIMPLEMENTED_INST) {
              Thread->OpDispatcher->UnimplementedOp(DecodedInfo);
            } else {
              Thread->OpDispatcher->NoExecOp(DecodedInfo);
            }
          }

          HadInvalidInst = true;
        }

        const bool NeedsBlockEnd = (HadDispatchError && TotalInstructions > 0) ||
                                   (Thread->OpDispatcher->NeedsBlockEnder() && i + 1 == InstsInBlock) || HadInvalidInst;

        // If we had a dispatch error then leave early
        if (HadDispatchError && TotalInstructions == 0) {
          // Couldn't handle any instruction in op dispatcher
          Thread->OpDispatcher->DelayedDisownBuffer();
          return {std::nullopt, 0, 0, 0, 0};
        }

        if (NeedsBlockEnd) {
          // We had some instructions. Early exit
          Thread->OpDispatcher->ExitFunction(
            Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry + BlockInstructionsLength - GuestRIP));
          break;
        }


        if (Thread->OpDispatcher->FinishOp(DecodedInfo->PC + DecodedInfo->InstSize, i + 1 == InstsInBlock)) {
          break;
        }
      }
    }

#ifdef ZYDIS_DISASSEMBLER
    if (FEXCore::Config::Get_X86DISASSEMBLE()) {
      LogMan::Msg::IFmt("Guest x86 End");
    }
#endif

    Thread->OpDispatcher->Finalize();
  }

  Thread->FrontendDecoder->DelayedDisownBuffer();

  IR::IREmitter* IREmitter = Thread->OpDispatcher.get();

  auto ShouldDump = Thread->OpDispatcher->ShouldDumpIR();
  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  // Run the passmanager over the IR from the dispatcher
  Thread->PassManager->Run(IREmitter);

  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  return {
    .IRView = IREmitter->ViewIR(),
    .TotalInstructions = TotalInstructions,
    .TotalInstructionsLength = TotalInstructionsLength,
    .StartAddr = Thread->FrontendDecoder->DecodedMinAddress,
    .Length = Thread->FrontendDecoder->DecodedMaxAddress - Thread->FrontendDecoder->DecodedMinAddress,
    .NeedsAddGuestCodeRanges = !HasCustomIR,
  };
}

ContextImpl::CompileCodeResult ContextImpl::CompileCode(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  if (SourcecodeResolver && Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (MappedSection) {
      MappedSection->FileInfo.SourcecodeMap =
        SourcecodeResolver->GenerateMap(MappedSection->FileInfo.Filename, CodeMap::GetBaseFilename(MappedSection->FileInfo, false));
    }
  }

  // Generate IR + Meta Info
  auto [IRView, TotalInstructions, TotalInstructionsLength, StartAddr, Length, NeedsAddGuestCodeRanges] =
    GenerateIR(Thread, GuestRIP, Config.GDBSymbols(), MaxInst);
  if (!IRView) {
    Thread->FrontendDecoder->ValidateDisownedOrFree();
    Thread->OpDispatcher->ValidateDisownedOrFree();
    // OpDispatcher IR already released in this case.
    return {{}, nullptr, 0, 0, false};
  }

  // Attempt to get the CPU backend to compile this code
  // Re-check if another thread raced us in compiling this block.
  // We could lock CodeBufferWriteMutex earlier to prevent this from happening,
  // but this would increase lock contention. Redundant frontend runs aren't
  // as expensive and are easily reverted.
  if (MaxInst != 1) {
    if (auto Block = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
      // Raced to compile, release the OpDispatcher IR.
      Thread->OpDispatcher->DelayedDisownBuffer();
      Thread->FrontendDecoder->ValidateDisownedOrFree();
      Thread->OpDispatcher->ValidateDisownedOrFree();
      return {.CompiledCode = {.BlockBegin = reinterpret_cast<uint8_t*>(Block), .EntryPoints = {{GuestRIP, reinterpret_cast<uint8_t*>(Block)}}},
              .DebugData = nullptr,
              .StartAddr = 0,
              .Length = 0,
              .NeedsAddGuestCodeRanges = false};
    }
  }

  auto DebugData = fextl::make_unique<FEXCore::Core::DebugData>();

  // If the trap flag is set we generate single instruction blocks that each check to generate a single step exception.
  bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];

  auto CompiledCode = Thread->CPUBackend->CompileCode(GuestRIP, Length, TotalInstructions == 1, &*IRView, DebugData.get(), TFSet);

  // Release the IR
  Thread->OpDispatcher->DelayedDisownBuffer();

  Thread->FrontendDecoder->ValidateDisownedOrFree();
  Thread->OpDispatcher->ValidateDisownedOrFree();
  return {
    .CompiledCode = std::move(CompiledCode),
    .DebugData = std::move(DebugData),
    .StartAddr = StartAddr,
    .Length = Length,
    .NeedsAddGuestCodeRanges = NeedsAddGuestCodeRanges,
  };
}

uintptr_t ContextImpl::CompileBlock(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP, uint64_t MaxInst) {
  if constexpr (BLOCK_DEBUGGING) {
    // Block debugging logic is hand-written and needs to be handled with care.
    // Force MaxInst to only be one in this case.
    MaxInst = 1;

    // If the entrypoint is part of the single step targets then single step it.
    if (BlockDebuggerTracker.IsSingleStepTarget(GuestRIP)) {
      return CompileSingleStep(Frame, GuestRIP);
    }
  }

  auto Thread = Frame->Thread;
  FEXCORE_PROFILE_SCOPED("CompileBlock");
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedJITTime);

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);

  // Is the code in the cache?
  // The backends only check L1 and L2, not L3
  if (auto HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
    return HostCode;
  }
  FEXCore::FH6Stats::Add(FEXCore::FH6Stats::CompileBlockMiss);

  std::optional<ExecutableFileSectionInfo> Region = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);

  const bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  HLE::ExecutableRangeInfo RangeInfo {};
  if (PoolCloneModeValue != 0 && !Region && MaxInst == 0 && !TFSet) {
    RangeInfo = SyscallHandler->QueryGuestExecutableRange(Thread, GuestRIP);
  }
  const bool PoolCandidate = RangeInfo.Size != 0;
  auto& PoolCopy = Thread->PoolCopy;
  auto& PoolCopySize = Thread->PoolCopySize;
  PoolCopySize = 0;
  if (PoolCandidate) {
    // One snapshot of the slot: the template match and the entry CRC must describe the same bytes.
    std::array<uint8_t, MaxX86InstSize + 5> Snapshot;
    const uint64_t RangeEnd = RangeInfo.Base + RangeInfo.Size;
    const uint64_t Avail = RangeEnd > GuestRIP ? std::min<uint64_t>(Snapshot.size(), RangeEnd - GuestRIP) : 0;
    memcpy(Snapshot.data(), reinterpret_cast<const void*>(GuestRIP), Avail);
    // {InsnLen, Target}: a lone ret (Target 0), or one instruction followed by jmp rel32.
    std::array<std::pair<uint64_t, uint64_t>, MaxX86InstSize + 1> Candidates;
    size_t NumCandidates = 0;
    if (Avail >= 1 && Snapshot[0] == 0xC3) {
      Candidates[NumCandidates++] = {1, 0};
    }
    for (uint64_t InsnLen = 1; InsnLen <= MaxX86InstSize && InsnLen + 5 <= Avail; ++InsnLen) {
      if (Snapshot[InsnLen] == 0xE9) {
        Candidates[NumCandidates++] = {InsnLen, PoolJmpTarget(Snapshot.data(), GuestRIP, InsnLen)};
      }
    }
    for (size_t Candidate = 0; Candidate < NumCandidates; ++Candidate) {
      const auto [InsnLen, Target] = Candidates[Candidate];
      const auto Template = FindPoolTemplate(PoolKey(Snapshot.data(), InsnLen, Target));
      if (!Template || Template->InsnLen != InsnLen || Template->Target != Target || Template->Writable != RangeInfo.Writable ||
          memcmp(Template->Insn.data(), Snapshot.data(), InsnLen) != 0) {
        continue;
      }
      if (Template->Host.size() > sizeof(PoolCopy) || !PatchPoolCopy(this, *Template, GuestRIP, Snapshot.data(), PoolCopy)) {
        break;
      }
      PoolCopySize = Template->Host.size();
      // Mode 1 still checks one copy in 256 against a fresh compile.
      if (PoolCloneModeValue == 2 || (PoolVerifyTick.fetch_add(1, std::memory_order_relaxed) & 255) == 0) {
        break;
      }
      const uint32_t CopySize = PoolCopySize;
      PoolCopySize = 0;
      const auto Loaded = Thread->CPUBackend->LoadCachedCode({PoolCopy, CopySize});
      if (!Loaded.BlockBegin) {
        break;
      }
      const std::array<uint64_t, 1> Entry {GuestRIP};
      const uint64_t LastByte = GuestRIP + InsnLen + (Target ? 5 : 0) - 1;
      const std::array<uint64_t, 2> Pages {GuestRIP & FEXCore::Utils::FEX_PAGE_MASK, LastByte & FEXCore::Utils::FEX_PAGE_MASK};
      const size_t NumPages = Pages[0] == Pages[1] ? 1 : 2;
      for (size_t i = 0; i < NumPages; ++i) {
        if (Thread->LookupCache->AddBlockExecutableRange(Thread, Entry, Pages[i], FEXCore::Utils::FEX_PAGE_SIZE)) {
          SyscallHandler->MarkGuestExecutableRange(Thread, Pages[i], FEXCore::Utils::FEX_PAGE_SIZE);
        }
      }
      void* Host = Loaded.BlockBegin + Template->EntryOffset;
      Thread->LookupCache->AddBlockMapping(Thread, GuestRIP, std::span<const uint64_t>(Pages.data(), NumPages), Host);
      FEXCore::FH6Stats::NoteBlock(GuestRIP, reinterpret_cast<uint64_t>(Host));
      FEXCore::FH6Stats::Add(FEXCore::FH6Stats::PoolCloneHits);
      FEXCore::FH6Stats::Add(FEXCore::FH6Stats::JITHostBytes, CopySize);
      return reinterpret_cast<uintptr_t>(Host);
    }
  }

  Thread->FrontendDecoder->SetupDecodeInstructionsAtEntry(Thread, GuestRIP, MaxInst);

  std::optional<DiskCache::CodeHitData> Hit;
  std::optional<uint64_t> DiskCacheGuestCodeKey;
  {
    FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedDiskCacheLookupTime);
    Hit = DiskCache.Lookup(Thread, Region, GuestRIP, DiskCacheGuestCodeKey);
    if (Hit && !DiskCache.IsValidating()) {
      auto LoadedCode = Thread->CPUBackend->LoadCachedCode(Hit->HostCode);
      if (LoadedCode.BlockBegin) {
        for (auto& CodePage : Hit->GuestPages) {
          if (Thread->LookupCache->AddBlockExecutableRange(Thread, Hit->EntryPointRIPs, CodePage, FEXCore::Utils::FEX_PAGE_SIZE)) {
            SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
          }
        }

        LOGMAN_THROW_A_FMT(Hit->EntryPointRIPs.size() == Hit->EntryPointHostOffsets.size(), "Mismatched Disk Cache entrypoint pairs!");

        uintptr_t CachedHostCode = 0;
        for (size_t i = 0; i < Hit->EntryPointRIPs.size(); i++) {
          void* HostAddr = LoadedCode.BlockBegin + Hit->EntryPointHostOffsets[i];
          Thread->LookupCache->AddBlockMapping(Thread, Hit->EntryPointRIPs[i], Hit->GuestPages, HostAddr);
          if (Hit->EntryPointRIPs[i] == GuestRIP) {
            CachedHostCode = reinterpret_cast<uintptr_t>(HostAddr);
          }
        }

        LOGMAN_THROW_A_FMT(CachedHostCode != 0, "Couldn't find GuestRIP in Disk Cache entrypoints!");

        FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedDiskCacheHitCount, 1);
        FEXCore::FH6Stats::Add(FEXCore::FH6Stats::DiskCacheHits);
        Thread->FrontendDecoder->DelayedDisownBuffer();

        Thread->FrontendDecoder->ValidateDisownedOrFree();
        Thread->OpDispatcher->ValidateDisownedOrFree();
        return CachedHostCode;
      }
    }
    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedDiskCacheMissCount, 1);
  }

  // Accumulate a JIT count now, as even if another thread raced us, it should count as a compile.
  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedJITCount, 1);
  FEXCore::FH6Stats::Add(FEXCore::FH6Stats::JITCompiles);

  const uint64_t CompileStart = FEXCore::FH6Stats::Ticks();
  Thread->PoolPatchable = PoolCandidate;
  Thread->CPUBackend->SetRelocatablePadding(PoolCandidate);
  auto [CompiledCode, DebugData, StartAddr, Length, NeedsAddGuestCodeRanges] = CompileCode(Thread, GuestRIP, MaxInst);
  Thread->PoolPatchable = false;
  Thread->CPUBackend->SetRelocatablePadding(false);
  FEXCore::FH6Stats::Add(FEXCore::FH6Stats::JITCompileTicks, FEXCore::FH6Stats::Ticks() - CompileStart);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  } else if (!DebugData) {
    // DebugData wasn't populated, indicating another thread raced us for compiling this block
    FEXCore::FH6Stats::Add(FEXCore::FH6Stats::RacedCompiles);
    return reinterpret_cast<uintptr_t>(CodePtr);
  }
  FEXCore::FH6Stats::Add(FEXCore::FH6Stats::JITGuestBytes, Length);
  FEXCore::FH6Stats::Add(FEXCore::FH6Stats::JITHostBytes, CompiledCode.Size);

  if (DiskCacheGuestCodeKey && Hit && DiskCache.IsValidating()) {
    DiskCache.Validate(*DiskCacheGuestCodeKey, *Hit, CompiledCode, Region);
  }

  // if this ever fires, we need to serialize the offset into disk cache
  LOGMAN_THROW_A_FMT(StartAddr == GuestRIP, "StartAddr offset from GuestRIP");

  // The core managed to compile the code.
  if (Config.BlockJITNaming()) {
    auto FragmentBasePtr = CompiledCode.BlockBegin;

    auto GuestRIPLookup = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);

    if (DebugData->Subblocks.size()) {
      for (auto& Subblock : DebugData->Subblocks) {
        auto BlockBasePtr = FragmentBasePtr + Subblock.HostCodeOffset;
        if (GuestRIPLookup) {
          Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                           GuestRIP - GuestRIPLookup->FileStartVA);
        } else {
          Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, GuestRIP, Subblock.HostCodeSize);
        }
      }
    } else {
      if (GuestRIPLookup) {
        Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                         GuestRIP - GuestRIPLookup->FileStartVA);
      } else {
        Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, GuestRIP, CompiledCode.Size);
      }
    }
  }

  if (Config.LibraryJITNaming() || Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (MappedSection) {
      if (Config.LibraryJITNaming()) {
        Symbols.RegisterNamedRegion(Thread->SymbolBuffer.get(), CodePtr, DebugData->HostCodeSize, MappedSection->FileInfo.Filename);
      }

      if (Config.GDBSymbols()) {
        GDBJITRegister(MappedSection->FileInfo, MappedSection->FileStartVA, GuestRIP, (uintptr_t)CodePtr, *DebugData);
      }
    }
  }

  fextl::vector<uint64_t> CodePages;

  if (NeedsAddGuestCodeRanges) {
    // Track in the guest to host map all entrypoints for all pages the compiled block touches, if any page didn't previously
    // contain code, inform the frontend so it can setup SMC detection.
    auto BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    CodePages.reserve(BlockInfo->CodePages.size());
    CodePages.insert(CodePages.end(), BlockInfo->CodePages.begin(), BlockInfo->CodePages.end());
    for (auto CodePage : BlockInfo->CodePages) {
      if (Thread->LookupCache->AddBlockExecutableRange(Thread, BlockInfo->EntryPoints, CodePage, FEXCore::Utils::FEX_PAGE_SIZE)) {
        SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
      }
    }
  }

  // Disk Cache
  if (!CodeCache.IsGeneratingCache) {
    if (DiskCacheGuestCodeKey) {
      std::span<const FEXCore::CPU::Relocation> Relocations;
      if (DebugData && DebugData->Relocations) {
        Relocations = *DebugData->Relocations;
      }
      std::span<const uint8_t> GuestCode = {reinterpret_cast<const uint8_t*>(StartAddr), Length};
      const Frontend::Decoder::DecodedBlockInformation* BlockInfo =
        NeedsAddGuestCodeRanges ? Thread->FrontendDecoder->GetDecodedBlockInfo() : nullptr;
      DiskCache.Store(Thread, Region, GuestRIP, *DiskCacheGuestCodeKey, GuestCode, CompiledCode, Relocations, BlockInfo);
    }

    if (CodeMapWriter && Region && Region->FileStartVA != 0) {
      CodeMapWriter->AppendBlock(*Region, GuestRIP);
    }
  }

  if (!Region) {
    FEXCore::FH6Stats::NotePoolCompile(reinterpret_cast<const uint8_t*>(StartAddr), Length);
  }
  if (!Region && !(PoolCandidate && NeedsAddGuestCodeRanges)) {
    FEXCore::FH6Stats::Add(FEXCore::FH6Stats::PoolRejectNotCandidate);
  }
  if (PoolCandidate && NeedsAddGuestCodeRanges) {
    if (PoolCopySize) {
      if (PoolCopySize == CompiledCode.Size && memcmp(PoolCopy, CompiledCode.BlockBegin, CompiledCode.Size) == 0) {
        FEXCore::FH6Stats::Add(FEXCore::FH6Stats::PoolVerifyOK);
      } else {
        FEXCore::FH6Stats::Add(FEXCore::FH6Stats::PoolVerifyBad);
        FEXCore::FH6Stats::NoteCloneMismatch(GuestRIP, PoolCopy, PoolCopySize, CompiledCode.BlockBegin, CompiledCode.Size);
      }
      PoolCopySize = 0;
    }
    std::span<const CPU::Relocation> Relocs;
    if (DebugData->Relocations) {
      Relocs = *DebugData->Relocations;
    }
    if (auto Template = MakePoolTemplate(*Thread->FrontendDecoder->GetDecodedBlockInfo(), GuestRIP, Length, RangeInfo.Writable, CompiledCode, Relocs)) {
      const uint64_t Key = PoolKey(Template->Insn.data(), Template->InsnLen, Template->Target);
      StorePoolTemplate(Key, std::move(Template));
      FEXCore::FH6Stats::Add(FEXCore::FH6Stats::PoolTemplatesStored);
    }
  }

  // Insert to lookup cache
  for (auto [GuestAddr, HostAddr] : CompiledCode.EntryPoints) {
    Thread->LookupCache->AddBlockMapping(Thread, GuestAddr, CodePages, HostAddr);
    FEXCore::FH6Stats::NoteBlock(GuestAddr, reinterpret_cast<uint64_t>(HostAddr));
  }

  // Clear any relocations that might have been generated
  if (!CodeCache.IsGeneratingCache) {
    Thread->CPUBackend->ClearRelocations();
  }

  Thread->FrontendDecoder->ValidateDisownedOrFree();
  Thread->OpDispatcher->ValidateDisownedOrFree();

  return (uintptr_t)CodePtr;
}

uintptr_t ContextImpl::CompileSingleStep(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  FEXCORE_PROFILE_SCOPED("CompileSingleStep");
  auto Thread = Frame->Thread;

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);

  Thread->FrontendDecoder->SetupDecodeInstructionsAtEntry(Thread, GuestRIP, 1);
  auto [CompiledCode, DebugData, StartAddr, Length, _] = CompileCode(Thread, GuestRIP, 1);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  }

  // Clear any relocations that might have been generated
  Thread->CPUBackend->ClearRelocations();

  return (uintptr_t)CodePtr;
}

bool ContextImpl::InvalidateCodeBuffersCodeRange(uint64_t Start, uint64_t Length) {
  FEXCORE_PROFILE_SCOPED("InvalidateCodeBuffersCodeRange");

  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  const uint64_t InvalidateStart = FEXCore::FH6Stats::Ticks();
  bool HadCode = false;
  std::scoped_lock lk {CodeBufferListLock};
  auto it = CodeBufferList.begin();
  while (it != CodeBufferList.end()) {
    if (auto Strong = it->lock()) {
      HadCode |= Strong->LookupCache->InvalidateRange(Start, Length);
      it++;
    } else {
      it = CodeBufferList.erase(it);
    }
  }
  FEXCore::FH6Stats::Add(FEXCore::FH6Stats::IntervalInvalidate);
  FEXCore::FH6Stats::Add(FEXCore::FH6Stats::IntervalInvalidateTicks, FEXCore::FH6Stats::Ticks() - InvalidateStart);
  return HadCode;
}

void ContextImpl::InvalidateThreadCachedCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  // Ensures now-modified mappings aren't cached as being in their previous non-executable state.
  // Accessing FrontendDecoder is safe as the thread's code invalidation mutex must be locked here.
  Thread->FrontendDecoder->ResetExecutableRangeCache();

  if (Thread->LookupCache->InvalidateCacheRange(Start, Length)) {
    FEXCORE_PROFILE_SCOPED("InvalidateCallRet");

    // This may cause access violations in the thread on Windows as zeroing is not atomic, this is handled by the frontend
    Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
  }
}

void ContextImpl::InvalidateCodeBuffersBlock(uint64_t Entry) {
  std::scoped_lock lk {CodeBufferListLock};
  for (const auto& Weak : CodeBufferList) {
    if (auto Strong = Weak.lock()) {
      auto MapLock = Strong->LookupCache->AcquireWriteLock();
      Strong->LookupCache->Erase(Entry, MapLock);
    }
  }
}

void ContextImpl::InvalidateThreadCachedBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Entry) {
  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  Thread->LookupCache->InvalidateCachedBlock(Entry);
}

void ContextImpl::InvalidateThreadUntrackedCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  std::scoped_lock Lock {CodeInvalidationMutex};
  Thread->FrontendDecoder->ResetExecutableRangeCache();
  Thread->LookupCache->InvalidateUntrackedRange(Start, Length);
}

void ContextImpl::ThreadRemoveCodeEntryFromJit(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  auto Thread = Frame->Thread;
  auto CTX = static_cast<ContextImpl*>(Thread->CTX);

  FEXCore::FH6Stats::Add(FEXCore::FH6Stats::SMCMismatch);
  FEXCore::FH6Stats::NoteSMC(GuestRIP & ~0xFFFULL, GuestRIP);
  FEXCore::FH6Stats::NoteShape(GuestRIP, 0, 0, 0, std::min<uint64_t>(32, 0x1000 - (GuestRIP & 0xFFF)), 0);

  if (CTX->Config.SMCChecks == FEXCore::Config::CONFIG_SMC_FULL) {
    // Every block compiled from writable code validates its own bytes on entry, so a thread that
    // reaches a stale copy through its own cache, an older buffer's links, or a racing link detects
    // the mismatch itself and erases it from the map it looks up in. Drop only this thread's block.
    Thread->LookupCache->InvalidateBlock(GuestRIP);
    return;
  }

  Thread->LookupCache->InvalidateBlock(GuestRIP);
  CTX->SyscallHandler->InvalidateGuestBlock(Thread, GuestRIP);
}

std::optional<CustomIRResult>
ContextImpl::AddCustomIREntrypoint(uintptr_t Entrypoint, CustomIREntrypointHandler Handler, void* Creator, void* Data) {
  LOGMAN_THROW_A_FMT(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::unique_lock lk(CustomIRMutex);

  auto InsertedIterator = CustomIRHandlers.emplace(Entrypoint, CustomIRHandlerEntry {Handler, Creator, Data});
  HasCustomIRHandlers = true;

  if (!InsertedIterator.second) {
    const auto& [fn, Creator, Data] = InsertedIterator.first->second;
    return CustomIRResult(Creator, Data);
  }

  return std::nullopt;
}

void ContextImpl::AddThunkTrampolineIRHandler(uintptr_t Entrypoint, uintptr_t GuestThunkEntrypoint) {
  LOGMAN_THROW_A_FMT(Entrypoint, "Tried to link null pointer address to guest function");
  LOGMAN_THROW_A_FMT(GuestThunkEntrypoint, "Tried to link address to null pointer guest function");
  if (!Config.Is64BitMode) {
    LOGMAN_THROW_A_FMT((Entrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
    LOGMAN_THROW_A_FMT((GuestThunkEntrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
  }

  LogMan::Msg::DFmt("Thunks: Adding guest trampoline from address {:#x} to guest function {:#x}", Entrypoint, GuestThunkEntrypoint);

  auto Result = AddCustomIREntrypoint(
    Entrypoint,
    [this, GuestThunkEntrypoint](uintptr_t Entrypoint, FEXCore::IR::IREmitter* emit) {
      auto IRHeader = emit->_IRHeader(emit->Invalid(), Entrypoint, 0, 0, 0, 0);
      auto Block = emit->CreateCodeNode(true, 0);
      IRHeader.first->Blocks = emit->WrapNode(Block);
      emit->SetCurrentCodeBlock(Block);

      const auto GPRSize = this->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit;

      // Thunk entry-points don't get cached, don't need to be padded.
      if (GPRSize == IR::OpSize::i64Bit) {
        IR::Ref R = emit->_StoreRegister(emit->Constant(Entrypoint), GPRSize);
        R->Reg = IR::PhysicalRegister(IR::RegClass::GPRFixed, X86State::REG_R11).Raw;
      } else {
        emit->_StoreContextFPR(GPRSize, emit->_VCastFromGPR(IR::OpSize::i64Bit, IR::OpSize::i64Bit, emit->Constant(Entrypoint)),
                               offsetof(Core::CPUState, mm[0][0]));
      }
      emit->_ExitFunction(IR::OpSize::i64Bit, emit->Constant(GuestThunkEntrypoint), IR::BranchHint::None, emit->Invalid(), emit->Invalid());
    },
    ThunkHandler, (void*)GuestThunkEntrypoint);

  if (Result.has_value()) {
    if (Result->Creator != ThunkHandler) {
      ERROR_AND_DIE_FMT("Input address for AddThunkTrampoline is already linked by another module");
    }
    if (Result->Data != (void*)GuestThunkEntrypoint) {
      // NOTE: This may happen in Vulkan thunks if the Vulkan driver resolves two different symbols
      //       to the same function (e.g. vkGetPhysicalDeviceFeatures2/vkGetPhysicalDeviceFeatures2KHR)
      LogMan::Msg::EFmt("Input address for AddThunkTrampoline is already linked elsewhere");
    }
  }
}

void ContextImpl::AddForceTSOInformation(const IntervalList<uint64_t>& ValidRanges, fextl::set<uint64_t>&& Instructions) {
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  ForceTSOValidRanges.Insert(ValidRanges);
  ForceTSOInstructions.merge(std::move(Instructions));
}

void ContextImpl::RemoveForceTSOInformation(uint64_t Address, uint64_t Size) {
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  ForceTSOValidRanges.Remove({Address, Address + Size});
  ForceTSOInstructions.erase(ForceTSOInstructions.lower_bound(Address), ForceTSOInstructions.upper_bound(Address + Size));
}

void ContextImpl::MarkMonoBackpatcherBlock(uint64_t BlockEntry) {
  MonoBackpatcherBlock.store(BlockEntry, std::memory_order_relaxed);
}

void ContextImpl::RemoveCustomIREntrypoint(FEXCore::Core::InternalThreadState* Thread, uintptr_t Entrypoint) {
  LOGMAN_THROW_A_FMT(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::scoped_lock lk(CustomIRMutex);

  CustomIRHandlers.erase(Entrypoint);
  HasCustomIRHandlers = !CustomIRHandlers.empty();
  SyscallHandler->InvalidateGuestCodeRange(Thread, Entrypoint, 1);
}

void ContextImpl::MonoBackpatcherWrite(FEXCore::Core::CpuStateFrame* Frame, uint8_t Size, uint64_t Address, uint64_t Value) {
  auto Thread = Frame->Thread;
  auto CTX = static_cast<ContextImpl*>(Thread->CTX);
  {
    auto lk = GuardSignalDeferringSection(CTX->CodeInvalidationMutex, Thread);

    if (Size == 8) {
      *reinterpret_cast<uint64_t*>(Address) = Value;
    } else if (Size == 4) {
      *reinterpret_cast<uint32_t*>(Address) = Value;
    } else {
      ERROR_AND_DIE_FMT("Unexpected write size for backpatcher: {}", Size);
    }
  }

  CTX->SyscallHandler->InvalidateGuestCodeRange(Thread, Address, Size);
}

void ContextImpl::ConfigureAOTGen(FEXCore::Core::InternalThreadState* Thread, fextl::set<uint64_t>* ExternalBranches, uint64_t SectionMaxAddress) {
  Thread->FrontendDecoder->SetExternalBranches(ExternalBranches);
}
} // namespace FEXCore::Context
