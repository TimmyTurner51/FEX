// SPDX-License-Identifier: MIT
/*
$info$
tags: backend|arm64
$end_info$
*/

#include "Interface/Context/Context.h"
#include "FEXCore/IR/IR.h"
#include "Interface/Core/LookupCache.h"

#include "Interface/Core/JIT/JITClass.h"

#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/MathUtils.h>

namespace FEXCore::CPU {

DEF_OP(CallbackReturn) {
  // spill back to CTX
  SpillStaticRegs(TMP1);

  // First we must reset the stack
  ResetStack();

  // We can now lower the ref counter again

  ldr(ARMEmitter::WReg::w2, STATE, offsetof(FEXCore::Core::CpuStateFrame, SignalHandlerRefCounter));
  sub(ARMEmitter::Size::i32Bit, ARMEmitter::Reg::r2, ARMEmitter::Reg::r2, 1);
  str(ARMEmitter::WReg::w2, STATE, offsetof(FEXCore::Core::CpuStateFrame, SignalHandlerRefCounter));

  // We need to adjust an additional 8 bytes to get back to the original "misaligned" RSP state
  ldr(ARMEmitter::XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.gregs[X86State::REG_RSP]));
  add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r2, ARMEmitter::Reg::r2, 8);
  str(ARMEmitter::XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.gregs[X86State::REG_RSP]));

  PopCalleeSavedRegisters();

  // Return to the thunk
  ret();
}

DEF_OP(ExitFunction) {
  auto Op = IROp->C<IR::IROp_ExitFunction>();

  ResetStack();

  if (CTX->HostFeatures.IsInstCountCI) [[unlikely]] {
    // Emit function end marker
    udf(0x420F);
  }

  uint64_t NewRIP;

  if constexpr (Context::BLOCK_DEBUGGING) {
    // Skip block linking when BLOCK_DEBUGGING as it adds overhead and is unncessary.
    // This is a debug only feature and doesn't need caching help.
    bool IsInlineRIP = IsInlineConstant(Op->NewRIP, &NewRIP) || IsInlineEntrypointOffset(Op->NewRIP, &NewRIP);
    ARMEmitter::ForwardLabel l_ExitLink;
    if (IsInlineRIP) {
      ldr(TMP1, &l_ExitLink);
      str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    } else {
      auto RipReg = GetReg(Op->NewRIP);
      str(RipReg.X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
    }
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    br(TMP2);

    if (IsInlineRIP) {
      BindOrRestart(&l_ExitLink);
      dc64(NewRIP);
    }

    return;
  }

  if (IsInlineConstant(Op->NewRIP, &NewRIP) || IsInlineEntrypointOffset(Op->NewRIP, &NewRIP)) {
#ifdef ARCHITECTURE_arm64ec
    if (NewRIP < EC_CODE_BITMAP_MAX_ADDRESS && RtlIsEcCode(NewRIP)) {
      str(REG_CALLRET_SP, STATE_PTR(CpuStateFrame, State.callret_sp));
      add(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::rsp, StaticRegisters[X86State::REG_RSP], 0);
      if (Op->PatchSiteAddress) {
        InsertGuestPatchableMove(RelocationTypes::RELOC_GUEST_PATCHABLE_RIP_MOVE, EC_CALL_CHECKER_PC_REG, NewRIP, Op->PatchSiteAddress,
                                 Op->PatchSiteSize);
      } else {
        InsertGuestRIPMove(EC_CALL_CHECKER_PC_REG, NewRIP);
      }
      ldr(TMP2, STATE_PTR(CpuStateFrame, Pointers.ExitFunctionEC));
      br(TMP2);
    } else {
#endif
      // In order to support direct branches without constantly hitting the L1 cache, we emit a call to a block linker,
      // this will compile the branch target block when it is hit and replace the branch to the linker at the callsite
      // with a direct branch to the destination block. Upon invalidation of the target block the backpatch is undone.
      //
      // In addition, to avoid needing to lookup in the cache for returns and any indirect branch prediction penalty,
      // a shadow stack of <GuestReturnRIP, HostReturnPC> pairs is maintained, acting as a first level cache for any
      // return operations. As the guest may not balance calls and returns exactly, an exception handler is expected to
      // be installed by the frontend, to reset the shadow stack to the middle of its valid bounds on overflow/underflow.
      // This shadow stack is also cleared on block invalidation operations or codebuffer switches, to ensure all pointed-to
      // host code is always valid.

      // This code will be backpatched by Arm64JITCore_ExitFunctionLink, below is an enumeration of all the possible cases.
      // Jump thunks are emitted in JIT.cpp after compilation of the entire multiblock.
      //
      // Call with known return block - unlinked
      //    00: adr TMP1, 0xC
      //    04: stp RetReg, TMP1, [SpReg, -0x10]!
      //    08: bl JmpThunk00
      //    JmpThunk00:
      //    00: b 0x8
      //    04: br TMP1
      //    08: ldr TMP1, <Shared exit linker>
      //    0c: blr TMP1
      //    10: HostCode
      //    18: GuestRIP
      //    20: CallerOffset
      //
      // Call with known return block after backpatching - linked in branch immediate range
      //    00: adr TMP1, 0xC
      //    04: stp RetReg, TMP1, [SpReg, -0x10]!
      //    08: bl HostCode                                        - MODIFIED
      //
      // Call with known return block after backpatching - linked out of range
      //    00: adr TMP1, 0xC
      //    04: stp RetReg, TMP1, [SpReg, -0x10]!
      //    08: bl JmpThunk00
      //    JmpThunk00:
      //    00: ldr TMP1, 0x10                                     - MODIFIED 2nd
      //    04: br TMP1
      //    08: ldr TMP1, <Shared exit linker>
      //    0c: blr TMP1
      //    10: HostCode                                           - MODIFIED 1st
      //    18: GuestRIP
      //    20: CallerOffset
      //
      // Jump - unlinked
      //    00: b JmpThunk00
      //    JmpThunk00:
      //    00: b 0x8
      //    04: br TMP1
      //    08: ldr TMP1, <Shared exit linker>
      //    0c: blr TMP1
      //    10: HostCode
      //    18: GuestRIP
      //    20: CallerOffset
      //
      // Jump after backpatching - linked in branch immediate range
      //    00: b HostCode                                         - MODIFIED
      //
      // Jump after backpatching - linked out of range
      //    00: b JmpThunk00
      //    JmpThunk00:
      //    00: ldr TMP1, 0x10                                     - MODIFIED 2nd
      //    04: br TMP1
      //    08: ldr TMP1, <Shared exit linker>
      //    0c: blr TMP1
      //    10: HostCode                                           - MODIFIED 1st
      //    18: GuestRIP
      //    20: CallerOffset

      ARMEmitter::ForwardLabel l_BranchHost;
      ARMEmitter::ForwardLabel l_CallReturn;
      if (Op->Hint == IR::BranchHint::Call) {
        if (!Op->CallReturnBlock.IsInvalid()) {
          auto CallReturnAddressReg = GetReg(Op->CallReturnAddress).X();
          PendingCallReturnTargetLabel = &CallReturnTargets.try_emplace(Op->CallReturnBlock.ID()).first->second;
          (void)adr(TMP1, &l_CallReturn);
          stp<ARMEmitter::IndexType::PRE>(CallReturnAddressReg, TMP1, REG_CALLRET_SP, -0x10);
        } else {
          stp<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::zr, ARMEmitter::XReg::zr, REG_CALLRET_SP, -0x10);
        }
      } else if (Op->Hint == IR::BranchHint::CheckTF) {
        ARMEmitter::ForwardLabel TFUnset;
        ldrb(TMP1, STATE_PTR(CpuStateFrame, State.flags[X86State::RFLAG_TF_RAW_LOC]));
        (void)cbz(ARMEmitter::Size::i32Bit, TMP1, &TFUnset);
        // todo do we need to account for cache patching here?
        InsertGuestRIPMove(TMP1, NewRIP);
        str(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
        ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
        blr(TMP2);
        (void)Bind(&TFUnset);
      }

      EmitLinkedBranch(NewRIP, Op->Hint == IR::BranchHint::Call, Op->PatchSiteAddress, Op->PatchSiteSize);
      (void)Bind(&l_CallReturn);
#ifdef ARCHITECTURE_arm64ec
    }
#endif
  } else {
    ARMEmitter::ForwardLabel SkipFullLookup;
    auto RipReg = GetReg(Op->NewRIP);

    if (Op->Hint == IR::BranchHint::Return) {
      // First try to pop from the call-ret stack, otherwise follow the normal path (but ending in a ret)
      ldp<ARMEmitter::IndexType::POST>(TMP1, TMP2, REG_CALLRET_SP, 0x10);
      sub(TMP1, TMP1, RipReg.X());
      (void)cbz(ARMEmitter::Size::i64Bit, TMP1, &SkipFullLookup);
    }

    // L1 Cache
    ldp<ARMEmitter::IndexType::OFFSET>(TMP1, TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.L1Pointer));

    // Calculate (tmp1 + ((ripreg & L1_ENTRIES_MASK) << 4)) for the address
    // L1Mask is pre-shifted.
    and_(ARMEmitter::Size::i64Bit, TMP2, TMP2, RipReg, ARMEmitter::ShiftType::LSL, FEXCore::ilog2(sizeof(LookupCache::LookupCacheEntry)));
    add(TMP1, TMP1, TMP2);

    ldp<ARMEmitter::IndexType::OFFSET>(TMP2, TMP1, TMP1, 0);

    // Note: sub+cbnz used over cmp+br to preserve flags.
    sub(TMP1, TMP1, RipReg.X());
    (void)cbz(ARMEmitter::Size::i64Bit, TMP1, &SkipFullLookup);
    ldr(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
    str(RipReg.X(), STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));

    (void)Bind(&SkipFullLookup);
    if (Op->Hint == IR::BranchHint::Call) {
      ARMEmitter::ForwardLabel l_CallReturn;
      if (!Op->CallReturnBlock.IsInvalid()) {
        auto CallReturnAddressReg = GetReg(Op->CallReturnAddress).X();
        PendingCallReturnTargetLabel = &CallReturnTargets.try_emplace(Op->CallReturnBlock.ID()).first->second;
        (void)adr(TMP1, &l_CallReturn);
        stp<ARMEmitter::IndexType::PRE>(CallReturnAddressReg, TMP1, REG_CALLRET_SP, -0x10);
      } else {
        stp<ARMEmitter::IndexType::PRE>(ARMEmitter::XReg::zr, ARMEmitter::XReg::zr, REG_CALLRET_SP, -0x10);
      }
      blr(TMP2);
      (void)Bind(&l_CallReturn);
    } else if (Op->Hint == IR::BranchHint::Return) {
      ret(TMP2);
    } else {
      br(TMP2);
    }
  }
}

DEF_OP(Jump) {
  const auto Op = IROp->C<IR::IROp_Jump>();

  PendingTargetLabel = JumpTarget(Op->TargetBlock);
}

DEF_OP(CondJump) {
  auto Op = IROp->C<IR::IROp_CondJump>();

  auto TrueTargetLabel = JumpTarget(Op->TrueBlock);

  if (Op->FromNZCV) {
    b_OrRestart(MapCC(Op->Cond), TrueTargetLabel);
  } else {
    uint64_t Const;
    const bool isConst = IsInlineConstant(Op->Cmp2, &Const);

    auto Reg = GetReg(Op->Cmp1);
    const auto Size = Op->CompareSize == IR::OpSize::i32Bit ? ARMEmitter::Size::i32Bit : ARMEmitter::Size::i64Bit;

    LOGMAN_THROW_A_FMT(IsGPR(Op->Cmp1), "CondJump: Expected GPR");
    LOGMAN_THROW_A_FMT(isConst, "CondJump: Expected constant source");

    if (Op->Cond == IR::CondClass::EQ) {
      LOGMAN_THROW_A_FMT(Const == 0, "CondJump: Expected 0 source");
      cbz_OrRestart(Size, Reg, TrueTargetLabel);
    } else if (Op->Cond == IR::CondClass::NEQ) {
      LOGMAN_THROW_A_FMT(Const == 0, "CondJump: Expected 0 source");
      cbnz_OrRestart(Size, Reg, TrueTargetLabel);
    } else if (Op->Cond == IR::CondClass::TSTZ) {
      LOGMAN_THROW_A_FMT(Const < 64, "CondJump: Expected valid bit source");
      tbz_OrRestart(Reg, Const, TrueTargetLabel);
    } else if (Op->Cond == IR::CondClass::TSTNZ) {
      LOGMAN_THROW_A_FMT(Const < 64, "CondJump: Expected valid bit source");
      tbnz_OrRestart(Reg, Const, TrueTargetLabel);
    } else {
      LOGMAN_THROW_A_FMT(false, "CondJump expected simple condition");
    }
  }

  PendingTargetLabel = JumpTarget(Op->FalseBlock);
}

DEF_OP(Syscall) {
  SpillStaticRegs(TMP1);

  // Jump to the syscall dispatch handler. We won't return after this.
  ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.ThreadDispatchSyscallHandler));
  br(TMP1);
}

DEF_OP(Thunk) {
  auto Op = IROp->C<IR::IROp_Thunk>();
  // Arguments are passed as follows:
  // X0: CTX
  // X1: Args (from guest stack)

  // spill to ctx before ra64 spill
  SpillStaticRegs(TMP1, {
                          .NZCV = false,
                        });

  PushDynamicRegs(TMP1);

  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, GetReg(Op->ArgPtr));

  InsertNamedThunkRelocation(ARMEmitter::Reg::r2, Op->ThunkNameHash);
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<void, void*, void*>(ARMEmitter::Reg::r2);
  } else {
    blr(ARMEmitter::Reg::r2);
  }

  PopDynamicRegs();

  // load from ctx after ra64 refill
  FillStaticRegs({
    .NZCV = false,
  });
}

DEF_OP(ValidateCode) {
  auto Op = IROp->C<IR::IROp_ValidateCode>();
  auto Base = GetReg(Op->Address).X();
  int len = Op->CodeLength;

  const auto Dst = GetReg(Node);
  const auto CRC32Reg = GetReg(Op->crc);

  // Changes to TMP1
  auto WorkingReg = ARMEmitter::XReg::zr;
  auto BaseReg = TMP2;
  auto TmpDataReg = TMP3;
  mov(ARMEmitter::Size::i64Bit, BaseReg, Base);

  while (len >= 8) {
    ldr<ARMEmitter::IndexType::POST>(TmpDataReg, BaseReg, 8);
    crc32x(TMP1, WorkingReg, TmpDataReg);
    len -= 8;
    WorkingReg = TMP1;
  }

  while (len >= 4) {
    ldr<ARMEmitter::IndexType::POST>(TmpDataReg.W(), BaseReg, 4);
    crc32w(TMP1.W(), WorkingReg.W(), TmpDataReg.W());
    len -= 4;
    WorkingReg = TMP1;
  }

  while (len >= 2) {
    ldrh<ARMEmitter::IndexType::POST>(TmpDataReg.W(), BaseReg, 2);
    crc32h(TMP1.W(), WorkingReg.W(), TmpDataReg.W());
    len -= 2;
    WorkingReg = TMP1;
  }

  while (len >= 1) {
    ldrb<ARMEmitter::IndexType::POST>(TmpDataReg.W(), BaseReg, 1);
    crc32b(TMP1.W(), WorkingReg.W(), TmpDataReg.W());
    len -= 1;
    WorkingReg = TMP1;
  }

  sub(ARMEmitter::Size::i32Bit, Dst, TMP1, CRC32Reg);

  ARMEmitter::ForwardLabel Match, End;
  cbz_OrRestart(ARMEmitter::Size::i32Bit, Dst, &Match);

  LoadConstant(ARMEmitter::Size::i32Bit, Dst, 1);
  b_OrRestart(&End);
  BindOrRestart(&Match);
  str(ARMEmitter::XReg::zr, STATE, offsetof(FEXCore::Core::CpuStateFrame, LastSMCInvalidateRIP));
  BindOrRestart(&End);
}

DEF_OP(ThreadRemoveCodeEntry) {
  auto Op = IROp->C<IR::IROp_ThreadRemoveCodeEntry>();

  // Fast path: this thread already queued this entry. SRA stays live. Still
  // poke L1+L2 of the ENTRY (not the chunk) so title LoopTop misses and
  // compiles the rewrite (hbfastq 550ms-stalled with L2 still live). Do not
  // use x2 (SRA / guest RDX).
  ARMEmitter::ForwardLabel Slow, SkipL1, SkipL2;
  mov(ARMEmitter::Size::i64Bit, TMP1, GetReg(Op->EntryToInvalidate));
  mov(ARMEmitter::Size::i64Bit, TMP2, GetReg(Op->NewRIP));
  // Title occupancy is chunk 0 of the function (entry == RIP). Fast path
  // LoopTop then CompileBlock with SRA live (hbfastl1 550ms). In-world the
  // failing chunk is not the entry.
  cmp(ARMEmitter::Size::i64Bit, TMP1, TMP2);
  b_OrRestart(ARMEmitter::Condition::CC_EQ, &Slow);
  ldr(TMP3, STATE, offsetof(FEXCore::Core::CpuStateFrame, LastSMCInvalidateRIP));
  cmp(ARMEmitter::Size::i64Bit, TMP1, TMP3);
  b_OrRestart(ARMEmitter::Condition::CC_NE, &Slow);
  str(TMP2, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));

  ldp<ARMEmitter::IndexType::OFFSET>(TMP3, TMP4, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.L1Pointer));
  and_(ARMEmitter::Size::i64Bit, TMP4, TMP4, TMP1.R(), ARMEmitter::ShiftType::LSL,
       FEXCore::ilog2(sizeof(FEXCore::LookupCache::LookupCacheEntry)));
  add(TMP3, TMP3, TMP4);
  ldr(TMP4, TMP3, 8);
  cmp(ARMEmitter::Size::i64Bit, TMP4, TMP1);
  b_OrRestart(ARMEmitter::Condition::CC_NE, &SkipL1);
  str(ARMEmitter::XReg::zr, TMP3, 8);
  BindOrRestart(&SkipL1);

  ldr(TMP3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.L2Pointer));
  cbz_OrRestart(ARMEmitter::Size::i64Bit, TMP3, &SkipL2);
  {
    const uint64_t VirtualMemorySize = CTX->Config.VirtualMemSize;
    if (std::popcount(VirtualMemorySize) == 1) {
      and_(ARMEmitter::Size::i64Bit, TMP4, TMP1, VirtualMemorySize - 1);
    } else {
      LoadConstant(ARMEmitter::Size::i64Bit, TMP4, VirtualMemorySize);
      and_(ARMEmitter::Size::i64Bit, TMP4, TMP1, TMP4);
    }
  }
  lsr(ARMEmitter::Size::i64Bit, TMP2, TMP4, 12);
  ldr(TMP3, TMP3, TMP2, ARMEmitter::ExtendedType::LSL_64, 3);
  cbz_OrRestart(ARMEmitter::Size::i64Bit, TMP3, &SkipL2);
  and_(ARMEmitter::Size::i64Bit, TMP2, TMP4, 0x0FFF);
  add(TMP3, TMP3, TMP2, ARMEmitter::ShiftType::LSL, FEXCore::ilog2(sizeof(FEXCore::LookupCache::LookupCacheEntry)));
  stp<ARMEmitter::IndexType::OFFSET>(ARMEmitter::XReg::zr, ARMEmitter::XReg::zr, TMP3, 0);
  BindOrRestart(&SkipL2);

  ldr(TMP1, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.DispatcherLoopTop));
  br(TMP1);

  BindOrRestart(&Slow);
  // Copy before spill: TMP1 (x10) is the spill scratch. x12/x13/x14 are not SRA.
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r12, GetReg(Op->EntryToInvalidate));
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r13, GetReg(Op->NewRIP));
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r14, GetReg(Op->PackedCRC));

  SpillStaticRegs(TMP1);

  // GitHub: resume at the failing chunk (NewRIP), invalidate the function entry.
  // hbgh2 stored the entry in RIP and compiled the rewrite from the top.
  str(ARMEmitter::XReg::x13, STATE, offsetof(FEXCore::Core::CpuStateFrame, State.rip));
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, ARMEmitter::Reg::r12);
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r10, ARMEmitter::Reg::r13);
  mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r0, STATE.R());

  ldr(ARMEmitter::XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.ThreadDispatchRemoveCodeEntry));
  br(ARMEmitter::XReg::x2);
}

DEF_OP(CPUID) {
  auto Op = IROp->C<IR::IROp_CPUID>();

  isb();
  mov(ARMEmitter::Size::i64Bit, TMP2, GetReg(Op->Function));
  mov(ARMEmitter::Size::i64Bit, TMP3, GetReg(Op->Leaf));

  PushDynamicRegs(TMP4);
  SpillStaticRegs(TMP4);

  // x0 = CPUID Handler
  // x1 = CPUID Function
  // x2 = CPUID Leaf
  ldr(ARMEmitter::XReg::x0, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDObj));
  ldr(ARMEmitter::XReg::x3, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDFunction));

  if (!TMP_ABIARGS) {
    mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r1, TMP2);
    mov(ARMEmitter::Size::i64Bit, ARMEmitter::Reg::r2, TMP3);
  }

  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<__uint128_t, void*, uint64_t, uint64_t>(ARMEmitter::Reg::r3);
  } else {
    blr(ARMEmitter::Reg::r3);
  }

  if (!TMP_ABIARGS) {
    mov(ARMEmitter::Size::i64Bit, TMP1, ARMEmitter::Reg::r0);
    mov(ARMEmitter::Size::i64Bit, TMP2, ARMEmitter::Reg::r1);
  }

  FillStaticRegs();

  PopDynamicRegs();

  // Results are in x0, x1
  // Results want to be 4xi32 scalars
  mov(ARMEmitter::Size::i32Bit, GetReg(Op->OutEAX), TMP1);
  mov(ARMEmitter::Size::i32Bit, GetReg(Op->OutECX), TMP2);
  ubfx(ARMEmitter::Size::i64Bit, GetReg(Op->OutEBX), TMP1, 32, 32);
  ubfx(ARMEmitter::Size::i64Bit, GetReg(Op->OutEDX), TMP2, 32, 32);
}

DEF_OP(XGetBV) {
  auto Op = IROp->C<IR::IROp_XGetBV>();

  PushDynamicRegs(TMP4);
  SpillStaticRegs(TMP4);

  mov(ARMEmitter::Size::i32Bit, ARMEmitter::Reg::r1, GetReg(Op->Function));

  // x0 = CPUID Handler
  // x1 = XCR Function
  ldr(ARMEmitter::XReg::x0, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDObj));
  ldr(ARMEmitter::XReg::x2, STATE, offsetof(FEXCore::Core::CpuStateFrame, Pointers.XCRFunction));
  if (!CTX->Config.DisableVixlIndirectCalls) [[unlikely]] {
    GenerateIndirectRuntimeCall<uint64_t, void*, uint32_t>(ARMEmitter::Reg::r2);
  } else {
    blr(ARMEmitter::Reg::r2);
  }

  if (!TMP_ABIARGS) {
    mov(ARMEmitter::Size::i64Bit, TMP1, ARMEmitter::Reg::r0);
  }

  FillStaticRegs();

  PopDynamicRegs();

  // Results are in x0, need to split into i32 parts
  mov(ARMEmitter::Size::i32Bit, GetReg(Op->OutEAX), TMP1);
  ubfx(ARMEmitter::Size::i64Bit, GetReg(Op->OutEDX), TMP1, 32, 32);
}

} // namespace FEXCore::CPU
