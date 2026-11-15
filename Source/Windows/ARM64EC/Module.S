.text
.balign 16

// iOS clobbers x18 on context switches. Read TEB from TPIDRRO_EL0 + the raw
// pthread TSD slot that wine's ntdll-unix publishes the TEB in, instead of
// trusting x18 directly. TPIDRRO_EL0 IS preserved by iOS across context
// switches, and AND #~7 + ldr is the canonical pthread TLS pattern.
//
// The #0x898 below is a PLACEHOLDER, not the slot. The real slot is whichever
// one backs ntdll-unix's TEB pthread key in this process, which is not knowable
// at assembly time and differs per device and per load order. Wine's x18
// binary patcher recognises this exact three-instruction triplet and rewrites
// the immediate through the .text RW alias, before this code is ever executed
// (see the "retarget hand-written TEB-from-TSD reads" pass in virtual_ios.c).
//
// Do NOT "correct" this constant, and do NOT break the triplet apart or
// reorder it -- the patcher matches all three instructions with matching
// registers, and an unmatched sequence silently keeps reading the wrong slot.
// The JIT emitters read the same offset at runtime via IosTebTsdOffset.
#ifdef FEX_IOS_HOST
.arch_extension lse   // ml1131: stadd/ldadd for the transition probe counters
// ml1131: add 1 to the sp-sharded counter at IosXpFex + \off. Clobbers \a, \b.
.macro IOS_XP_COUNT off, a, b
  adrp \a, IosXpFex
  add \a, \a, #:lo12:IosXpFex
  mov \b, sp
  ubfx \b, \b, #16, #4
  add \a, \a, \b, lsl #6
  add \a, \a, #\off
  mov \b, #1
  stadd \b, [\a]
.endm
.macro IOS_LOAD_TEB reg
  mrs \reg, TPIDRRO_EL0
  and \reg, \reg, #~7
  ldr \reg, [\reg, #0x898]
.endm

// ml1136: rewrite \reg from a PE VA to the JIT-pool alias of the same byte when
// IosAliasEntries knows the image, because PEB->EcCodeBitMap is indexed by
// ADDRESS BITS (virtual_ios.c set_arm64ec_range: word = addr >> 18, bit =
// (addr >> 12) & 63) and only 0x40000 words are committed -- good to 16 GB.
// A pool address (the pool sits near 0x15xxxxxxxx) is in range; a PE VA such as
// ucrtbase's 0x71fe780000 is not, so testing one can never report ARM64EC and
// every such import falls through to emulation instead. Leaves \reg alone when
// it is already pool space; branches to \fail when it is neither.
// Entry layout (as ExitFunctionEC and ios_ffs_xlate read it): 0 = PeBase,
// 8 = JitBase, 16 = Size, 32 bytes per entry, walked newest-first.
// Only \a \b \c \d may be used: on ARM64EC x13/x14/x23/x24/x28 are disallowed
// outright, x19-x22/x25-x27 hold x64 nonvolatile state, and x0-x4 carry the
// x64 argument registers RCX/RDX/R8/R9/R10 that must reach the callee intact.
// So callers pass x10/x11/x12/x16, which are dead at this point.
// Nothing is spilled: the walk needs exactly five live values (target, base,
// cursor, offset, size) and \reg is only written on a hit, so a miss returns
// the target unchanged and \fail can branch straight out.
.macro IOS_PE_TO_POOL_TO reg, a, b, c, d, fail
  lsr \a, \reg, #15
  cmp \a, #0x40000
  b.lo 99f                        // already pool space: nothing to do
  adrp \a, IosAliasEntries
  add \a, \a, #:lo12:IosAliasEntries   // table base -- \a stays the base
  adrp \b, IosAliasCount
  ldr \b, [\b, #:lo12:IosAliasCount]
  and \b, \b, #0xffffffff         // volatile int: count is in the low word
  add \b, \a, \b, lsl #5          // cursor, one past the last entry
97:
  cmp \b, \a
  b.eq \fail                      // walked everything: not a known image
  sub \b, \b, #32                 // entry
  ldr \c, [\b]                    // Entry.PeBase
  sub \c, \reg, \c                // offset (wraps when \reg < PeBase)
  ldr \d, [\b, #16]               // Entry.Size
  cmp \c, \d
  b.hs 97b
  ldr \d, [\b, #8]                // Entry.JitBase
  add \reg, \d, \c                // pool alias of the same byte
99:
.endm

// ml1207: the inverse of IOS_PE_TO_POOL_TO -- pool address to the PE address of
// the same byte. The guest executes the pool copy, but loader.c binds imports
// into the PE view (`thunk_list->u1.Function = ...` is a store through a PE
// VA) and only the NtProtect-time iat-sync carries those stores across. When
// that sync does not cover a slot, the pool copy still holds whatever the file
// mapped -- for an ARM64EC hybrid image that is the 0xcccccccccccccccc trap
// filler -- so following an import thunk inside the pool copy reads filler
// instead of the bound target. The PE view is where the bind actually happened,
// so it is the copy to trust. Same entry layout and same scratch rules as
// IOS_PE_TO_POOL_TO; leaves \reg alone when no entry contains it.
.macro IOS_POOL_TO_PE_TO reg, a, b, c, d, fail
  adrp \a, IosAliasEntries
  add \a, \a, #:lo12:IosAliasEntries
  adrp \b, IosAliasCount
  ldr \b, [\b, #:lo12:IosAliasCount]
  and \b, \b, #0xffffffff
  add \b, \a, \b, lsl #5          // cursor, one past the last entry
98:
  cmp \b, \a
  b.eq \fail                      // walked everything: not a known pool address
  sub \b, \b, #32
  ldr \c, [\b, #8]                // Entry.JitBase
  sub \c, \reg, \c                // offset (wraps when \reg < JitBase)
  ldr \d, [\b, #16]               // Entry.Size
  cmp \c, \d
  b.hs 98b
  ldr \d, [\b]                    // Entry.PeBase
  add \reg, \d, \c                // PE address of the same byte
99:
.endm

// Read by RetToEntryThunk below; ARM64EC/Module.cpp sets it at process init.
.data
.balign 8
.globl IosRetToJit
IosRetToJit:
  .word 0

// ml1230: which route reached enter_jit.
//
// The 08:10 run proved the ARM64EC target is correct -- thunk slot rva 0x50650
// holds 0x153b6c7fc (kernelbase+0x547fc) and the SEGV dump says [EC=1] -- yet
// the call still reached enter_jit and branched to NULL. Both paths that
// should have prevented that (the bitmap test's EC branch, and ml1222's
// "FEX uninitialised + real target -> branch natively" guard) are supposed to
// make enter_jit unreachable for this call, so reading the code cannot say
// which one let it through. Each route stamps its own byte here and enter_jit
// writes the record to stderr once, so one run names the gate instead of
// another round of inference.
//
//   '1' check_target_ec   -- the pre-ExitToX64 dispatch_call bitmap test
//   '2' ios_ffs_reject    -- thunk-reject path (guard declined)
//   '3' ios_ffs_no_bypass -- no x64 thunk shape matched at all
.balign 8
.globl IosJitGateMsg
IosJitGateMsg:
  .ascii "\n[jit-gate] "
  .byte 0x30                      // offset 12: the route tag
  .byte 0x0a                      // offset 13: newline
.text

// Stamp the route tag. x16/x17 are IP0/IP1: dead at every call boundary and
// unused by the tail of each route below.
.macro IOS_SET_GATE imm
  adrp x16, IosJitGateMsg
  add x16, x16, #:lo12:IosJitGateMsg
  mov w17, #\imm
  strb w17, [x16, #12]
.endm
#endif

  // __os_arm64x_x64_jump in ARM64EC docs
  // Expects target code address in x9
.globl DispatchJump
DispatchJump:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr.
  b check_target_ec

  // __os_arm64x_dispatch_ret in ARM64EC docs
  // Expects target code address in lr
.globl RetToEntryThunk
RetToEntryThunk:
  mov x9, lr
#ifdef FEX_IOS_HOST
  // An entry thunk returns to the x64 caller of its function. Enter the JIT at once: the dispatcher
  // tests the EC code bitmap at the loop top on an L1 miss, and an ARM64EC address is never in L1.
  // IosRetToJit is set at process init; 0 keeps the test here.
  adrp x16, IosRetToJit
  ldr w16, [x16, #:lo12:IosRetToJit]
  cbnz w16, enter_jit
#endif

check_target_ec:
  // Check if target is in fact x86 code
#ifdef FEX_IOS_HOST
  IOS_LOAD_TEB x16
  ldr x16, [x16, #0x60] // TEB->PEB
#else
  ldr x16, [x18, #0x60] // TEB->PEB
#endif
  ldr x16, [x16, #0x368] // PEB->EcCodeBitMap
  lsr x17, x9, #18
  ldr x16, [x16, x17, lsl #3]
  lsr x17, x9, #12
  lsr x16, x16, x17
  tbnz x16, #0, ExitFunctionEC
#ifdef FEX_IOS_HOST
  IOS_SET_GATE 0x31               // ml1230: dispatch_call bitmap said "not EC"
#endif
  b enter_jit

  // __os_arm64x_dispatch_call_no_redirect in ARM64EC docs
  // Expects target code address in x9, and to be called using a 'blr x16' instruction.
.globl ExitToX64
ExitToX64:
#ifdef FEX_IOS_HOST
  // iOS ml316 FFS BYPASS (root cause of the ml315 SCM-RPC ccontext=0x10 kill).
  //
  // When wine's __os_arm64x_check_call cannot classify a target (task #40: the x18 fix
  // that would let it is A/B-proven to break CEF), a native EC caller's call to an EC
  // function gets routed through clang's $iexit_thunk$cdecl$...$varargs with x9 = the
  // target's x64 fast-forward sequence. That thunk builds NO x64 frame -- it just does
  // `stp x4, x5, [sp, #0x20]` and calls here. After our `str lr, [sp,#-8]!` the guest
  // frame reads [RSP+0x28]=saved x4, [RSP+0x30]=saved x5 -- so when the FFS jmp lands
  // back in EC code and the varargs ENTRY thunk hands those to the callee as its stack
  // arguments, a variadic EC callee receives (x4, x5) VERBATIM instead of the real
  // args. ml315 measured exactly that: NdrClientCall2's param2 = the caller's
  // stack-args pointer, param3 = 0x10 = x5 the size -- which became the "context
  // handle" the SCM RPC then dereferenced.
  //
  // Real Windows never takes this round trip: check_call pattern-matches the FFS and
  // returns the underlying EC target for a direct native call. Do that here instead --
  // the one transition point we fully control. If x9 is the canonical 14-byte FFS
  //   48 8b c4  mov rax, rsp
  //   48 89 58 20  mov [rax+0x20], rbx
  //   55 5d     push rbp; pop rbp
  //   e9 rel32  jmp target
  // (byte-identical in every wine-built EC DLL: rpcrt4/sechost dumps verified) and the
  // jmp target is EC code per the bitmap, branch to it natively. x4/x5 flow through
  // untouched and the exit thunk becomes a transparent pass-through; the EC callee
  // rets to lr = the exit thunk's continuation. Non-FFS or non-EC targets fall
  // through to normal emulation with every register intact.
  //
  // Scratch: x16/x17 (IP0/IP1, dead at any call boundary) + x23 -- safe for the same
  // reason ExitFunctionEC already clobbers it: EnterEC rebuilds the RSP SRA register
  // from the native sp on every JIT entry. The `br` targets the PE VA; the Mach
  // exec-fault redirect translates it to the pool copy (proven ~33us path, and this
  // is RPC-call frequency, not per-frame).
  // iOS-Madeira: resolve an x64 import thunk to the function it jumps to before any of the
  // FFS tests below. Wine's builtins reach this exit thunk with x9 pointing at an import
  // thunk (TlsAlloc from ucrtbase's exit thunk was the first), and ExitToX64 matches only
  // the FFS shape, so without this every such call fell to ios_ffs_no_bypass and entered
  // the JIT with x9 still = the thunk. Two shapes exist:
  //   bare        ff 25 rel32                    jmp *__imp_x(%rip)
  //   hotpatched  48 8d a4 24 00 00 00 00 ff 25  build/wine-patches/0001 puts this in
  //                                              front of the same jmp, because Forza's
  //                                              anti-tamper requires a hotpatch prologue.
  // Follow the jmp to its IAT slot, then hand the real target to the shared alias/bitmap
  // path: EC targets branch natively, genuine x64 ones fall through to emulation with x9
  // restored to the thunk (emulating the thunk itself is the correct x64 behaviour).
  // Scratch x16/x17 only until ios_thunk_slot, which spills x4/x9 before using
  // x4/x23 as well.
  ldrh w16, [x9]
  movz w17, #0x25ff
  cmp w16, w17
  b.eq ios_thunk_bare
  ldr w16, [x9]
  movz w17, #0x8d48
  movk w17, #0x24a4, lsl #16       // 48 8d a4 24 = lea rsp,[rsp+0]
  cmp w16, w17
  b.ne ios_ffs_check
  ldr w16, [x9, #4]
  cbnz w16, ios_ffs_check          // the four operand bytes must be zero
  ldrh w16, [x9, #8]
  movz w17, #0x25ff
  cmp w16, w17
  b.ne ios_ffs_check
  ldursw x16, [x9, #10]            // jmp rel32, hotpatched
  add x17, x9, x16
  add x17, x17, #14
  b ios_thunk_slot
ios_thunk_bare:
  ldursw x16, [x9, #2]             // jmp rel32, bare
  add x17, x9, x16
  add x17, x17, #6
ios_thunk_slot:
  // ml1209: the displacement this thunk's jmp carries is a LINK-TIME constant
  // that belongs to the file, and the pool copy of it has been observed to
  // differ. kernel32+0x35a70 is `48 8d a4 24 00 00 00 00 ff 25 <rel32>`: the
  // file's rel32 is 0x1abd2, landing on rva 0x50650 in .rdata, which really is
  // GetCommandLineA's IAT slot; the pool copy's rel32 is 0x11402, landing on
  // rva 0x46e80 -- past the end of .hexpthk (va 0x40000 + 0x1cc0) and before
  // .rdata (va 0x50000), i.e. the uninitialised gap, which reads as 0xcc
  // filler. Following the pool copy therefore reads a constant that was never
  // a target. Recompute the slot from the PE copy, the copy the linker wrote,
  // and only then map it back into the pool to read.
  //
  // The pool-derived slot is kept on the stack as a fallback so that an image
  // the alias table does not know behaves exactly as before. sp stays
  // 16-aligned through the push/pop on every path.
  str x17, [sp, #-16]!             // the pool-derived slot, as a fallback
  mov x16, x9
  IOS_POOL_TO_PE_TO x16, x10, x11, x12, x17, 89f
  cmp x16, x9
  b.eq 89f                         // unknown image: keep the pool-derived slot
  ldr w10, [x16]
  movz w11, #0x8d48
  movk w11, #0x24a4, lsl #16       // hotpatched prologue 48 8d a4 24?
  cmp w10, w11
  b.ne 88f
  ldursw x10, [x16, #10]           // yes: rel32 at +10, rip+14
  add x17, x16, x10
  add x17, x17, #14
  b 87f
88:
  ldursw x10, [x16, #2]            // bare: rel32 at +2, rip+6
  add x17, x16, x10
  add x17, x17, #6
87:
  // ml1213: record what the PE copy's own displacement produced, so a log can
  // separate "the displacement is wrong too" from "the displacement is right
  // and the slot it names is unbound".
  adrp x11, IosFfsBypassLog
  add x11, x11, #:lo12:IosFfsBypassLog
  str x10, [x11, #128]             // [16] = the displacement used (signed rel32)
  str x17, [x11, #136]             // [17] = the slot address it derived
  // x17 is now the slot's address in PE space. Read the VALUE from the PE view:
  // loader.c binds an import by storing through a PE VA, and the log proves the
  // PE view carries the resolved pointer (the ucrtbase dispatcher slot reads
  // back as a pool address there). The pool copy of a *plain* IAT slot is not
  // carried over: rva 0x50650 there still holds the file's unbound 0x63fc8
  // hint/name rva, which is neither NULL nor 0xcc filler, so it sailed past the
  // filler test below, failed the FFS-prologue test, and then had 0x63fc8
  // classified against the EC bitmap -- rejected, into emulation, into
  // enter_jit's `ldr x16,[x17,#0x40]; br x16` and the br to NULL at pc=0.
  ldr x10, [x17]
  cbz x10, 89f                     // unbound here too: try the pool-derived slot
  movz x11, #0xcccc
  movk x11, #0xcccc, lsl #16
  movk x11, #0xcccc, lsl #32
  movk x11, #0xcccc, lsl #48
  cmp x10, x11
  b.eq 89f                         // filler: likewise
  movz x11, #0x10, lsl #16         // 0x100000
  cmp x10, x11
  b.hs 83f
  // ml1212: a value below 1 MB is an rva that leaked out of an unbound slot,
  // not an address. No real target here is that low (PE images sit near
  // 0x71fe..., the JIT pool near 0x15..., the FEX arena at 0x7c00000000), and
  // treating one as a code address is exactly how this crash worked: it is not
  // NULL and not filler, so it survived every earlier test, then passed the EC
  // bitmap's range check and ended in enter_jit's `br x16` with x16 = 0.
  adrp x11, IosFfsBypassLog
  add x11, x11, #:lo12:IosFfsBypassLog
  ldr x12, [x11, #104]
  add x12, x12, #1
  str x12, [x11, #104]             // [13] = rva guard fired
  b 89f
83:
  mov x16, x17                     // slot address, for the filler/NULL re-read below
  mov x17, x10                     // the value, from the copy loader.c writes
  adrp x11, IosFfsBypassLog
  add x11, x11, #:lo12:IosFfsBypassLog
  ldr x12, [x11, #96]
  add x12, x12, #1
  str x12, [x11, #96]              // [12] = slot values taken from the PE view
  // ml1213: keep the last PE slot address and the value found there. Counters
  // alone cannot distinguish "the PE view is unbound too" from "the PE view is
  // bound but the answer is the wrong function"; these two numbers can, and
  // they cost nothing to record on a path that already loads both.
  str x16, [x11, #112]             // [14] = last PE-view slot address
  str x17, [x11, #120]             // [15] = value read from it
  add sp, sp, #16                  // taken: drop the fallback
  b 84f
89:
  ldr x17, [sp], #16               // fallback: the pool-derived slot address
85:
  mov x16, x17                     // ml1207: keep the slot address itself
  ldr x17, [x17]                   // the pointer the jmp loads
84:
  // ml1218: canonicalise the target into POOL space before the bitmap test.
  //
  // That test indexes a 256 KB bitmap with addr>>15 and rejects anything at or
  // above 0x40000 words, which is correct for the pool (0x153...) and wrong for
  // a PE image (0x71fe...). Both paths above can produce either: the PE IAT read
  // yields whatever loader.c stored, and a value that IS a real ARM64EC target
  // still fails the range check when it is expressed as a PE address -- so the
  // call was rejected into emulation for being correct. IOS_PE_TO_POOL_TO is a
  // no-op on a pool address (it exits early when reg>>15 < 0x40000) and leaves
  // reg untouched when no alias entry contains it, so calling it here cannot
  // regress the plain pool path.
  adrp x11, IosFfsBypassLog
  add x11, x11, #:lo12:IosFfsBypassLog
  str x17, [x11, #144]             // [18] = target before canonicalisation
  IOS_PE_TO_POOL_TO x17, x10, x11, x12, x23, 82f
82:
  adrp x11, IosFfsBypassLog
  add x11, x11, #:lo12:IosFfsBypassLog
  str x17, [x11, #152]             // [19] = target the bitmap test will see
  // ml1136: the slot rarely holds the native body. loader.c's
  // arm64ec_iat_is_exported_x64 keeps the x64-VISIBLE 14-byte fast-forward stub
  // of a hybrid export (in the importer's .hexpthk) so x64 callers and hook
  // resolvers see an x64-shaped export, and Wine installs pool aliases into IATs.
  // Either way the value below is x64 bytes, so the EC-bitmap test that follows
  // could never pass it and the call was rejected into emulation -- which is the
  // pc=0, because no thread owns a CpuStateFrame during the DllMain walk.
  // Canonicalise into pool space and follow the fast-forward stub to the native
  // body, exactly as ios_ffs_check does for x9, and only then ask the bitmap.
  //
  // The ORIGINAL slot value is spilled and restored on every miss. That is not
  // tidiness: an x64 thunk's bytes can live inside a page the CodeMap marks
  // ARM64EC (kernel32's .text holds both its ARM64 code and the embedded
  // hotpatched thunks), so testing a canonicalised thunk address against the
  // bitmap can report EC and branch into x86 bytes executed as ARM64. Falling
  // back to the untouched slot value keeps the old test exactly as it was.
  // x9 is deliberately untouched too: if all of this fails, emulation must
  // still run the ORIGINAL thunk.
  //
  // x23 and x4 are the only extra scratch used, and both are spilled in the
  // frame below. x4 == x64 R10 and the bitmap test uses it as a scratch, while
  // the bypass path promises R10 reaches the callee intact -- so it has to be
  // saved and restored, which the original code did not do. x4/x5 are NOT free
  // as scratch generally: they carry the ARM64EC variadic descriptor (stack-args
  // pointer and size) and the ml315 note at the top of this file records what
  // clobbering them cost -- an RPC livelock where a pointer became
  // dwDesiredAccess and the size became the context handle. x0-x3 are
  // RCX/RDX/R8/R9 and must reach the callee untouched.
  //
  // The frame also repairs a PRE-EXISTING sp imbalance. ios_thunk_slot used to
  // push nothing, yet ios_thunk_reject branched into ios_ffs_reject, whose
  // `ldp x4, x9, [sp], #16` pairs with the push in ios_ffs_check -- so every
  // thunk that was correctly rejected into emulation popped 16 bytes that were
  // never pushed, moving sp by +16 and loading garbage into x4/x9. The reject
  // path now unwinds its own frame and joins the shared counter at
  // ios_ffs_reject_count, which does not pop.
  //
  // Frame: [sp+0]=slot value, [sp+8]=x4 (x64 R10), [sp+16]=x23, [sp+24]=hop budget.
  stp x17, x4, [sp, #-32]!         // keep sp 16-aligned; save slot value + R10
  stp x23, xzr, [sp, #16]
  // ml1207: trap filler or NULL in the slot means the pool copy of this IAT
  // slot was never synced from the PE view that loader.c binds into, so the
  // number just loaded is not a target at all. Neither 0 nor the 0xcc filler
  // can ever be a callable address, so re-reading the same slot from the PE
  // copy cannot turn a working call into a broken one -- and it turns this
  // call into a working one. Only entered on those two values.
  movz x23, #0xcccc
  movk x23, #0xcccc, lsl #16
  movk x23, #0xcccc, lsl #32
  movk x23, #0xcccc, lsl #48
  cmp x17, x23
  b.eq 91f
  cbnz x17, 92f
91:
  IOS_POOL_TO_PE_TO x16, x10, x11, x12, x23, 93f
93:
  ldr x17, [x16]
  str x17, [sp]                    // keep [sp] = the value actually in use
  adrp x23, IosFfsBypassLog
  add x23, x23, #:lo12:IosFfsBypassLog
  ldr x16, [x23, #88]
  add x16, x16, #1
  str x16, [x23, #88]              // [11] = slots re-read from the PE view
92:
  // Bounded FFS chain. One hop is the normal case -- a hybrid export's slot holds a
  // single 14-byte FFS whose jmp target is the native EC body -- but kernel32 ->
  // kernelbase forwarders can put a second hybrid export in the way, so follow up to
  // four hops instead of silently giving up on hop two. Running out of budget is
  // treated exactly like "not an FFS chain", i.e. the untouched slot value is what
  // the bitmap test sees, and [6]/[7] record that it happened.
  movz w23, #4
  str x23, [sp, #24]               // hop budget
ios_thunk_slot_follow:
  IOS_PE_TO_POOL_TO x17, x10, x11, x12, x16, ios_thunk_slot_orig
  ldr x16, [x17]
  movz x23, #0x8b48
  movk x23, #0x48c4, lsl #16       // 48 8b c4 48 = mov rax,rsp / mov [rax+0x20],rbx
  movk x23, #0x5889, lsl #32
  movk x23, #0x5520, lsl #48
  cmp x16, x23
  b.ne ios_thunk_slot_followed     // not an FFS: x17 is the real target
  ldrh w16, [x17, #8]
  movz w23, #0xe95d                // 5d e9 = pop rbp / jmp rel32
  cmp w16, w23
  b.ne ios_thunk_slot_followed
  ldursw x16, [x17, #10]
  add x17, x17, x16
  add x17, x17, #14                // raw target = stub base + 14 + rel32
  // Record what was followed, so the next log can prove the chain end-to-end even
  // when the final bitmap verdict is a rejection.
  adrp x16, IosFfsBypassLog
  add x16, x16, #:lo12:IosFfsBypassLog
  ldr x23, [x16, #64]
  add x23, x23, #1
  str x23, [x16, #64]              // [8] = count of FFS prologues followed
  str x17, [x16, #72]              // [9] = last FFS target reached
  ldr x23, [sp, #24]
  subs x23, x23, #1
  str x23, [sp, #24]
  b.ne ios_thunk_slot_follow
  b ios_thunk_slot_orig            // chain longer than the budget: give up cleanly
ios_thunk_slot_followed:
  b ios_thunk_slot_bitmap
ios_thunk_slot_orig:
  // [6]/[7]: the fix was reached and did not apply, plus the value it gave up
  // on. Only x16/x17/x23 are touched here; x4 was saved at entry and is
  // restored on both exits.
  adrp x16, IosFfsBypassLog
  add x16, x16, #:lo12:IosFfsBypassLog
  ldr x23, [x16, #48]
  add x23, x23, #1
  str x23, [x16, #48]              // [6] = unresolved import-slot count
  ldr x23, [sp]                    // the slot value as it actually was
  str x23, [x16, #56]              // [7] = last unresolved slot value
  str x23, [x16, #80]              // [10] = same value, kept across [7] overwrites
  ldr x17, [sp]                    // target for the bitmap test below
ios_thunk_slot_bitmap:
  // iOS-Madeira: classify the resolved target BEFORE falling back to emulation.
  //
  // This path can run inside process_attach's DllMain walk, i.e. BEFORE
  // arm64ec_process_init has run FEX's ProcessInit/ThreadInit. Then no thread has a
  // CpuStateFrame and the CPU area's EmulatorData is all zero, so enter_jit's
  // `ldr x16,[x17,#0x40]; br x16` branches to NULL. That was 2026-11-14's
  // c0000005 at pc=0 with cpu_area[0x40]=0: ucrtbase's call through
  // __os_arm64x_dispatch_call_no_redirect with x9 = kernel32's bare `ff 25` thunk
  // for kernelbase!TlsAlloc. TlsAlloc is ARM64EC code in a hybrid image, so the
  // correct outcome is a native branch and the emulator is never needed.
  //
  // Index space (this is the trap that made an earlier attempt miss): the bitmap is
  // indexed by ADDRESS BITS -- word = addr >> 18, bit = (addr >> 12) & 63 -- and
  // only 0x40000 words are committed, so it is good to 16 GB and the pool (near
  // 0x15xxxxxxxx) fits while a PE VA (0x71fe...) does not. Everything above is
  // canonicalised into pool space before this test for exactly that reason.
  lsr x4, x17, #15                 // (addr >> 12) / 8 == addr >> 15
  cmp x4, #0x40000                 // 256 KB of bitmap covers 8 GB of pool
  b.hs ios_thunk_reject            // not pool space: cannot be EC code
  IOS_LOAD_TEB x16
  ldr x16, [x16, #0x60]            // TEB->PEB
  ldr x16, [x16, #0x368]           // PEB->EcCodeBitMap
  cbz x16, ios_thunk_reject
  lsr x4, x17, #18                 // word index
  ldr x16, [x16, x4, lsl #3]
  lsr x4, x17, #12                 // LSRV uses bits[5:0] == the page's bit index
  lsr x16, x16, x4
  tbz x16, #0, ios_thunk_reject
  // EC: branch natively. The pool copy is already executable, so this needs no
  // exec-fault redirect. R10 (x4) is restored from the frame first so it reaches
  // the callee intact; x9 was never touched on this path.
  adrp x16, IosFfsBypassLog
  add x16, x16, #:lo12:IosFfsBypassLog
  ldr x23, [x16]
  add x23, x23, #1
  str x23, [x16]                   // [0] = bypass count
  str x17, [x16, #8]               // [1] = last EC target taken natively
  ldr x4, [sp, #8]                 // restore x64 R10
  ldr x23, [sp, #16]               // restore x64 nonvolatile x23
  add sp, sp, #32
  br x17
ios_thunk_reject:
  // ml1220: a rejection is not always the right answer.
  //
  // Reaching here means the bitmap says "not ARM64EC", and the normal response
  // is to emulate, which is correct for a genuine x64 jmp target. But this site
  // is also reached during process_attach's DllMain walk, where NO thread has a
  // CpuStateFrame yet: enter_jit then reads an all-zero CPU area and executes
  // `br x16` with x16 = 0, which is a guaranteed c0000005 at pc=0 -- exactly the
  // crash that has survived builds 24..33 of this investigation. Emulating is
  // not merely suboptimal there, it cannot work at all.
  //
  // Two conditions make a native branch the only sound answer:
  //   * x17 is a real code address rather than an rva or filler, established
  //     either by actually following an FFS stub ([sp+24] != the initial 4) or,
  //     when nothing was followed, by the slot value in use being a full
  //     address (>= 0x100000). A followed stub's jmp target is that image's
  //     native ARM64EC body BY CONSTRUCTION -- .hexpthk is the x64-visible face
  //     of native code, which is why ucrtbase reaches it through an exit thunk
  //     in the first place -- and a bound IAT slot holds a resolved address,
  //     not an rva. Either way the only thing still in doubt is the bitmap's
  //     own marking, and an unmarked page is not evidence that the code is x64.
  //   * DispatcherLoopTopEnterEC is NULL, i.e. FEX has not initialised this
  //     thread, so the emulation branch would dereference NULL.
  // If FEX is live the bitmap keeps its authority and nothing changes; if the
  // slot holds an unbound hint/name rva or 0xcc filler, nothing changes either.
  //
  // The point of the second route is that the alternative is not "emulate
  // correctly" but "br x16 with x16 = 0". Given a guaranteed fatal fault, a
  // resolved native address is the better branch on any accounting.
  IOS_LOAD_TEB x16
  ldr x16, [x16, #0x1788]          // TEB->ChpeV2CpuAreaInfo
  cbz x16, 94f
  ldr x16, [x16, #0x40]            // ->EmulatorData[2] == DispatcherLoopTopEnterEC
  cbnz x16, 94f                    // FEX is initialised: honour the bitmap
  // ml1222: FEX is uninitialised, so enter_jit is not a fallback -- it is a
  // guaranteed `br x16` with x16 = 0. Under that condition ANY real address is
  // a better branch than emulation. The earlier versions of this guard asked
  // for more (that a stub had been followed, or that the slot value was
  // >= 0x100000) and the 00:50 run proved that was too strict: the guard
  // visibly did not fire, cpu_area[0x40] was still 0, and the crash was
  // byte-identical to the build without any guard at all. So drop those
  // conditions and keep only "not NULL, not filler", which are the two values
  // that cannot be a target under any reading.
  cbz x17, 94f
  movz x23, #0xcccc
  movk x23, #0xcccc, lsl #16
  movk x23, #0xcccc, lsl #32
  movk x23, #0xcccc, lsl #48
  cmp x17, x23
  b.eq 94f
95:
  adrp x16, IosFfsBypassLog
  add x16, x16, #:lo12:IosFfsBypassLog
  ldr x23, [x16]
  add x23, x23, #1
  str x23, [x16]                   // [0] = bypass count (counted as a bypass)
  str x17, [x16, #8]               // [1] = last target taken natively
  ldr x4, [sp, #8]                 // restore x64 R10
  ldr x23, [sp, #16]               // restore x64 nonvolatile x23
  add sp, sp, #32
  br x17
94:
  // Rejected into emulation. Unwind this frame and join the shared counter at
  // ios_ffs_reject_count -- NOT ios_ffs_reject, whose ldp pairs with the push in
  // ios_ffs_check and would corrupt sp by 16 bytes here.
  ldr x4, [sp, #8]
  ldr x23, [sp, #16]
  add sp, sp, #32
  b ios_ffs_reject_count

// ml7xx: x9 matched NO x64 thunk shape, so it is a raw target address.
//
// Every test above treats x9 as an x86 import thunk, because that is what wine's
// builtins hand this dispatcher and decoding it is what made TlsAlloc work. But
// clang also emits $iexit_thunk$cdecl$* blocks whose x9 is an ARM64EC callee:
//
//     adrp x8, page ; ldr x16,[x8,#0x898] ; blr x16 ; mov x0, x8
//
// (all four in ucrtbase are byte-identical and share that one slot, so the
// per-call callee cannot be the slot value -- it is x9). Build 15's log shows
// exactly that: slot 0xe3898 = 0x1536154e4 = xtajit64 pool 0x1534fd000 + ExitToX64
// 0x1184e4, i.e. already correct; x9 = 0x153a85a70, in the pool but past every
// module on the stack; x10 = x11 = the thunk's own start.
//
// Such a target fails every thunk test and falls to ios_ffs_no_bypass, where
// enter_jit runs `ldr x16,[x17,#0x40]; br x16` against an all-zero CPU area --
// no thread has a CpuStateFrame yet during the DllMain walk -- and branches to
// NULL. That is the c0000005 at pc=0 whose lr is ucrtbase.dll+0x90f1c, the
// `mov x0,x8` after the blr.
//
// So if the EC bitmap says the raw target is ARM64EC code, branch to it
// natively. The target is canonicalised into pool space first (the same
// IOS_PE_TO_POOL_TO the import-slot path uses), because Wine also hands this
// dispatcher PE VAs and the 0x40000 bound below -- correct for the pool, wrong
// for a PE module near 0x71fe... -- would otherwise reject every one of them.
// It is only reached once the thunk shapes have been ruled out, so it cannot
// mistake an x64 thunk for EC code. x4 (x64 R10) and x23 are callee-saved, so
// both are spilled across it.
//
// PLACEMENT: this must stay off every fall-through path. ios_ffs_reject runs
// straight into ios_ffs_no_bypass on purpose, and it has just restored x9 to the
// thunk and x4 to its own saved copy -- landing here from that edge would branch
// natively to an x64 thunk that is already EC-marked (.text of an EC image
// carries the bit). Its only entrances are the two b.ne below, from the
// ios_ffs_check shape test; ios_thunk_reject above ends in an unconditional
// branch to ios_ffs_reject, so nothing falls in here.
ios_ec_entry:
  stp x4, x23, [sp, #-16]!       // keep sp 16-aligned; x4=x64 R10
  mov x17, x9                    // candidate target, canonicalised below
  IOS_PE_TO_POOL_TO x17, x10, x11, x12, x16, ios_ec_entry_miss
  lsr x4, x17, #15               // (addr >> 12) / 8 == addr >> 15
  cmp x4, #0x40000               // 256 KB of bitmap covers 8 GB of pool
  b.hs ios_ec_entry_miss         // not pool space: cannot be EC code
  IOS_LOAD_TEB x16
  ldr x16, [x16, #0x60]          // TEB->PEB
  ldr x16, [x16, #0x368]         // PEB->EcCodeBitMap
  cbz x16, ios_ec_entry_miss
  lsr x4, x17, #18               // word index
  ldr x16, [x16, x4, lsl #3]
  lsr x4, x17, #12               // LSRV uses bits[5:0] == the page's bit index
  lsr x16, x16, x4
  tbz x16, #0, ios_ec_entry_miss
  adrp x16, IosFfsBypassLog
  add x16, x16, #:lo12:IosFfsBypassLog
  ldr x23, [x16, #32]
  add x23, x23, #1
  str x23, [x16, #32]            // [4] = raw-target EC entries taken natively
  str x17, [x16, #40]            // [5] = last such target
  ldp x4, x23, [sp], #16
  br x17                         // native ARM64EC: x0-x8 and lr untouched
ios_ec_entry_miss:
  ldp x4, x23, [sp], #16
  b ios_ffs_no_bypass            // not EC: emulate, exactly as before

ios_ffs_check:
  ldr x16, [x9]
  movz x17, #0x8b48
  movk x17, #0x48c4, lsl #16
  movk x17, #0x5889, lsl #32
  movk x17, #0x5520, lsl #48
  cmp x16, x17
  b.ne ios_ec_entry
  ldrh w16, [x9, #8]
  movz w17, #0xe95d
  cmp w16, w17
  b.ne ios_ec_entry
  ldursw x16, [x9, #10]  // jmp rel32 (signed)
  add x17, x9, x16
  add x17, x17, #14      // raw target = FFS base + 14 + rel32
  // ml316b: x9 (and thus the raw target) is usually the POOL-COPY alias -- wine
  // installs pool aliases into the dispatch slots and IATs so native code can
  // call them, and the copy is byte-identical so the pattern still matches.
  // The EC bitmap only covers PE-space VAs (the #52 lesson all over again), so
  // reverse-translate the target through IosAliasEntries BEFORE consulting it.
  // x4/x9 are spilled to free loop registers; restored on every exit path.
  // (Native EC callers keep sp 16-aligned at call boundaries per AAPCS.)
  stp x4, x9, [sp, #-16]!
  // ml1116: last-hit entry first, then the table newest-first.
  adrp x16, IosAliasLast
  ldr x16, [x16, #:lo12:IosAliasLast]
  cbz x16, ios_ffs_xlate_walk
  ldr x4, [x16, #8]      // Entry.JitBase
  sub x4, x17, x4
  ldr x23, [x16, #16]    // Entry.Size
  cmp x4, x23
  b.lo ios_ffs_xlate_hit
ios_ffs_xlate_walk:
  adrp x9, IosAliasCount
  ldr w9, [x9, #:lo12:IosAliasCount]
  adrp x16, IosAliasEntries
  add x16, x16, #:lo12:IosAliasEntries
  add x16, x16, x9, lsl #5   // one past the last entry
ios_ffs_xlate_loop:
  cbz w9, ios_ffs_xlate_done
  sub x16, x16, #32
  sub w9, w9, #1
  ldr x4, [x16, #8]      // Entry.JitBase
  sub x4, x17, x4
  ldr x23, [x16, #16]    // Entry.Size
  cmp x4, x23
  b.lo ios_ffs_xlate_hit_walk
  b ios_ffs_xlate_loop
ios_ffs_xlate_hit_walk:
  adrp x23, IosAliasLast
  str x16, [x23, #:lo12:IosAliasLast]
ios_ffs_xlate_hit:
  ldr x23, [x16]         // Entry.PeBase
  add x17, x23, x4       // target in PE space
ios_ffs_xlate_done:
  IOS_LOAD_TEB x16
  ldr x16, [x16, #0x60]  // TEB->PEB
  ldr x16, [x16, #0x368] // PEB->EcCodeBitMap
  cbz x16, ios_ffs_reject
  lsr x23, x17, #18
  ldr x16, [x16, x23, lsl #3]
  lsr x23, x17, #12
  lsr x16, x16, x23
  tbz x16, #0, ios_ffs_reject
  ldp x4, x9, [sp], #16
  adrp x16, IosFfsBypassLog
  add x16, x16, #:lo12:IosFfsBypassLog
  ldr x23, [x16]
  add x23, x23, #1
  str x23, [x16]         // [0] = bypass count (diagnostic, read by Core.cpp reporter)
  str x17, [x16, #8]     // [1] = last EC target taken natively
  br x17                 // PE VA; the Mach exec-fault redirect maps it to the pool copy
ios_ffs_reject:
  IOS_SET_GATE 0x32               // ml1230: thunk reject (ml1222 guard declined)
  // Pattern matched but the (PE-space) target is not EC per the bitmap: fall
  // through to normal emulation -- correct for genuine x64 jmp targets -- but
  // COUNT it, so a run with zero bypasses is distinguishable from one where the
  // probe never fired at all (ml316's silent miss must not repeat).
  ldp x4, x9, [sp], #16
ios_ffs_reject_count:
  adrp x16, IosFfsBypassLog
  add x16, x16, #:lo12:IosFfsBypassLog
  ldr x23, [x16, #16]
  add x23, x23, #1
  str x23, [x16, #16]    // [2] = matched-but-rejected count
  str x17, [x16, #24]    // [3] = last rejected (PE-space) target
ios_ffs_no_bypass:
  // ml1230: default route tag, but never overwrite an earlier stamp -- the
  // reject path arrives here too and '2' is the more specific answer.
  adrp x16, IosJitGateMsg
  add x16, x16, #:lo12:IosJitGateMsg
  ldrb w17, [x16, #12]
  cbnz w17, 77f
  IOS_SET_GATE 0x33               // no x64 thunk shape matched
77:
  IOS_XP_COUNT 2112, x16, x17   // ml1131: EC->x64 call (callback) emulated
#endif
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr.

enter_jit:
#ifdef FEX_IOS_HOST
  // ml1230: publish the route that got here, before anything else runs.
  //
  // Raw Darwin write(2) through svc #0x80: fd 2 at the unix layer is the
  // madeira-log.txt that ntdll-unix already writes to, so this needs no CRT,
  // no import table and no TEB. x0-x5 are RCX/RDX/R8/R9 and the ARM64EC
  // variadic descriptor, so they are spilled rather than assumed dead; the
  // frame is a multiple of 16 so sp alignment is unchanged.
  stp x0, x1, [sp, #-48]!
  stp x2, x3, [sp, #16]
  stp x4, x5, [sp, #32]
  adrp x1, IosJitGateMsg
  add x1, x1, #:lo12:IosJitGateMsg
  mov x0, #2                      // fd 2
  mov x2, #14                     // "\n[jit-gate] X\n"
  mov w16, #4                     // syscall 4 == write
  svc #0x80
  ldp x4, x5, [sp, #32]
  ldp x2, x3, [sp, #16]
  ldp x0, x1, [sp], #48
  IOS_LOAD_TEB x17
  ldr x17, [x17, #0x1788] // TEB->ChpeV2CpuAreaInfo
#else
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
#endif
  mov w16, #1
  strb w16, [x17, #0x0] // ChpeV2CpuAreaInfo->InSimulation
#ifdef FEX_IOS_HOST
  // ml460 (#75) Dekker handshake vs the pool-tail sweeper: InSimulation=1 is
  // published above; the full barrier orders it before the gate read, so
  // either the sweeper sees us in-simulation (and skips this thread) or we
  // see the gate (and wait out the sweep before touching L1/callret state).
  dmb ish
8:
  adrp x16, IosCodeBufferSweepGate
  add x16, x16, #:lo12:IosCodeBufferSweepGate
  ldar x16, [x16]
  cbz x16, 9f
  yield
  b 8b
9:
#endif
  ldr x16, [x17, #0x40] // ChpeV2CpuAreaInfo->EmulatorData[2] - DispatcherLoopTopEnterEC
  br x16 // DispatcherLoopTopEnterEC(RIP:x9, CPUArea:x17)

  // Invoked by KiUserEmulationDispatcher after e.g. an NtContinue to x86 code
.global BeginSimulation
BeginSimulation:
#ifdef FEX_IOS_HOST
  IOS_LOAD_TEB x17
  ldr x17, [x17, #0x1788] // TEB->ChpeV2CpuAreaInfo
  // ml460 (#75): this funnel re-enters the JIT after NtContinue (syscall
  // resumes, guest SEH returns, suspend resumes) and could otherwise run
  // emitted code with a stale InSimulation=0 — invisible to the sweeper.
  // Publish InSimulation BEFORE SyncThreadContext (the sweeper touches
  // State.callret_sp) and wait out any active sweep.
  mov w16, #1
  strb w16, [x17, #0x0] // ChpeV2CpuAreaInfo->InSimulation
  dmb ish
6:
  adrp x16, IosCodeBufferSweepGate
  add x16, x16, #:lo12:IosCodeBufferSweepGate
  ldar x16, [x16]
  cbz x16, 7f
  yield
  b 6b
7:
#else
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
#endif
  ldr x16, [x17, #0x8] // ChpeV2CpuAreaInfo->EmulatorStackBase
  mov sp, x16
  ldr x0, [x17, #0x18] // ChpeV2CpuAreaInfo->ContextAmd64
#ifdef FEX_IOS_HOST
  // llvm-mingw arm64ec emits extern "C" funcs as plain (unprefixed) symbols.
  bl SyncThreadContext
#else
  bl "#SyncThreadContext"
#endif
#ifdef FEX_IOS_HOST
  IOS_LOAD_TEB x17
  ldr x17, [x17, #0x1788] // TEB->ChpeV2CpuAreaInfo
#else
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
#endif
  ldr x16, [x17, #0x48] // ChpeV2CpuAreaInfo->EmulatorData[3] - DispatcherLoopTopEnterECFillSRA
  mov x11, #0 // Zero ENTRY_FILL_SRA_SINGLE_INST_REG to avoid single step
  br x16 // DispatcherLoopTopEnterECFillSRA(SingleInst:x10, CPUArea:x17)

#ifdef FEX_IOS_HOST
// FEXCore::Core::CpuStateFrame offsets read below; ARM64EC/Module.cpp checks them with static_asserts.
#define IOS_FRAME_SUSPEND_DOORBELL 1512
#define IOS_FRAME_CPU_AREA 4080
#define IOS_FRAME_XP_COUNT 4088
#define IOS_FRAME_ALIAS_HINT 4096

  // ExitFunctionEC for exits from JIT code, where x28 is this thread's CpuStateFrame; installed as
  // Pointers.ExitFunctionEC when AFP is off, so FPCR.NEP and FPCR.AH are never set and there is
  // nothing to clear. The CPU area and the suspend doorbell come from the frame, the x64->EC call
  // is counted per thread and added to IosXpFex 64 at a time (each 64th target goes to the ring),
  // and the alias lookup starts at this thread's last hit. Same contract and clobbers as
  // ExitFunctionEC, whose tail it shares.
.global ExitFunctionECJit
ExitFunctionECJit:
  ldr x16, [x28, #IOS_FRAME_XP_COUNT]
  add x16, x16, #1
  str x16, [x28, #IOS_FRAME_XP_COUNT]
  tst x16, #63
  b.ne 2f
  adrp x16, IosXpFex
  add x16, x16, #:lo12:IosXpFex
  mov x23, sp
  ubfx x23, x23, #16, #4
  add x17, x16, x23, lsl #6
  add x17, x17, #64
  mov x4, #64
  stadd x4, [x17]
  add x17, x16, #3136
  mov x4, #1
  ldadd x4, x23, [x17]
  and x23, x23, #4095
  add x17, x16, #3200
  str x9, [x17, x23, lsl #3]
2:
  ldr x17, [x28, #IOS_FRAME_CPU_AREA]
  strb wzr, [x17, #0x0] // ChpeV2CpuAreaInfo->InSimulation
  ldr w17, [x28, #IOS_FRAME_SUSPEND_DOORBELL] // *ChpeV2CpuAreaInfo->SuspendDoorbell
  cbnz w17, ExitFunctionSuspendPoint
  ldr x16, [x28, #IOS_FRAME_ALIAS_HINT]
  cbz x16, ios_ec_jit_xlate_walk
  ldr x23, [x16]        // Entry.PeBase
  sub x23, x9, x23
  ldr x4, [x16, #16]    // Entry.Size
  cmp x23, x4
  b.lo ios_ec_xlate_hit
ios_ec_jit_xlate_walk:
  adrp x17, IosAliasCount
  ldr w17, [x17, #:lo12:IosAliasCount]
  adrp x16, IosAliasEntries
  add x16, x16, #:lo12:IosAliasEntries
  add x16, x16, x17, lsl #5   // one past the last entry
ios_ec_jit_xlate_loop:
  cbz w17, ios_ec_xlate_done
  sub x16, x16, #32
  sub w17, w17, #1
  ldr x23, [x16]        // Entry.PeBase
  sub x23, x9, x23
  ldr x4, [x16, #16]    // Entry.Size
  cmp x23, x4
  b.hs ios_ec_jit_xlate_loop
  str x16, [x28, #IOS_FRAME_ALIAS_HINT]
  b ios_ec_xlate_hit
#endif

  // Called into by FEXCore
  // Expects the target code address in x9
.global ExitFunctionEC
ExitFunctionEC:
  // Clear any the AFP NEP and AH bits in FPCR as native code won't expect their behaviour.
  // ml1125: only WRITE FPCR when a bit actually has to change. An FPCR write is
  // expensive on Apple cores (the samples pile up on the instruction after it,
  // ph-rdr74/75), and with AFP disabled (FEX_HOSTFEATURES=disableafp) the bits
  // are never set, so every x64->EC call paid for a no-op write. NZCV is free
  // here: the cmp at check_thunk clobbers it on every path anyway.
  mrs x17, fpcr
  tst x17, #6
  b.eq 1f
  and x17, x17, #~6 // NEP + AH
  msr fpcr, x17
#ifdef FEX_IOS_HOST
  IOS_XP_COUNT 1088, x16, x23   // ml1131: FPCR writes actually performed
#endif
1:
#ifdef FEX_IOS_HOST
  // ml1131: count this x64->EC call (x9 = target as the caller addressed it) and
  // append every 64th target of a shard to the ring. x4 (x64 R10, volatile at a
  // call boundary), x16, x17 and x23 are clobbered on every path below anyway.
  adrp x16, IosXpFex
  add x16, x16, #:lo12:IosXpFex
  mov x23, sp
  ubfx x23, x23, #16, #4
  add x17, x16, x23, lsl #6
  add x17, x17, #64
  mov x4, #1
  ldadd x4, x23, [x17]
  tst x23, #63
  b.ne 2f
  add x17, x16, #3136
  ldadd x4, x23, [x17]
  and x23, x23, #4095
  add x17, x16, #3200
  str x9, [x17, x23, lsl #3]
2:
  IOS_LOAD_TEB x17
  ldr x17, [x17, #0x1788] // TEB->ChpeV2CpuAreaInfo
#else
  ldr x17, [x18, #0x1788] // TEB->ChpeV2CpuAreaInfo
#endif
  strb wzr, [x17, #0x0] // ChpeV2CpuAreaInfo->InSimulation
  ldr x17, [x17, #0x20] // ChpeV2CpuAreaInfo->SuspendDoorbell
  ldr w17, [x17]
  cbnz w17, ExitFunctionSuspendPoint

.global ExitFunctionSuspendResumePoint
ExitFunctionSuspendResumePoint:
#ifdef FEX_IOS_HOST
  // iOS: PE images can't execute at their mapped address (no mprotect(RX) on
  // file-backed mmaps); the only runnable copy lives in the dual-mapped JIT
  // pool. Translate the target through the alias table (IosJitAlias.cpp)
  // before branching — otherwise every x64→EC call lands on the PE VA and
  // costs a Mach exec-fault redirect (~33us each, measured ~40K/frame in
  // Thumper's menu = the entire frame budget).
  // x16/x17/x23 are already clobbered on all downstream paths; x4 maps to
  // x64 R10 (volatile at this call/ret boundary) and is clobbered by the
  // entry-thunk path below. NZCV is clobbered by the cmp at check_thunk
  // regardless.
  // ml1116: last-hit entry first, then the table newest-first.
  adrp x16, IosAliasLast
  ldr x16, [x16, #:lo12:IosAliasLast]
  cbz x16, ios_ec_xlate_walk
  ldr x23, [x16]        // Entry.PeBase
  sub x23, x9, x23
  ldr x4, [x16, #16]    // Entry.Size
  cmp x23, x4
  b.lo ios_ec_xlate_hit
ios_ec_xlate_walk:
  adrp x17, IosAliasCount
  ldr w17, [x17, #:lo12:IosAliasCount]
  adrp x16, IosAliasEntries
  add x16, x16, #:lo12:IosAliasEntries
  add x16, x16, x17, lsl #5   // one past the last entry
ios_ec_xlate_loop:
  cbz w17, ios_ec_xlate_done
  sub x16, x16, #32
  sub w17, w17, #1
  ldr x23, [x16]        // Entry.PeBase
  sub x23, x9, x23      // offset into image (unsigned-wraps huge if below base)
  ldr x4, [x16, #16]    // Entry.Size
  cmp x23, x4
  b.lo ios_ec_xlate_hit_walk
  b ios_ec_xlate_loop
ios_ec_xlate_hit_walk:
  adrp x4, IosAliasLast
  str x16, [x4, #:lo12:IosAliasLast]
ios_ec_xlate_hit:
  ldr x4, [x16, #8]     // Entry.JitBase
  add x9, x4, x23
ios_ec_xlate_done:
#endif
  // Either return to an exit thunk (return to ARM64EC function) or call an entry thunk (call to ARM64EC function).
  // It is assumed that a 'blr x16' instruction is only ever used to call into x86 code from an exit thunk, and that all
  // exported ARM64EC functions have a 4-byte offset to their entry thunk immediately before their first instruction.
  mov x17, x9
  mov w16, #0x200
  movk w16, #0xd63f, lsl 16 // blr x16
  ldursw x23, [x17, #-0x4] // Load either the entry thunk offset or the calling instruction.
  cmp w23, w16
  beq ret_sp_aligned

  and x23, x23, #-0x4
  add x17, x17, x23 // Resolve entry thunk address.

  mov x4, sp
  tbz x4, #3, ret_sp_misaligned
  ldr lr, [x4], #0x8 // Pop the return address into lr.
  mov sp, x4

ret_sp_aligned:
  br x17

ret_sp_misaligned:
  // In the case of the x64 caller leaving sp only 8-byte aligned, leave the return address on the stack to keep 16-byte
  // alignment and have the callee return to an x86 ret instruction. FEX can then return to the actual caller keeping
  // the misaligned RSP.
  //
  // ml218: x4 must still point PAST the return address. On the path above the address is
  // popped (`ldr lr, [x4], #0x8`), leaving x4 = RSP+8 -- the base of the x64 home space,
  // which a variadic entry thunk then advances by 0x20 to reach the first stack argument:
  //   $ientry_thunk$cdecl$i8$varargs:  add x4, x4, #0x20
  // Here the address is deliberately LEFT on the stack, so x4 = RSP is one slot short and
  // every stack argument is read 8 bytes early. Measured directly in a Steam RPC call:
  //   [ndr-shift] param3 off=0x18 StackTop=0x703CD5EBF0 HERE=0x10 next=0x703CD5EC88
  //               => SHIFT: real pointer is ONE SLOT LATER (+8)
  // which is how ccontext arrived as 0x10 and faulted in #NdrContextHandleUnmarshall+0xcc.
  // Only variadic callees are affected -- non-variadic entry thunks never read x4 -- which
  // is why this stayed hidden outside RPC. sp is intentionally left untouched.
  add x4, x4, #0x8
  adrp lr, X64ReturnInstr
  ldr lr, [lr, #:lo12:X64ReturnInstr]
  br x17

.global ExitFunctionSuspendPoint
ExitFunctionSuspendPoint:
  brk #0xCAFE
  // Resume will jump back to `ExitFunctionSuspendResumePoint`

  // Makes a wrapper for calling a system call directly, skipping the usual ntdll thunks
#define HASH #
#define DIRECT_SYSCALL_WRAPPER(Name, WineIdName, WindowsId) \
  .global Name; \
  Name:; \
    adrp x16, WineSyscallDispatcher; \
    ldr x16, [x16, HASH:lo12:WineSyscallDispatcher]; \
    cbz x16, 1f; \
    mov x9, x30; \
    adrp x8, WineIdName; \
    ldr x8, [x8, HASH:lo12:WineIdName]; \
    blr x16; \
    ret; \
  1:; \
    svc HASH WindowsId; \
    ret

  // Allows for continuing from a full native context, as the NTDLL NtContinue export takes in an x64 context with EC and
  // the conversion to that loses the ARM64EC ABI-disallowed registers that FEX uses.
#ifdef FEX_IOS_HOST
// llvm-mingw arm64ec emits unprefixed references from C code (`NtContinueNative`)
// but the macro defines `#NtContinueNative` only. Add unprefixed aliases pointing
// to the same code so the link resolves cleanly without linker-synthesized thunks.
.global NtContinueNative
NtContinueNative:
#endif
DIRECT_SYSCALL_WRAPPER("#NtContinueNative", WineNtContinueSyscallId, 0x43)

  // Both of these are wrapped as FEX needs them to setup its call checker at startup time and their NTDLL thunks could
  // already be patched by then (and because the call checker isn't installed, their patched x86 versions would be invoked
  // when called by FEX).
#ifdef FEX_IOS_HOST
.global NtAllocateVirtualMemoryNative
NtAllocateVirtualMemoryNative:
#endif
DIRECT_SYSCALL_WRAPPER("#NtAllocateVirtualMemoryNative", WineNtAllocateVirtualMemorySyscallId, 0x18)
#ifdef FEX_IOS_HOST
.global NtProtectVirtualMemoryNative
NtProtectVirtualMemoryNative:
#endif
DIRECT_SYSCALL_WRAPPER("#NtProtectVirtualMemoryNative", WineNtProtectVirtualMemorySyscallId, 0x50)

  // A replacement for the standard ARM64EC call checker that ignores any FFS patches and always redirects to a function's
  // native implementation. As the only library FEX calls into is NTDLL, this is done using a LUT generated at init time.
  // Expects the FFS address in x11, exit thunk address in x10 (unused) and it's own address in x9. Return address is in x11.
.global "CheckCall"
"CheckCall":
  adrp x9, NtDllBase
  ldr x9, [x9, #:lo12:NtDllBase]
  subs x16, x11, x9
  b.lo end
  adrp x17, NtDllRedirectionLUTSize
  ldr x17, [x17, #:lo12:NtDllRedirectionLUTSize]
  cmp x16, x17
  b.hi end
  adrp x17, NtDllRedirectionLUT
  ldr x17, [x17, #:lo12:NtDllRedirectionLUT]
  ldr w11, [x17, x16, lsl #2]
  add x11, x11, x9
end:
  ret

  // Expects target address in x0, and the SP to set in x1
#ifdef FEX_IOS_HOST
.global JumpSetStack
JumpSetStack:
#endif
.global "#JumpSetStack"
"#JumpSetStack":
  mov sp, x1
  br x0
