#ifndef __MT_REGS_H
#define __MT_REGS_H

#include "pub_tool_basics.h"
#include "pub_tool_guest.h"

struct Reg {
   UShort offset;
   UShort size;
   const HChar* name;
};

#define DEFINE_REG(name)                               \
   {                                                   \
      offsetof(VexGuestArchState, name),               \
          sizeof(((VexGuestArchState*)0)->name), #name \
   }

#define DEFINE_SUBREG(name, offset, type, alias)                      \
   {                                                                  \
      offsetof(VexGuestArchState, name) + offset, sizeof(type), alias \
   }

static const struct Reg regs[] = {
#if defined(VGA_x86)
    DEFINE_REG(host_EvC_FAILADDR),
    DEFINE_REG(host_EvC_COUNTER),
    DEFINE_SUBREG(guest_EAX, 0, UInt, "eax"),
    DEFINE_SUBREG(guest_EAX, 0, UShort, "ax"),
    DEFINE_SUBREG(guest_EAX, 0, UChar, "al"),
    DEFINE_SUBREG(guest_EAX, 1, UChar, "ah"),
    DEFINE_SUBREG(guest_ECX, 0, UInt, "ecx"),
    DEFINE_SUBREG(guest_ECX, 0, UShort, "cx"),
    DEFINE_SUBREG(guest_ECX, 0, UChar, "cl"),
    DEFINE_SUBREG(guest_ECX, 1, UChar, "ch"),
    DEFINE_SUBREG(guest_EDX, 0, UInt, "edx"),
    DEFINE_SUBREG(guest_EDX, 0, UShort, "dx"),
    DEFINE_SUBREG(guest_EDX, 0, UChar, "dl"),
    DEFINE_SUBREG(guest_EDX, 1, UChar, "dh"),
    DEFINE_SUBREG(guest_EBX, 0, UInt, "ebx"),
    DEFINE_SUBREG(guest_EBX, 0, UShort, "bx"),
    DEFINE_SUBREG(guest_EBX, 0, UChar, "bl"),
    DEFINE_SUBREG(guest_EBX, 1, UChar, "bh"),
    DEFINE_SUBREG(guest_ESP, 0, UInt, "esp"),
    DEFINE_SUBREG(guest_ESP, 0, UShort, "sp"),
    DEFINE_SUBREG(guest_EBP, 0, UInt, "ebp"),
    DEFINE_SUBREG(guest_EBP, 0, UShort, "bp"),
    DEFINE_SUBREG(guest_ESI, 0, UInt, "esi"),
    DEFINE_SUBREG(guest_ESI, 0, UShort, "si"),
    DEFINE_SUBREG(guest_EDI, 0, UInt, "edi"),
    DEFINE_SUBREG(guest_EDI, 0, UShort, "di"),
    DEFINE_REG(guest_CC_OP),
    DEFINE_REG(guest_CC_DEP1),
    DEFINE_REG(guest_CC_DEP2),
    DEFINE_REG(guest_CC_NDEP),
    DEFINE_REG(guest_DFLAG),
    DEFINE_REG(guest_IDFLAG),
    DEFINE_REG(guest_ACFLAG),
    DEFINE_SUBREG(guest_EIP, 0, UInt, "eip"),
    DEFINE_SUBREG(guest_EIP, 0, UShort, "ip"),
    DEFINE_REG(guest_FPREG),
    DEFINE_REG(guest_FPTAG),
    DEFINE_REG(guest_FPROUND),
    DEFINE_REG(guest_FC3210),
    DEFINE_REG(guest_FTOP),
    DEFINE_REG(guest_SSEROUND),
    DEFINE_REG(guest_XMM0),
    DEFINE_REG(guest_XMM1),
    DEFINE_REG(guest_XMM2),
    DEFINE_REG(guest_XMM3),
    DEFINE_REG(guest_XMM4),
    DEFINE_REG(guest_XMM5),
    DEFINE_REG(guest_XMM6),
    DEFINE_REG(guest_XMM7),
    DEFINE_REG(guest_CS),
    DEFINE_REG(guest_DS),
    DEFINE_REG(guest_ES),
    DEFINE_REG(guest_FS),
    DEFINE_REG(guest_GS),
    DEFINE_REG(guest_SS),
    DEFINE_REG(guest_LDT),
    DEFINE_REG(guest_GDT),
    DEFINE_REG(guest_EMNOTE),
    DEFINE_REG(guest_CMSTART),
    DEFINE_REG(guest_CMLEN),
    DEFINE_REG(guest_NRADDR),
    DEFINE_REG(guest_SC_CLASS),
    DEFINE_REG(guest_IP_AT_SYSCALL),
    DEFINE_REG(padding1),
    DEFINE_REG(padding2),
    DEFINE_REG(padding3),
#endif
#if defined(VGA_amd64)
    DEFINE_REG(host_EvC_FAILADDR),
    DEFINE_REG(host_EvC_COUNTER),
    DEFINE_REG(pad0),
    DEFINE_SUBREG(guest_RAX, 0, ULong, "rax"),
    DEFINE_SUBREG(guest_RAX, 0, UInt, "eax"),
    DEFINE_SUBREG(guest_RAX, 0, UShort, "ax"),
    DEFINE_SUBREG(guest_RAX, 0, UChar, "al"),
    DEFINE_SUBREG(guest_RAX, 1, UChar, "ah"),
    DEFINE_SUBREG(guest_RCX, 0, ULong, "rcx"),
    DEFINE_SUBREG(guest_RCX, 0, UInt, "ecx"),
    DEFINE_SUBREG(guest_RCX, 0, UShort, "cx"),
    DEFINE_SUBREG(guest_RCX, 0, UChar, "cl"),
    DEFINE_SUBREG(guest_RCX, 1, UChar, "ch"),
    DEFINE_SUBREG(guest_RDX, 0, ULong, "rdx"),
    DEFINE_SUBREG(guest_RDX, 0, UInt, "edx"),
    DEFINE_SUBREG(guest_RDX, 0, UShort, "dx"),
    DEFINE_SUBREG(guest_RDX, 0, UChar, "dl"),
    DEFINE_SUBREG(guest_RDX, 1, UChar, "dh"),
    DEFINE_SUBREG(guest_RBX, 0, ULong, "rbx"),
    DEFINE_SUBREG(guest_RBX, 0, UInt, "ebx"),
    DEFINE_SUBREG(guest_RBX, 0, UShort, "bx"),
    DEFINE_SUBREG(guest_RBX, 0, UChar, "bl"),
    DEFINE_SUBREG(guest_RBX, 1, UChar, "bh"),
    DEFINE_SUBREG(guest_RSP, 0, ULong, "rsp"),
    DEFINE_SUBREG(guest_RSP, 0, UInt, "esp"),
    DEFINE_SUBREG(guest_RSP, 0, UShort, "sp"),
    DEFINE_SUBREG(guest_RSP, 0, UChar, "spl"),
    DEFINE_SUBREG(guest_RBP, 0, ULong, "rbp"),
    DEFINE_SUBREG(guest_RBP, 0, UInt, "ebp"),
    DEFINE_SUBREG(guest_RBP, 0, UShort, "bp"),
    DEFINE_SUBREG(guest_RBP, 0, UChar, "bpl"),
    DEFINE_SUBREG(guest_RSI, 0, ULong, "rsi"),
    DEFINE_SUBREG(guest_RSI, 0, UInt, "esi"),
    DEFINE_SUBREG(guest_RSI, 0, UShort, "si"),
    DEFINE_SUBREG(guest_RSI, 0, UChar, "sil"),
    DEFINE_SUBREG(guest_RDI, 0, ULong, "rdi"),
    DEFINE_SUBREG(guest_RDI, 0, UInt, "edi"),
    DEFINE_SUBREG(guest_RDI, 0, UShort, "di"),
    DEFINE_SUBREG(guest_RDI, 0, UChar, "dil"),
    DEFINE_SUBREG(guest_R8, 0, ULong, "r8"),
    DEFINE_SUBREG(guest_R8, 0, UInt, "r8d"),
    DEFINE_SUBREG(guest_R8, 0, UShort, "r8w"),
    DEFINE_SUBREG(guest_R8, 0, UChar, "r8b"),
    DEFINE_SUBREG(guest_R9, 0, ULong, "r9"),
    DEFINE_SUBREG(guest_R9, 0, UInt, "r9d"),
    DEFINE_SUBREG(guest_R9, 0, UShort, "r9w"),
    DEFINE_SUBREG(guest_R9, 0, UChar, "r9b"),
    DEFINE_SUBREG(guest_R10, 0, ULong, "r10"),
    DEFINE_SUBREG(guest_R10, 0, UInt, "r10d"),
    DEFINE_SUBREG(guest_R10, 0, UShort, "r10w"),
    DEFINE_SUBREG(guest_R10, 0, UChar, "r10b"),
    DEFINE_SUBREG(guest_R11, 0, ULong, "r11"),
    DEFINE_SUBREG(guest_R11, 0, UInt, "r11d"),
    DEFINE_SUBREG(guest_R11, 0, UShort, "r11w"),
    DEFINE_SUBREG(guest_R11, 0, UChar, "r11b"),
    DEFINE_SUBREG(guest_R12, 0, ULong, "r12"),
    DEFINE_SUBREG(guest_R12, 0, UInt, "r12d"),
    DEFINE_SUBREG(guest_R12, 0, UShort, "r12w"),
    DEFINE_SUBREG(guest_R12, 0, UChar, "r12b"),
    DEFINE_SUBREG(guest_R13, 0, ULong, "r13"),
    DEFINE_SUBREG(guest_R13, 0, UInt, "r13d"),
    DEFINE_SUBREG(guest_R13, 0, UShort, "r13w"),
    DEFINE_SUBREG(guest_R13, 0, UChar, "r13b"),
    DEFINE_SUBREG(guest_R14, 0, ULong, "r14"),
    DEFINE_SUBREG(guest_R14, 0, UInt, "r14d"),
    DEFINE_SUBREG(guest_R14, 0, UShort, "r14w"),
    DEFINE_SUBREG(guest_R14, 0, UChar, "r14b"),
    DEFINE_SUBREG(guest_R15, 0, ULong, "r15"),
    DEFINE_SUBREG(guest_R15, 0, UInt, "r15d"),
    DEFINE_SUBREG(guest_R15, 0, UShort, "r15w"),
    DEFINE_SUBREG(guest_R15, 0, UChar, "r15b"),
    DEFINE_REG(guest_CC_OP),
    DEFINE_REG(guest_CC_DEP1),
    DEFINE_REG(guest_CC_DEP2),
    DEFINE_REG(guest_CC_NDEP),
    DEFINE_REG(guest_DFLAG),
    DEFINE_SUBREG(guest_RIP, 0, ULong, "rip"),
    DEFINE_SUBREG(guest_RIP, 0, UInt, "eip"),
    DEFINE_SUBREG(guest_RIP, 0, UShort, "ip"),
    DEFINE_REG(guest_ACFLAG),
    DEFINE_REG(guest_IDFLAG),
    DEFINE_REG(guest_FS_CONST),
    DEFINE_REG(guest_SSEROUND),
    DEFINE_REG(guest_YMM0),
    DEFINE_REG(guest_YMM1),
    DEFINE_REG(guest_YMM2),
    DEFINE_REG(guest_YMM3),
    DEFINE_REG(guest_YMM4),
    DEFINE_REG(guest_YMM5),
    DEFINE_REG(guest_YMM6),
    DEFINE_REG(guest_YMM7),
    DEFINE_REG(guest_YMM8),
    DEFINE_REG(guest_YMM9),
    DEFINE_REG(guest_YMM10),
    DEFINE_REG(guest_YMM11),
    DEFINE_REG(guest_YMM12),
    DEFINE_REG(guest_YMM13),
    DEFINE_REG(guest_YMM14),
    DEFINE_REG(guest_YMM15),
    DEFINE_REG(guest_YMM16),
    DEFINE_REG(guest_FTOP),
    DEFINE_REG(pad1),
    DEFINE_REG(guest_FPREG),
    DEFINE_REG(guest_FPTAG),
    DEFINE_REG(guest_FPROUND),
    DEFINE_REG(guest_FC3210),
    DEFINE_REG(guest_EMNOTE),
    DEFINE_REG(pad2),
    DEFINE_REG(guest_CMSTART),
    DEFINE_REG(guest_CMLEN),
    DEFINE_REG(guest_NRADDR),
    DEFINE_REG(guest_SC_CLASS),
    DEFINE_REG(guest_GS_CONST),
    DEFINE_REG(guest_IP_AT_SYSCALL),
    DEFINE_REG(pad3),
#endif
#if defined(VGA_s390x)
    DEFINE_REG(guest_a0),
    DEFINE_REG(guest_a1),
    DEFINE_REG(guest_a2),
    DEFINE_REG(guest_a3),
    DEFINE_REG(guest_a4),
    DEFINE_REG(guest_a5),
    DEFINE_REG(guest_a6),
    DEFINE_REG(guest_a7),
    DEFINE_REG(guest_a8),
    DEFINE_REG(guest_a9),
    DEFINE_REG(guest_a10),
    DEFINE_REG(guest_a11),
    DEFINE_REG(guest_a12),
    DEFINE_REG(guest_a13),
    DEFINE_REG(guest_a14),
    DEFINE_REG(guest_a15),
    DEFINE_REG(guest_v0),
    DEFINE_REG(guest_v1),
    DEFINE_REG(guest_v2),
    DEFINE_REG(guest_v3),
    DEFINE_REG(guest_v4),
    DEFINE_REG(guest_v5),
    DEFINE_REG(guest_v6),
    DEFINE_REG(guest_v7),
    DEFINE_REG(guest_v8),
    DEFINE_REG(guest_v9),
    DEFINE_REG(guest_v10),
    DEFINE_REG(guest_v11),
    DEFINE_REG(guest_v12),
    DEFINE_REG(guest_v13),
    DEFINE_REG(guest_v14),
    DEFINE_REG(guest_v15),
    DEFINE_REG(guest_v16),
    DEFINE_REG(guest_v17),
    DEFINE_REG(guest_v18),
    DEFINE_REG(guest_v19),
    DEFINE_REG(guest_v20),
    DEFINE_REG(guest_v21),
    DEFINE_REG(guest_v22),
    DEFINE_REG(guest_v23),
    DEFINE_REG(guest_v24),
    DEFINE_REG(guest_v25),
    DEFINE_REG(guest_v26),
    DEFINE_REG(guest_v27),
    DEFINE_REG(guest_v28),
    DEFINE_REG(guest_v29),
    DEFINE_REG(guest_v30),
    DEFINE_REG(guest_v31),
    DEFINE_REG(guest_r0),
    DEFINE_REG(guest_r1),
    DEFINE_REG(guest_r2),
    DEFINE_REG(guest_r3),
    DEFINE_REG(guest_r4),
    DEFINE_REG(guest_r5),
    DEFINE_REG(guest_r6),
    DEFINE_REG(guest_r7),
    DEFINE_REG(guest_r8),
    DEFINE_REG(guest_r9),
    DEFINE_REG(guest_r10),
    DEFINE_REG(guest_r11),
    DEFINE_REG(guest_r12),
    DEFINE_REG(guest_r13),
    DEFINE_REG(guest_r14),
    DEFINE_REG(guest_r15),
    DEFINE_REG(guest_counter),
    DEFINE_REG(guest_fpc),
    DEFINE_REG(unused),
    DEFINE_REG(guest_IA),
    DEFINE_REG(guest_SYSNO),
    DEFINE_REG(guest_CC_OP),
    DEFINE_REG(guest_CC_DEP1),
    DEFINE_REG(guest_CC_DEP2),
    DEFINE_REG(guest_CC_NDEP),
    DEFINE_REG(guest_NRADDR),
    DEFINE_REG(guest_CMSTART),
    DEFINE_REG(guest_CMLEN),
    DEFINE_REG(guest_IP_AT_SYSCALL),
    DEFINE_REG(guest_EMNOTE),
    DEFINE_REG(host_EvC_COUNTER),
    DEFINE_REG(host_EvC_FAILADDR),
    DEFINE_REG(padding),
#endif
};

#endif
