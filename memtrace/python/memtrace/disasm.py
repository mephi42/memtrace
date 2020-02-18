try:
    import capstone
except ImportError:
    capstone = None

from memtrace import EM_386, EM_X86_64, EM_PPC64, EM_ARM, EM_AARCH64, \
    EM_S390, EM_MIPS


def disasm_init(endian, word_size, e_machine):
    if capstone is None:
        return None
    # See cstool.c for valid combinations
    if e_machine == EM_386:
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_32
    elif e_machine == EM_X86_64:
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64
    # EM_PPC is not supported
    elif e_machine == EM_PPC64:
        arch = capstone.CS_ARCH_PPC
        mode = capstone.CS_MODE_64
        if endian == '<':
            mode |= capstone.CS_MODE_LITTLE_ENDIAN
        else:
            mode |= capstone.CS_MODE_BIG_ENDIAN_ENDIAN
    elif e_machine == EM_ARM:
        arch = capstone.CS_ARCH_ARM
        mode = capstone.CS_MODE_ARM
        if endian == '<':
            mode |= capstone.CS_MODE_LITTLE_ENDIAN
        else:
            mode |= capstone.CS_MODE_BIG_ENDIAN_ENDIAN
    elif e_machine == EM_AARCH64:
        arch = capstone.CS_ARCH_ARM64
        if endian == '<':
            mode = capstone.CS_MODE_LITTLE_ENDIAN
        else:
            mode = capstone.CS_MODE_BIG_ENDIAN_ENDIAN
    elif e_machine == EM_S390:
        arch = capstone.CS_ARCH_SYSZ
        mode = capstone.CS_MODE_BIG_ENDIAN
    elif e_machine == EM_MIPS:
        arch = capstone.CS_ARCH_MIPS
        if word_size == 4:
            mode = capstone.CS_MODE_MIPS32
        else:
            mode = capstone.CS_MODE_MIPS64
        if endian == '<':
            mode |= capstone.CS_MODE_LITTLE_ENDIAN
        else:
            mode |= capstone.CS_MODE_BIG_ENDIAN_ENDIAN
    # EM_NANOMIPS is not supported
    else:
        return None
    return capstone.Cs(arch, mode)


def disasm_cs(disasm, pc, buf):
    if capstone is None or not isinstance(disasm, capstone.Cs):
        return None
    try:
        return next(disasm.disasm(buf, pc))
    except StopIteration:
        return None


UNKNOWN = '<unknown>'


def disasm_str(disasm, pc, buf):
    cs_insn = disasm_cs(disasm, pc, buf)
    if cs_insn is None:
        return UNKNOWN
    else:
        return '{} {}'.format(cs_insn.mnemonic, cs_insn.op_str)
