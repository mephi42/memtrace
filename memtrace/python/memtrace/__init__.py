import struct

EM_386 = 3
EM_X86_64 = 62
EM_PPC = 20
EM_PPC64 = 21
EM_ARM = 40
EM_AARCH64 = 183
EM_S390 = 22
EM_MIPS = 8
EM_NANOMIPS = 249

EM2STR = {
    EM_386: 'EM_386',
    EM_X86_64: 'EM_X86_64',
    EM_PPC: 'EM_PPC',
    EM_PPC64: 'EM_PPC64',
    EM_ARM: 'EM_ARM',
    EM_AARCH64: 'EM_AARCH64',
    EM_S390: 'EM_S390',
    EM_MIPS: 'EM_MIPS',
    EM_NANOMIPS: 'EM_NANOMIPS',
}

MT_LOAD = 1 << 0
MT_STORE = 1 << 1
MT_REGS = 1 << 2
MT_INSN = 1 << 3
MT_GET_REG = 1 << 4
MT_PUT_REG = 1 << 5
MT_INSN_EXEC = 1 << 6
MT_SIZE_SHIFT = 8

MAGIC2STRUCT = {
    b'MT32': '>I',
    b'MT64': '>Q',
    b'23TM': '<I',
    b'46TM': '<Q',
}


def read_entries(memtrace):
    fp = open(memtrace, 'rb')
    try:
        magic = fp.read(4)
        try:
            endian, word = MAGIC2STRUCT[magic]
        except KeyError:
            raise Exception('Unsupported magic: %s'.format(magic))
        e_machine, = struct.unpack(endian + 'H', fp.read(2))
        fp.read(58)
    except:  # noqa: E722
        fp.close()
        raise

    def gen():
        with fp:
            entry_fmt = word * 3
            entry_fmt += '20x' if word == 'I' else '8x'
            entry_fmt += '32s'
            while True:
                buf = fp.read(64 * 1024)
                if len(buf) == 0:
                    break
                entries_fmt = entry_fmt * (len(buf) // 64)
                values = struct.unpack(endian + entries_fmt, buf)
                for i in range(0, len(values), 4):
                    yield values[i:i + 4]

    return endian, word, e_machine, gen()
