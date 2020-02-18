from dataclasses import dataclass
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

MT_LOAD = 0x4c4c
MT_STORE = 0x5353
MT_REG = 0x5252
MT_INSN = 0x4949
MT_GET_REG = 0x4747
MT_PUT_REG = 0x5050
MT_INSN_EXEC = 0x5858
MT_GET_REG_NX = 0x6767
MT_PUT_REG_NX = 0x7070

TAG2STR = {
    MT_LOAD: 'MT_LOAD',
    MT_STORE: 'MT_STORE',
    MT_REG: 'MT_REG',
    MT_INSN: 'MT_INSN',
    MT_GET_REG: 'MT_GET_REG',
    MT_PUT_REG: 'MT_PUT_REG',
    MT_INSN_EXEC: 'MT_INSN_EXEC',
    MT_GET_REG_NX: 'MT_GET_REG_NX',
    MT_PUT_REG_NX: 'MT_PUT_REG_NX',
}


@dataclass
class LdStEntry:
    pc: int
    addr: int
    value: bytes

    @property
    def end_addr(self):
        return self.addr + len(self.value)


@dataclass
class InsnEntry:
    pc: int
    value: bytes


@dataclass
class InsnExecEntry:
    pc: int


@dataclass
class LdStNxEntry:
    pc: int
    addr: int
    size: int

    @property
    def end_addr(self):
        return self.addr + self.size


TAG2TYPE = {
    MT_LOAD: LdStEntry,
    MT_STORE: LdStEntry,
    MT_REG: LdStEntry,
    MT_INSN: InsnEntry,
    MT_GET_REG: LdStEntry,
    MT_PUT_REG: LdStEntry,
    MT_INSN_EXEC: InsnExecEntry,
    MT_GET_REG_NX: LdStNxEntry,
    MT_PUT_REG_NX: LdStNxEntry,
}
MT_LDST = set(tag for tag, type in TAG2TYPE.items() if type == LdStEntry)

BUF_SIZE = 8 * 1024

MAGIC2STRUCT = {
    b'M4': '>I',
    b'M8': '>Q',
    b'4M': '<I',
    b'8M': '<Q',
}
STRUCT2SIZE = {
    'I': 4,
    'Q': 8,
}


def read_entries(memtrace):
    fp = open(memtrace, 'rb')
    try:
        entry = fp.read(4)
        tag, length = entry[:2], entry[2:]
        try:
            endian: str
            word: str
            endian, word = MAGIC2STRUCT[tag]
            word_size = STRUCT2SIZE[word]
        except KeyError:
            raise Exception('Unsupported magic: {}'.format(tag))
        length, = struct.unpack(endian + 'H', length)
        length = (length + (word_size - 1)) & ~(word_size - 1)
        entry += fp.read(length - 4)
        e_machine, = struct.unpack(
            endian + 'H', entry[word_size:word_size + 2])
        word_mask = word_size - 1
    except:  # noqa: E722
        fp.close()
        raise

    def gen():
        buf = memoryview(bytearray(BUF_SIZE))
        low = 0
        high = 0
        with fp:
            while True:
                buf[:high - low] = buf[low:high]
                n_read = fp.readinto(buf[high - low:])
                high = high - low + n_read
                low = 0
                if high == low:
                    break
                tags = []
                fmt = [endian]
                pad = 0
                while True:
                    if low + 4 > high:
                        break
                    tag, length = struct.unpack(
                        endian + 'HH', buf[low:low + 4])
                    padded_length = (length + word_mask) & ~word_mask
                    next_low = low + padded_length
                    if next_low > high:
                        break
                    pad += word_size
                    fmt.append('{}x'.format(pad))
                    pad = padded_length - length
                    tags.append(tag)
                    if tag in MT_LDST:
                        fmt.append('{}{}{}s'.format(
                            word, word, length - word_size * 3))
                    elif tag == MT_INSN:
                        fmt.append('{}{}s'.format(
                            word, length - word_size * 2))
                    elif tag == MT_INSN_EXEC:
                        fmt.append(word)
                    elif tag in (MT_GET_REG_NX, MT_PUT_REG_NX):
                        fmt.append('{}{}{}'.format(word, word, word))
                    else:
                        raise Exception('Unsupported tag: 0x{:x}'.format(tag))
                    low = next_low
                fmt.append('{}x'.format(pad))
                values = struct.unpack(''.join(fmt), buf[:low])
                j = 0
                for tag in tags:
                    tag_type = TAG2TYPE[tag]
                    nargs = len(tag_type.__dataclass_fields__)
                    yield tag, tag_type(*values[j:j + nargs])
                    j += nargs

    return endian, word, word_size, e_machine, gen()
