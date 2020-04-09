import struct

from memtrace_ext import Disasm, Entry, Tag


def format_value(value: bytes, endianness: str) -> str:
    if len(value) == 1:
        return hex(struct.unpack(endianness + 'B', value)[0])
    elif len(value) == 2:
        return hex(struct.unpack(endianness + 'H', value)[0])
    elif len(value) == 4:
        return hex(struct.unpack(endianness + 'I', value)[0])
    elif len(value) == 8:
        return hex(struct.unpack(endianness + 'Q', value)[0])
    else:
        return value.hex()


def format_entry(entry: Entry, endianness: str, disasm: Disasm) -> str:
    # This is the same as C++ implementation. Two reason it exists:
    # * test that all the properties are accessible in Python;
    # * exposing C++ implementation without hurting performance is not trivial.
    s = '[{:10}] '.format(entry.index)
    if entry.tag in (
            Tag.MT_LOAD, Tag.MT_STORE, Tag.MT_REG, Tag.MT_GET_REG,
            Tag.MT_PUT_REG):
        s += '0x{:08x}: {} uint{}_t [0x{:x}] {}'.format(
            entry.insn_seq,
            entry.tag,
            len(entry.value) * 8,
            entry.addr,
            format_value(bytes(entry.value), endianness),
        )
    elif entry.tag == Tag.MT_INSN:
        s += '0x{:08x}: {} 0x{:016x} {} {}'.format(
            entry.insn_seq,
            entry.tag,
            entry.pc,
            bytes(entry.value).hex(),
            disasm.disasm_str(entry.value, entry.pc),
        )
    elif entry.tag == Tag.MT_INSN_EXEC:
        s += '0x{:08x}: {}'.format(entry.insn_seq, entry.tag)
    elif entry.tag in (Tag.MT_GET_REG_NX, Tag.MT_PUT_REG_NX):
        s += '0x{:08x}: {} uint{}_t [0x{:x}]'.format(
            entry.insn_seq,
            entry.tag,
            len(entry.value) * 8,
            entry.addr,
        )
    elif entry.tag == Tag.MT_MMAP:
        s += '{} {:016x}-{:016x} {}{}{} {}'.format(
            entry.tag,
            entry.start,
            entry.end + 1,
            'r' if entry.flags & 1 else '-',
            'w' if entry.flags & 2 else '-',
            'x' if entry.flags & 4 else '-',
            entry.name,
        )
    else:
        s += '???'
    return s
