import struct

from memtrace_ext import Disasm, Entry, get_tag_str, InsnEntry, \
    InsnExecEntry, LdStEntry, LdStNxEntry, MmapEntry


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
    if isinstance(entry, LdStEntry):
        s += '0x{:016x}: {} uint{}_t [0x{:x}] {}'.format(
            entry.pc,
            get_tag_str(entry.tag),
            len(entry.value) * 8,
            entry.addr,
            format_value(bytes(entry.value), endianness),
        )
    elif isinstance(entry, InsnEntry):
        s += '0x{:016x}: {} {} {}'.format(
            entry.pc,
            get_tag_str(entry.tag),
            bytes(entry.value).hex(),
            disasm.disasm_str(entry.value, entry.pc),
        )
    elif isinstance(entry, InsnExecEntry):
        s += '0x{:016x}: {}'.format(entry.pc, get_tag_str(entry.tag))
    elif isinstance(entry, LdStNxEntry):
        s += '0x{:016x}: {} uint{}_t [0x{:x}]'.format(
            entry.pc,
            get_tag_str(entry.tag),
            len(entry.value) * 8,
            entry.addr,
        )
    elif isinstance(entry, MmapEntry):
        s += '{} {:016x}-{:016x} {}{}{} {}'.format(
            get_tag_str(entry.tag),
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
