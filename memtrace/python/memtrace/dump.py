#!/usr/bin/env python3
import argparse
import struct

from memtrace import EM2STR, MT_INSN, MT_INSN_EXEC, MT_GET_REG_NX, \
    MT_PUT_REG_NX, MT_LDST, TAG2STR, read_entries
from memtrace.disasm import disasm_init, disasm_str

SIZE2STRUCT = {
    1: 'B',
    2: 'H',
    4: 'I',
    8: 'Q',
}


def format_value(value, endian):
    format = SIZE2STRUCT.get(len(value))
    if format is None:
        return ('b\'' +
                ''.join([f'\\x{b:02x}' for b in value]) +
                '\'')
    value, = struct.unpack(endian + format, value)
    return hex(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('--start', type=int)
    parser.add_argument('--end', type=int)
    args = parser.parse_args()
    endian, word, word_size, e_machine, gen = read_entries(args.memtrace_out)
    print('Endian            : {}'.format(endian))
    print('Word              : {}'.format(word))
    print('Word size         : {}'.format(word_size))
    print('Machine           : {}'.format(EM2STR[e_machine]))
    disasm = disasm_init(endian, word_size, e_machine)
    insn_exec_count = 0
    for i, (tag, data) in enumerate(gen):
        if args.start is not None and i < args.start:
            continue
        if args.end is not None and i >= args.end:
            break
        op = TAG2STR[tag]
        if tag in MT_LDST:
            value_str = format_value(data.value, endian)
            print(f'[{i:10d}] 0x{data.pc:016x}: {op} '
                  f'uint{len(data.value) * 8}_t [0x{data.addr:x}] {value_str}')
        elif tag == MT_INSN:
            hex_str = data.value.hex()
            insn_str = disasm_str(disasm, data.pc, data.value)
            print(f'[{i:10d}] 0x{data.pc:016x}: {op} {hex_str} {insn_str}')
        elif tag == MT_INSN_EXEC:
            print(f'[{i:10d}] 0x{data.pc:016x}: {op}')
            insn_exec_count += 1
        elif tag in (MT_GET_REG_NX, MT_PUT_REG_NX):
            print(f'[{i:10d}] 0x{data.pc:016x}: {op} '
                  f'uint{data.size * 8}_t [0x{data.addr:x}]')
        else:
            raise Exception('Unsupported tag: 0x{:x}'.format(tag))
    if insn_exec_count > 0:
        print('Insns             : {}'.format(insn_exec_count))


if __name__ == '__main__':
    main()
