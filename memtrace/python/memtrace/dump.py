#!/usr/bin/env python3
import argparse
import struct

from memtrace import EM2STR, MT_LOAD, MT_STORE, MT_REGS, MT_INSN, MT_GET_REG, \
    MT_PUT_REG, MT_SIZE_SHIFT, read_entries
from memtrace.disasm import disasm_init, disasm_str


SIZE2STRUCT = {
    1: 'B',
    2: 'H',
    4: 'I',
    8: 'Q',
}


def format_value(value, endian, size):
    try:
        format = SIZE2STRUCT[size]
    except KeyError:
        return ('b\'' +
                ''.join('\\x{:02x}'.format(b) for b in value[:size]) +
                '\'')
    value, = struct.unpack(endian + format, value[:size])
    return hex(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    args = parser.parse_args()
    endian, word, e_machine, gen = read_entries(args.memtrace_out)
    print('Endian:  {}'.format(endian))
    print('Word:    {}'.format(word))
    print('Machine: {}'.format(EM2STR[e_machine]))
    disasm = disasm_init(endian, word, e_machine)
    for pc, addr, flags, value in gen:
        size = flags >> MT_SIZE_SHIFT
        if flags & MT_LOAD:
            op = 'MT_LOAD'
        elif flags & MT_STORE:
            op = 'MT_STORE'
        elif flags & MT_REGS:
            op = 'MT_REGS'
        elif flags & MT_INSN:
            op = 'MT_INSN'
        elif flags & MT_GET_REG:
            op = 'MT_GET_REG'
        elif flags & MT_PUT_REG:
            op = 'MT_PUT_REG'
        else:
            raise Exception('Unsupported flags')
        if flags & MT_INSN:
            hex_str = value[:size].hex()
            insn_str = disasm_str(disasm, pc, value[:size])
            print('0x{:x}: {} {} {}'.format(pc, op, hex_str, insn_str))
        else:
            print('0x{:x}: {} uint{}_t [0x{:x}] {}'.format(
                pc, op, size * 8, addr, format_value(value, endian, size)))


if __name__ == '__main__':
    main()
