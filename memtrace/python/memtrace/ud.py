#!/usr/bin/env python3
import argparse
from dataclasses import dataclass, field
from typing import Dict, Generator, List

from sortedcontainers import SortedKeyList

from memtrace import MT_LOAD, MT_STORE, MT_REGS, MT_INSN, MT_GET_REG, \
    MT_PUT_REG, MT_INSN_EXEC, read_entries
from memtrace.disasm import disasm_init, disasm_str


@dataclass
class InsnInCode:
    pc: int
    raw: bytes = b''


@dataclass
class InsnInTrace:
    seq: int
    in_code: InsnInCode
    reg_uses: List['Def'] = field(default_factory=list)
    reg_defs: List['Def'] = field(default_factory=list)
    mem_uses: List['Def'] = field(default_factory=list)
    mem_defs: List['Def'] = field(default_factory=list)


@dataclass
class Def:
    start: int
    end: int
    insn_in_trace: InsnInTrace


def node_key(node: Def) -> int:
    return node.end


def add_def(store: SortedKeyList, def_: Def) -> None:
    first_idx = store.bisect_key_left(def_.start + 1)
    last_idx = len(store)
    for idx in range(first_idx, last_idx):
        node = store[idx]
        if node.start >= def_.end:
            last_idx = idx
            break
    affected: List[Def] = store[first_idx:last_idx]
    del store[first_idx:last_idx]
    for node in affected:
        if def_.start <= node.start:
            if def_.end < node.end:
                # Left overlap
                store.add(Def(def_.end, node.end, node.insn_in_trace))
            else:
                # Outer overlap
                pass
        else:
            if def_.end < node.end:
                # Inner overlap
                store.add(Def(node.start, def_.start, node.insn_in_trace))
                store.add(Def(def_.end, node.end, node.insn_in_trace))
            else:
                # Right overlap
                store.add(Def(node.start, def_.start, node.insn_in_trace))
    store.add(def_)


def find_defs(store: SortedKeyList, start: int, end: int) \
        -> Generator[Def, None, None]:
    for idx in range(store.bisect_key_left(start + 1), len(store)):
        node = store[idx]
        if node.start >= end:
            break
        yield Def(
            max(start, node.start),
            min(end, node.end),
            node.insn_in_trace,
        )


INITIAL_INSN = InsnInTrace(seq=0, in_code=InsnInCode(pc=0))
INITIAL_DEF = Def(0, (1 << 64) - 1, INITIAL_INSN)


@dataclass
class UD:
    insns_in_trace: List['InsnInTrace'] = field(
        default_factory=lambda: [INITIAL_INSN])
    pc2insn: Dict[int, 'InsnInCode'] = field(default_factory=dict)
    regs: SortedKeyList = field(
        default_factory=lambda: SortedKeyList((INITIAL_DEF,), key=node_key))
    mem: SortedKeyList = field(
        default_factory=lambda: SortedKeyList((INITIAL_DEF,), key=node_key))


def analyze_insn(ud: UD, pc, addr, flags, data):
    insn_in_code = ud.pc2insn.get(pc)
    if insn_in_code is None:
        insn_in_code = InsnInCode(pc)
        ud.pc2insn[pc] = insn_in_code
    if pc != ud.insns_in_trace[-1].in_code.pc:
        insn_in_trace = InsnInTrace(
            seq=len(ud.insns_in_trace),
            in_code=insn_in_code,
        )
        ud.insns_in_trace.append(insn_in_trace)
    else:
        insn_in_trace = ud.insns_in_trace[-1]
    end = addr + (flags >> 8)
    if flags & MT_LOAD:
        insn_in_trace.mem_uses.extend(find_defs(ud.mem, addr, end))
    elif flags & MT_STORE:
        def_ = Def(addr, end, insn_in_trace)
        insn_in_trace.mem_defs.append(def_)
        add_def(ud.mem, def_)
    elif flags & MT_REGS:
        pass
    elif flags & MT_INSN:
        insn_in_code.raw = data[:flags >> 8]
    elif flags & MT_GET_REG:
        insn_in_trace.reg_uses.extend(find_defs(ud.regs, addr, end))
    elif flags & MT_PUT_REG:
        def_ = Def(addr, end, insn_in_trace)
        insn_in_trace.reg_defs.append(def_)
        add_def(ud.regs, def_)
    elif flags & MT_INSN_EXEC:
        pass
    else:
        raise Exception('Unsupported flags')


def format_uses(uses):
    return ', '.join(
        '0x{:x}-0x{:x}@[{}]0x{:x}'.format(
            use.start,
            use.end,
            use.insn_in_trace.seq,
            use.insn_in_trace.in_code.pc,
        )
        for use in uses
    )


def format_defs(defs):
    return ', '.join(
        '0x{:x}-0x{:x}'.format(def_.start, def_.end)
        for def_ in defs
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('--start', type=int)
    parser.add_argument('--end', type=int)
    args = parser.parse_args()
    endian, word, e_machine, gen = read_entries(args.memtrace_out)
    disasm = disasm_init(endian, word, e_machine)
    ud = UD()
    for i, (pc, addr, flags, data) in enumerate(gen):
        if args.start is not None and i < args.start:
            continue
        if args.end is not None and i >= args.end:
            break
        prev = ud.insns_in_trace[-1]
        if pc != prev.in_code.pc:
            print('[{}]0x{:x}: {} {} reg_uses=[{}] reg_defs=[{}] mem_uses=[{}] mem_defs=[{}]'.format(  # noqa: E501
                prev.seq,
                prev.in_code.pc,
                prev.in_code.raw.hex(),
                disasm_str(disasm, pc, prev.in_code.raw),
                format_uses(prev.reg_uses),
                format_defs(prev.reg_defs),
                format_uses(prev.mem_uses),
                format_defs(prev.mem_defs),
            ))
        analyze_insn(ud, pc, addr, flags, data)


if __name__ == '__main__':
    main()
