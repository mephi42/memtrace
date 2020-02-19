#!/usr/bin/env python3
import argparse
from dataclasses import dataclass, field
import os
from typing import Dict, List

from jinja2 import Template
from sortedcontainers import SortedKeyList

from memtrace import MT_LOAD, MT_STORE, MT_REG, MT_INSN, MT_GET_REG, \
    MT_PUT_REG, MT_INSN_EXEC, MT_GET_REG_NX, MT_PUT_REG_NX, read_entries
from memtrace.disasm import disasm_init, disasm_str, UNKNOWN


@dataclass
class InsnInCode:
    pc: int
    raw: bytes = b''
    disasm: str = UNKNOWN


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
    seq_in_trace: int


def node_key(node: Def) -> int:
    return node.end


def add_def(store: SortedKeyList, def_: Def) -> None:
    defs: List[Def] = [def_]
    first_idx = store.bisect_key_left(def_.start + 1)
    last_idx = first_idx
    for node in store.islice(first_idx):
        if node.start >= def_.end:
            break
        if def_.start <= node.start:
            if def_.end < node.end:
                # Left overlap
                defs.append(Def(def_.end, node.end, node.seq_in_trace))
            else:
                # Outer overlap
                pass
        else:
            if def_.end < node.end:
                # Inner overlap
                defs.append(Def(node.start, def_.start, node.seq_in_trace))
                defs.append(Def(def_.end, node.end, node.seq_in_trace))
            else:
                # Right overlap
                defs.append(Def(node.start, def_.start, node.seq_in_trace))
        last_idx += 1
    del store[first_idx:last_idx]
    store.update(defs)


def append_defs(
        defs: List[Def],
        store: SortedKeyList,
        start: int,
        end: int
) -> None:
    for node in store.irange_key(start + 1):
        if node.start >= end:
            break
        defs.append(Def(
            max(start, node.start),
            min(end, node.end),
            node.seq_in_trace,
        ))


INITIAL_INSN = InsnInTrace(seq=0, in_code=InsnInCode(pc=0))
INITIAL_DEF = Def(0, (1 << 64) - 1, 0)


@dataclass
class UD:
    insns_in_trace: List['InsnInTrace'] = field(
        default_factory=lambda: [INITIAL_INSN])
    pc2insn: Dict[int, 'InsnInCode'] = field(default_factory=dict)
    regs: SortedKeyList = field(
        default_factory=lambda: SortedKeyList((INITIAL_DEF,), key=node_key))
    mem: SortedKeyList = field(
        default_factory=lambda: SortedKeyList((INITIAL_DEF,), key=node_key))


def analyze_insn(ud: UD, disasm, tag, data):
    insn_in_code = ud.pc2insn.get(data.pc)
    if insn_in_code is None:
        insn_in_code = InsnInCode(data.pc)
        ud.pc2insn[data.pc] = insn_in_code
    if data.pc != ud.insns_in_trace[-1].in_code.pc:
        insn_in_trace = InsnInTrace(
            seq=len(ud.insns_in_trace),
            in_code=insn_in_code,
        )
        ud.insns_in_trace.append(insn_in_trace)
    else:
        insn_in_trace = ud.insns_in_trace[-1]
    if tag == MT_LOAD:
        append_defs(insn_in_trace.mem_uses, ud.mem, data.addr, data.end_addr)
    elif tag == MT_STORE:
        def_ = Def(data.addr, data.end_addr, insn_in_trace.seq)
        insn_in_trace.mem_defs.append(def_)
        add_def(ud.mem, def_)
    elif tag == MT_REG:
        pass
    elif tag == MT_INSN:
        insn_in_code.raw = data.value
        insn_in_code.disasm = disasm_str(disasm, data.pc, insn_in_code.raw)
    elif tag in (MT_GET_REG, MT_GET_REG_NX):
        append_defs(insn_in_trace.reg_uses, ud.regs, data.addr, data.end_addr)
    elif tag in (MT_PUT_REG, MT_PUT_REG_NX):
        def_ = Def(data.addr, data.end_addr, insn_in_trace.seq)
        insn_in_trace.reg_defs.append(def_)
        add_def(ud.regs, def_)
    elif tag == MT_INSN_EXEC:
        pass
    else:
        raise Exception(f'Unsupported tag: 0x{tag:x}')


def format_uses(uses):
    return ', '.join([
        f'0x{use.start:x}-0x{use.end:x}@[{use.seq_in_trace}]'
        for use in uses
    ])


def format_defs(defs):
    return ', '.join([
        f'0x{def_.start:x}-0x{def_.end:x}'
        for def_ in defs
    ])


def format_insn_in_trace(insn_in_trace: InsnInTrace) -> str:
    return (
        f'[{insn_in_trace.seq}]0x{insn_in_trace.in_code.pc:x}: '
        f'{insn_in_trace.in_code.raw.hex()} {insn_in_trace.in_code.disasm} '
        f'reg_uses=[{format_uses(insn_in_trace.reg_uses)}] '
        f'reg_defs=[{format_defs(insn_in_trace.reg_defs)}] '
        f'mem_uses=[{format_uses(insn_in_trace.mem_uses)}] '
        f'mem_defs=[{format_defs(insn_in_trace.mem_defs)}]'
    )


def output_template(fp, kind, ud: UD, disasm):
    template_path = os.path.join(
        os.path.dirname(__file__),
        'ud_{}.j2'.format(kind),
    )
    with open(template_path) as template_fp:
        template = Template(template_fp.read())
    template.stream(
        ud=ud,
        disasm=disasm,
        disasm_str=disasm_str,
    ).dump(fp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('--start', default=0, type=int)
    parser.add_argument('--end', type=int)
    parser.add_argument('--dot')
    parser.add_argument('--html')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    endian, word, word_size, e_machine, gen = read_entries(args.memtrace_out)
    disasm = disasm_init(endian, word_size, e_machine)
    ud = UD()
    it = enumerate(gen)
    for _ in range(args.start):
        next(it)
    for i, (tag, data) in it:
        if args.end is not None and i >= args.end:
            break
        prev = ud.insns_in_trace[-1]
        if args.verbose and data.pc != prev.in_code.pc:
            print(format_insn_in_trace(prev))
        analyze_insn(ud, disasm, tag, data)
    if args.dot is not None:
        with open(args.dot, 'w') as fp:
            output_template(fp, 'dot', ud, disasm)
    if args.html is not None:
        with open(args.html, 'w') as fp:
            output_template(fp, 'html', ud, disasm)


if __name__ == '__main__':
    main()
