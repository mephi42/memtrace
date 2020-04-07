#!/usr/bin/env python3
import argparse
from collections import deque
from dataclasses import dataclass, field
import os
from typing import Deque, Dict, List, Tuple
import sys
import tempfile

from memtrace.format import format_entry
from memtrace_ext import Disasm, Entry, get_endianness_str, InsnExecEntry, \
    LdStEntry, LdStNxEntry, Tag, Trace, Ud, ud_file


@dataclass
class BackwardNode:
    trace_index: int
    edges: Dict[int, 'BackwardEdge'] = field(default_factory=dict)
    done: bool = False

    def get_edge(self, dst: 'BackwardNode') -> 'BackwardEdge':
        edge = self.edges.get(dst.trace_index)
        if edge is None:
            edge = BackwardEdge(dst)
            self.edges[dst.trace_index] = edge
        return edge

    def pp(
            self,
            backward: 'Backward',
            fp=sys.stdout,
            indent='',
            seen=None,
    ) -> None:
        if seen is None:
            seen = set()
        code_index = backward.ud.get_code_for_trace(self.trace_index)
        pc = backward.ud.get_pc_for_code(code_index)
        disasm_str = backward.ud.get_disasm_for_code(code_index)
        if self.trace_index in seen:
            fp.write(
                f'{indent}(InsnInTrace:{self.trace_index}) '
                f'0x{pc:016x} {disasm_str}\n'
            )
            return
        seen.add(self.trace_index)
        fp.write(
            f'{indent}[InsnInTrace:{self.trace_index}] '
            f'0x{pc:016x} {disasm_str}\n'
        )
        for edge in self.edges.values():
            for entry in edge.reg:
                entry_str = format_entry(
                    entry, backward.endianness_str, backward.disasm)
                fp.write(f'{indent}    {entry_str}\n')
            for entry in edge.mem:
                entry_str = format_entry(
                    entry, backward.endianness_str, backward.disasm)
                fp.write(f'{indent}    {entry_str}\n')
            edge.dst.pp(backward, fp, indent + '    ', seen)


@dataclass
class BackwardEdge:
    dst: BackwardNode
    reg: List[Entry] = field(default_factory=list)
    mem: List[Entry] = field(default_factory=list)


class Backward:
    @staticmethod
    def from_trace_file(path) -> 'Backward':
        trace = Trace.load(path)
        with tempfile.TemporaryDirectory() as tmpdir:
            ud_path = os.path.join(tmpdir, '{}.bin')
            err = ud_file(
                path,
                0,  # start
                999999999,  # end
                None,  # dot
                None,  # html
                None,  # csv
                ud_path,  # binary
                None,  # verbose
            )
            if err < 0:
                raise Exception(f'use-def analysis failed: {err}')
            ud = Ud.load(ud_path)
        return Backward(trace, ud)

    def __init__(self, trace: Trace, ud: Ud):
        self.trace = trace
        self.ud = ud
        endianness = self.trace.get_endianness()
        self.endianness_str = get_endianness_str(endianness)
        self.disasm = Disasm(
            self.trace.get_machine_type(),
            endianness,
            self.trace.get_word_size(),
        )

    def analyze(self, pc) -> BackwardNode:
        trace_index0 = max(
            trace_index
            for code_index in self.ud.get_codes_for_pc(pc)
            for trace_index in self.ud.get_traces_for_code(code_index)
        )
        return BackwardAnalysis(self, trace_index0).analyze()

    def main(self, pc) -> None:
        self.analyze(pc).pp(self)


class BackwardAnalysis:
    def __init__(self, backward: Backward, trace_index0):
        self.trace: Trace = backward.trace
        self.ud: Ud = backward.ud
        self.node0: BackwardNode = BackwardNode(trace_index0)
        self.nodes: Dict[int, BackwardNode] = {trace_index0: self.node0}
        self.worklist: Deque[BackwardNode] = deque((self.node0,))

    def analyze(self) -> BackwardNode:
        while len(self.worklist) > 0:
            self.step(self.worklist.popleft())
        return self.node0

    def step(self, node: BackwardNode) -> None:
        if node.done:
            return
        reg_use_entries, mem_use_entries = self.get_use_entries(
            node.trace_index)
        for use, entry in zip(
                self.ud.get_reg_uses_for_trace(node.trace_index),
                reg_use_entries):
            def_node = self.get_node(self.ud.get_trace_for_reg_use(use))
            node.get_edge(def_node).reg.append(entry)
        for use, entry in zip(
                self.ud.get_mem_uses_for_trace(node.trace_index),
                mem_use_entries):
            def_node = self.get_node(self.ud.get_trace_for_mem_use(use))
            node.get_edge(def_node).mem.append(entry)
        node.done = True

    def get_node(self, trace_index: int) -> BackwardNode:
        node = self.nodes.get(trace_index)
        if node is None:
            node = BackwardNode(trace_index)
            self.nodes[trace_index] = node
            self.worklist.append(node)
        return node

    def get_use_entries(
            self, trace_index: int) -> Tuple[List[Entry], List[Entry]]:
        reg_use_entries = []
        mem_use_entries = []
        if trace_index == 0:
            return reg_use_entries, mem_use_entries
        self.trace.seek_insn(trace_index - 1)
        entry = next(self.trace)
        insn_seq = entry.insn_seq
        while True:
            if entry.tag in (Tag.MT_GET_REG, Tag.MT_GET_REG_NX):
                reg_use_entries.append(entry)
            elif entry.tag == Tag.MT_LOAD:
                mem_use_entries.append(entry)
            try:
                entry = next(self.trace)
            except StopIteration:
                break
            if isinstance(entry, (LdStEntry, InsnExecEntry, LdStNxEntry)):
                if entry.insn_seq != insn_seq:
                    break
                insn_seq = entry.insn_seq
        return reg_use_entries, mem_use_entries


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('trace')
    parser.add_argument('pc', type=lambda pc: int(pc, 0))
    parser.add_argument('--ud')
    args = parser.parse_args()
    if args.ud is None:
        backward = Backward.from_trace_file(args.trace)
    else:
        backward = Backward(Trace.load(args.trace), Ud.load(args.ud))
    backward.main(args.pc)
