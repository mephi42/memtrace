from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Set, Tuple
import sys

from memtrace.analysis import Analysis
from memtrace.format import format_entry
from memtrace.trace import Trace
from memtrace.ud import Ud
from ._memtrace import Entry, Tag


@dataclass
class BackwardNode:
    trace_index: int
    depth: int
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
            analysis: Analysis,
            fp=sys.stdout,
    ) -> None:
        class StackEntry:
            def __init__(self, edge: BackwardEdge):
                self.edge = edge
                self.is_fresh = True
                self.edges = iter(edge.dst.edges.values())

        fp.write('#+STARTUP: indent\n')
        stack: List[StackEntry] = [StackEntry(BackwardEdge(self))]
        seen: Set[int] = set()
        while len(stack) > 0:
            indent = '*' * len(stack)
            entry = stack[-1]
            if entry.is_fresh:
                edge = entry.edge
                node = edge.dst
                code_index = analysis.ud.get_code_for_trace(node.trace_index)
                disasm_str = analysis.pp_code(code_index)
                is_seen = node.trace_index in seen
                if is_seen:
                    prefix, suffix = '[[', ']]'
                else:
                    prefix, suffix = '<<', '>>'
                fp.write(
                    f'{indent} {prefix}InsnInTrace:{node.trace_index}'
                    f'{suffix} {disasm_str}\n'
                )
                for trace_entry in edge.reg:
                    entry_str = format_entry(
                        entry=trace_entry,
                        endianness=analysis.endianness_str,
                        disasm=analysis.disasm,
                        trace=analysis.trace,
                    )
                    fp.write(f'Reason: {entry_str}\n')
                for trace_entry in edge.mem:
                    entry_str = format_entry(
                        entry=trace_entry,
                        endianness=analysis.endianness_str,
                        disasm=analysis.disasm,
                        trace=analysis.trace,
                    )
                    fp.write(f'Reason: {entry_str}\n')
                if is_seen:
                    stack.pop()
                    continue
                seen.add(node.trace_index)
                entry.is_fresh = False
            try:
                edge = next(entry.edges)
            except StopIteration:
                stack.pop()
                continue
            stack.append(StackEntry(edge))


@dataclass
class BackwardEdge:
    dst: BackwardNode
    reg: List[Entry] = field(default_factory=list)
    mem: List[Entry] = field(default_factory=list)


class BackwardAnalysis:
    def __init__(
            self,
            analysis: Analysis,
            trace_index0: int,
            depth: int,
            ignore_registers: List[Tuple[int, int]] = None
    ):
        self.trace: Trace = analysis.trace
        self.ud: Ud = analysis.ud
        self.node0: BackwardNode = BackwardNode(trace_index0, depth)
        self.nodes: Dict[int, BackwardNode] = {trace_index0: self.node0}
        self.worklist: Deque[BackwardNode] = deque((self.node0,))
        self.ignore_registers = \
            [] if ignore_registers is None else ignore_registers

    def analyze(self) -> BackwardNode:
        while len(self.worklist) > 0:
            self.step(self.worklist.popleft())
        return self.node0

    def should_ignore_register(self, trace_entry) -> bool:
        start = trace_entry.addr
        end = start + len(trace_entry.value)
        for ignore_start, ignore_end in self.ignore_registers:
            if start >= ignore_start and end <= ignore_end:
                return True
        return False

    def step(self, node: BackwardNode) -> None:
        if node.done or node.depth == 0:
            return
        reg_use_entries, mem_use_entries = self.get_use_entries(
            node.trace_index)
        for use, entry in zip(
                self.ud.get_reg_uses_for_trace(node.trace_index),
                reg_use_entries):
            if self.should_ignore_register(entry):
                continue
            def_node = self.get_node(
                self.ud.get_trace_for_reg_use(use), node.depth - 1)
            node.get_edge(def_node).reg.append(entry)
        for use, entry in zip(
                self.ud.get_mem_uses_for_trace(node.trace_index),
                mem_use_entries):
            def_node = self.get_node(
                self.ud.get_trace_for_mem_use(use), node.depth - 1)
            node.get_edge(def_node).mem.append(entry)
        node.done = True

    def get_node(self, trace_index: int, depth: int) -> BackwardNode:
        node = self.nodes.get(trace_index)
        if node is None:
            node = BackwardNode(trace_index, depth)
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
            if entry.tag in (
                    Tag.MT_LOAD, Tag.MT_STORE, Tag.MT_REG, Tag.MT_GET_REG,
                    Tag.MT_PUT_REG, Tag.MT_INSN_EXEC, Tag.MT_GET_REG_NX,
                    Tag.MT_PUT_REG_NX):
                if entry.insn_seq != insn_seq:
                    break
                insn_seq = entry.insn_seq
        return reg_use_entries, mem_use_entries
