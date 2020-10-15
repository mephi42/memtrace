#!/usr/bin/env python3
import argparse
from collections import defaultdict
import os
import sys
import tempfile
from typing import Iterable, Optional

from memtrace.format import format_entry
from memtrace.interval_tree import IntervalTree
from memtrace.symbolizer import Symbolizer
from memtrace.trace import Trace, TraceFilter
from memtrace.ud import Ud
from ._memtrace import Disasm, get_endianness_str, Tag


class Analysis:
    def __init__(
            self,
            trace_path: str,
            index_path: Optional[str] = None,
            ud_path: Optional[str] = None,
            ud_log: Optional[str] = None,
            first_entry_index: Optional[int] = None,
            last_entry_index: Optional[int] = None,
            tags: Optional[Iterable[Tag]] = None,
            insn_seqs: Optional[Iterable[int]] = None,
    ):
        self.index_path = index_path
        self.ud_path = ud_path
        self.ud_log = ud_log
        self.trace = Trace.load(trace_path)
        if (first_entry_index is not None or
                last_entry_index is not None or
                tags is not None or
                insn_seqs is not None):
            filter = TraceFilter()
            if first_entry_index is not None:
                filter.first_entry_index = first_entry_index
            if last_entry_index is not None:
                filter.last_entry_index = last_entry_index
            if tags is not None:
                filter.tags = tags
            if insn_seqs is not None:
                filter.insn_seqs = insn_seqs
            self.trace.set_filter(filter)
        self._ud: Optional[Ud] = None
        self.endianness_str = get_endianness_str(self.trace.get_endianness())
        self._disasm: Optional[Disasm] = None
        self._symbolizer: Optional[Symbolizer] = None

    def init_insn_index(self):
        if self.trace.has_insn_index():
            return
        if self.index_path is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                index_path = os.path.join(tmpdir, '{}.bin')
                self.trace.build_insn_index(index_path)
        elif not os.path.exists(self.index_path.replace('{}', 'header')):
            self.trace.build_insn_index(self.index_path)
        else:
            self.trace.load_insn_index(self.index_path)

    @property
    def ud(self) -> Ud:
        if self._ud is None:
            self.init_insn_index()
            if (self.ud_path is None or
                    not os.path.exists(self.ud_path.replace('{}', 'header'))):
                self._ud = Ud.analyze(self.ud_path, self.trace, self.ud_log)
            else:
                self._ud = Ud.load(self.ud_path, self.trace)
        return self._ud

    @property
    def disasm(self) -> Disasm:
        if self._disasm is None:
            self._disasm = Disasm(
                self.trace.get_machine_type(),
                self.trace.get_endianness(),
                self.trace.get_word_size(),
            )
        return self._disasm

    @property
    def symbolizer(self) -> Symbolizer:
        if self._symbolizer is None:
            self._symbolizer = Symbolizer(self.trace)
        return self._symbolizer

    def close(self):
        if self._symbolizer is not None:
            self._symbolizer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_traces_for_pc(self, pc):
        for code_index in self.ud.get_codes_for_pc(pc):
            for trace_index in self.ud.get_traces_for_code(code_index):
                yield trace_index

    def get_last_trace_for_pc(self, pc):
        return max(self.get_traces_for_pc(pc))

    def pp_code(self, code_index: int) -> str:
        pc = self.ud.get_pc_for_code(code_index)
        disasm_str = self.ud.get_disasm_for_code(code_index)
        symbolized_pc = self.symbolizer.symbolize(pc)
        return f'0x{pc:016x} {disasm_str} {symbolized_pc}'


def int_any_base(x):
    return int(x, 0)


def range_any_base(x):
    start, end = x.split('-')
    return int_any_base(start), int_any_base(end)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--trace-path', default='memtrace.out')
    parser.add_argument('--ud-path')
    parser.add_argument('--index-path')
    subparsers = parser.add_subparsers(dest='subparser_name')

    subparser = subparsers.add_parser('get-traces-for-pc')
    subparser.add_argument('pc')

    subparser = subparsers.add_parser('taint-backward')
    group = subparser.add_mutually_exclusive_group(required=True)
    group.add_argument('--pc', type=int_any_base)
    group.add_argument('--trace', type=int_any_base)
    subparser.add_argument('--depth', type=int_any_base, default=1)
    subparser.add_argument(
        '--ignore-register', action='append', type=range_any_base)

    subparser = subparsers.add_parser('dump-entries')
    subparser.add_argument('--start-trace', type=int_any_base, default=0)
    subparser.add_argument('--count', type=int_any_base, default=10)

    subparser = subparsers.add_parser('ldst')
    subparser.add_argument('pc_range', nargs='+')

    args = parser.parse_args()
    with Analysis(
            trace_path=args.trace_path,
            index_path=args.index_path,
            ud_path=args.ud_path,
    ) as analysis:
        if args.subparser_name == 'get-traces-for-pc':
            pc = analysis.symbolizer.resolve(args.pc)
            if pc is None:
                print(f'Cannot find symbol \'{args.pc}\'', file=sys.stderr)
                sys.exit(1)
            for trace in analysis.get_traces_for_pc(pc):
                print(str(trace))
        elif args.subparser_name == 'taint-backward':
            if args.trace is None:
                trace_index0 = analysis.get_last_trace_for_pc(args.pc)
            else:
                trace_index0 = args.trace
            from memtrace.taint import BackwardAnalysis

            backward = BackwardAnalysis(
                analysis,
                trace_index0=trace_index0,
                depth=args.depth,
                ignore_registers=args.ignore_register,
            )
            dag = backward.analyze()
            dag.pp(analysis)
        elif args.subparser_name == 'dump-entries':
            analysis.trace.seek_insn(args.start_trace)
            for _ in range(args.count):
                entry = next(analysis.trace)
                entry_str = format_entry(
                    entry=entry,
                    endianness=analysis.endianness_str,
                    disasm=analysis.disasm,
                    trace=analysis.trace,
                )
                if entry.tag == Tag.MT_INSN_EXEC:
                    pc = analysis.ud.get_pc_for_code(entry.insn_seq)
                    disasm_str = analysis.ud.get_disasm_for_code(
                        entry.insn_seq)
                    entry_str = f'{entry_str} 0x{pc:016x}: {disasm_str}'
                print(entry_str)
        if args.subparser_name == 'ldst':
            pc_ranges = [
                (analysis.symbolizer.resolve(start_addr),
                 analysis.symbolizer.resolve(end_addr))
                for pc_range in args.pc_range
                for start_addr, end_addr in (pc_range.split('-'),)
            ]
            filter = TraceFilter()
            filter.tags = (Tag.MT_LOAD, Tag.MT_STORE)
            filter.insn_seqs = analysis.ud.get_codes_for_pc_ranges(pc_ranges)
            analysis.trace.set_filter(filter)

            def merge(list_of_insn_seq2index2entry):
                result = defaultdict(dict)
                for insn_seq2index2entry in list_of_insn_seq2index2entry:
                    for insn_seq, index2entry in insn_seq2index2entry.items():
                        for index, entry in index2entry.items():
                            result[insn_seq][index] = entry
                return result

            mem = IntervalTree(merge=merge)
            for entry in analysis.trace:
                start = entry.addr
                end = entry.addr + len(entry.value)
                entries = mem[start:end]
                entries[entry.insn_seq][entry.index] = entry
                mem[start:end] = entries
            for node in mem:
                print(f'* 0x{node.start:x}-0x{node.end:x}')
                for insn_seq, index2entry in node.value.items():
                    disasm_str = analysis.pp_code(insn_seq)
                    print(f'*** {disasm_str}')
                    for entry in index2entry.values():
                        entry_str = format_entry(
                            entry=entry,
                            endianness=analysis.endianness_str,
                            disasm=analysis.disasm,
                            trace=analysis.trace,
                        )
                        print(f'***** {entry_str}')


if __name__ == '__main__':
    main()
