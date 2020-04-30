#!/usr/bin/env python3
import argparse
import os
import sys
import tempfile
from typing import Optional

from memtrace.format import format_entry
from memtrace.symbolizer import Symbolizer
from memtrace.trace import Trace
from memtrace.ud import Ud
from memtrace_ext import Disasm, get_endianness_str, Tag, TraceFilter


class Analysis:
    def __init__(
            self,
            trace_path: str,
            index_path: Optional[str] = None,
            ud_path: Optional[str] = None,
            ud_log: Optional[str] = None,
            first_entry_index: Optional[int] = None,
            last_entry_index: Optional[int] = None,
    ):
        self.index_path = index_path
        self.ud_path = ud_path
        self.ud_log = ud_log
        self.trace = Trace.load(trace_path)
        if first_entry_index is not None or last_entry_index is not None:
            filter = TraceFilter()
            if first_entry_index is not None:
                filter.first_entry_index = first_entry_index
            if last_entry_index is not None:
                filter.last_entry_index = last_entry_index
            self.trace.set_filter(filter)
        self._ud: Optional[Ud] = None
        self.endianness_str = get_endianness_str(self.trace.get_endianness())
        self._disasm: Optional[Disasm] = None
        self._symbolizer: Optional[Symbolizer] = None

    def _init_insn_index(self):
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
            self._init_insn_index()
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
            self._symbolizer = Symbolizer(self.trace.get_mmap_entries())
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


def int_any_base(x):
    return int(x, 0)


def range_any_base(x):
    start, end = x.split('-')
    return int_any_base(start), int_any_base(end)


if __name__ == '__main__':
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
                )
                if entry.tag == Tag.MT_INSN_EXEC:
                    pc = analysis.ud.get_pc_for_code(entry.insn_seq)
                    disasm_str = analysis.ud.get_disasm_for_code(
                        entry.insn_seq)
                    entry_str = f'{entry_str} 0x{pc:016x}: {disasm_str}'
                print(entry_str)
