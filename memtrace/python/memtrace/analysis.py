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
from memtrace_ext import Disasm, get_endianness_str, Tag


class Analysis:
    def __init__(
            self,
            trace_path: str,
            index_path: Optional[str] = None,
            ud_path: Optional[str] = None,
            ud_verbose: bool = False,
    ):
        trace = Trace.load(trace_path)
        if index_path is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                index_path = os.path.join(tmpdir, '{}.bin')
                trace.build_insn_index(index_path)
        elif not os.path.exists(index_path.replace('{}', 'header')):
            trace.build_insn_index(index_path)
        else:
            trace.load_insn_index(index_path)
        if (ud_path is None or
                not os.path.exists(ud_path.replace('{}', 'header'))):
            ud = Ud.analyze(ud_path, trace, ud_verbose)
        else:
            ud = Ud.load(ud_path, trace)
        self.trace = trace
        self.ud = ud
        endianness = self.trace.get_endianness()
        self.endianness_str = get_endianness_str(endianness)
        self.disasm = Disasm(
            self.trace.get_machine_type(),
            endianness,
            self.trace.get_word_size(),
        )
        self.symbolizer = Symbolizer(self.trace.get_mmap_entries())

    def close(self):
        self.symbolizer.close()

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
