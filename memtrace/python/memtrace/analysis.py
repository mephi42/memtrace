#!/usr/bin/env python3
import argparse
import os
import sys
import tempfile

from memtrace.format import format_entry
from memtrace.symbolizer import Symbolizer
from memtrace_ext import Disasm, get_endianness_str, Trace, Ud, ud_file


class Analysis:
    def __init__(self, trace_path, index_path=None, ud_path=None):
        trace = Trace.load(trace_path)
        if index_path is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                index_path = os.path.join(tmpdir, 'memtrace.idx')
                trace.build_insn_index(index_path)
        else:
            trace.load_insn_index(index_path)
        if ud_path is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                ud_path = os.path.join(tmpdir, '{}.bin')
                err = ud_file(
                    trace_path,
                    0,  # start
                    9999999999,  # end
                    None,  # dot
                    None,  # html
                    None,  # csv
                    ud_path,  # binary
                    None,  # verbose
                )
                if err < 0:
                    raise Exception(f'use-def analysis failed: {err}')
                ud = Ud.load(ud_path)
        else:
            ud = Ud.load(ud_path)
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
                print(format_entry(
                    entry=next(analysis.trace),
                    endianness=analysis.endianness_str,
                    disasm=analysis.disasm,
                ))
