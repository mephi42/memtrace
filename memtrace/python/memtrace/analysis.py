#!/usr/bin/env python3
import argparse
import os
import tempfile

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

    def get_traces_for_pc(self, pc):
        for code_index in self.ud.get_codes_for_pc(pc):
            for trace_index in self.ud.get_traces_for_code(code_index):
                yield trace_index

    def get_last_trace_for_pc(self, pc):
        return max(self.get_traces_for_pc(pc))


if __name__ == '__main__':
    int_any_base = lambda x: int(x, 0)

    parser = argparse.ArgumentParser()
    parser.add_argument('--trace-path', default='memtrace.out')
    parser.add_argument('--ud-path')
    parser.add_argument('--index-path')
    subparsers = parser.add_subparsers(dest='subparser_name')

    subparser = subparsers.add_parser('get-traces-for-pc')
    subparser.add_argument('pc', type=int_any_base)

    subparser = subparsers.add_parser('taint-backward')
    group = subparser.add_mutually_exclusive_group(required=True)
    group.add_argument('--pc', type=int_any_base)
    group.add_argument('--trace', type=int_any_base)
    subparser.add_argument('--depth', type=int_any_base, default=1)

    args = parser.parse_args()
    analysis = Analysis(
        trace_path=args.trace_path,
        index_path=args.index_path,
        ud_path=args.ud_path,
    )
    if args.subparser_name == 'get-traces-for-pc':
        for trace in analysis.get_traces_for_pc(args.pc):
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
        )
        dag = backward.analyze()
        dag.pp(analysis)
