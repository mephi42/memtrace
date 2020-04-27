#!/usr/bin/env python3
import argparse
import os
import tempfile
from typing import Any, Optional

from memtrace.trace import Trace
import memtrace_ext


class Ud:
    @staticmethod
    def analyze(
            path: Optional[str], trace: Trace, verbose: bool = False) -> 'Ud':
        if path is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                ud_path = os.path.join(tmpdir, '{}.bin')
                native = memtrace_ext._Ud.analyze(
                    ud_path, trace.native, verbose)
        else:
            native = memtrace_ext._Ud.analyze(path, trace.native, verbose)
        if native is None:
            raise Exception('_Ud.analyze() failed')
        return Ud(native)

    @staticmethod
    def load(path: str, trace: Trace) -> 'Ud':
        native = memtrace_ext._Ud.load(path, trace.native)
        if native is None:
            raise Exception('_Ud.load() failed')
        return Ud(native)

    def __init__(self, native: memtrace_ext._Ud):
        self.native = native

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native, name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('memtrace_idx', nargs='?', default='index-{}.bin')
    parser.add_argument('--start', default=0, type=int)
    parser.add_argument('--end', default=9999999999, type=int)
    parser.add_argument('--dot')
    parser.add_argument('--html')
    parser.add_argument('--csv')
    parser.add_argument('--binary')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    from memtrace.analysis import Analysis
    analysis = Analysis(
        args.memtrace_out, args.memtrace_idx, args.binary, args.verbose)
    if args.dot is not None:
        analysis.ud.dump_dot(args.dot)
    if args.html is not None:
        analysis.ud.dump_dot(args.html)
    if args.csv is not None:
        analysis.ud.dump_csv(args.csv)


if __name__ == '__main__':
    main()
