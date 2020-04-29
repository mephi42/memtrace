#!/usr/bin/env python3
import argparse
import os
import sys
import tempfile
from typing import Any, List, Optional

from memtrace.trace import Trace
import memtrace_ext


class Ud:
    @staticmethod
    def analyze(
            path: Optional[str],
            trace: Trace,
            log: Optional[str] = None,
    ) -> 'Ud':
        if path is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                ud_path = os.path.join(tmpdir, '{}.bin')
                native = memtrace_ext._Ud.analyze(
                    ud_path, trace.native, log)
        else:
            native = memtrace_ext._Ud.analyze(path, trace.native, log)
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


def main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('memtrace_idx', nargs='?')
    parser.add_argument('--start', default=0, type=int)
    parser.add_argument('--end', default=9999999999, type=int)
    parser.add_argument('--dot')
    parser.add_argument('--html')
    parser.add_argument('--csv')
    parser.add_argument('--binary')
    parser.add_argument('--log')
    args = parser.parse_args(argv)
    if args.memtrace_idx is None:
        memtrace_idx = os.path.join(
            os.path.dirname(args.memtrace_out), 'index-{}.bin')
    else:
        memtrace_idx = args.memtrace_idx
    from memtrace.analysis import Analysis
    analysis = Analysis(
        args.memtrace_out, memtrace_idx, args.binary, args.log)
    try:
        if args.dot is not None:
            analysis.ud.dump_dot(args.dot)
        if args.html is not None:
            analysis.ud.dump_dot(args.html)
        if args.csv is not None:
            analysis.ud.dump_csv(args.csv)
    finally:
        analysis.close()


if __name__ == '__main__':
    main(sys.argv)
