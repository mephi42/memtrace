#!/usr/bin/env python3
import argparse
import os
import tempfile
from typing import Any, List, Optional, Tuple

from memtrace.trace import Trace
from ._memtrace import Range, _Ud, VectorOfRanges


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
                native = _Ud.analyze(
                    ud_path, trace.native, log)
        else:
            native = _Ud.analyze(path, trace.native, log)
        if native is None:
            raise Exception('_Ud.analyze() failed')
        return Ud(native)

    @staticmethod
    def load(path: str, trace: Trace) -> 'Ud':
        native = _Ud.load(path, trace.native)
        if native is None:
            raise Exception('_Ud.load() failed')
        return Ud(native)

    def __init__(self, native: _Ud):
        self.native = native

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native, name)

    def get_codes_for_pc_ranges(
            self, pc_ranges: List[Tuple[int, int]]) -> List[int]:
        native_pc_ranges = VectorOfRanges()
        native_pc_ranges.extend(
            Range(start_addr, end_addr)
            for start_addr, end_addr in pc_ranges
        )
        return self.native.get_codes_for_pc_ranges(native_pc_ranges)

    def get_codes_for_pc(self, pc: int) -> List[int]:
        return self.get_codes_for_pc_ranges([(pc, pc)])


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('memtrace_idx', nargs='?')
    parser.add_argument('--start', type=int)
    parser.add_argument('--end', type=int)
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
        args.memtrace_out,
        memtrace_idx,
        args.binary,
        args.log,
        first_entry_index=args.start,
        last_entry_index=args.end,
    )
    ud = analysis.ud
    try:
        if args.dot is not None:
            ud.dump_dot(args.dot)
        if args.html is not None:
            ud.dump_dot(args.html)
        if args.csv is not None:
            ud.dump_csv(args.csv)
    finally:
        analysis.close()


if __name__ == '__main__':
    main()
