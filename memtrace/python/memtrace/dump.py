#!/usr/bin/env python3
import argparse
import sys
from typing import List

from memtrace.analysis import Analysis


def main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('--output', default='/dev/stdout')
    parser.add_argument('--start', type=int)
    parser.add_argument('--end', type=int)
    args = parser.parse_args(argv)
    analysis = Analysis(
        args.memtrace_out,
        first_entry_index=args.start,
        last_entry_index=args.end,
    )
    analysis.trace.dump(args.output)


if __name__ == '__main__':
    main(sys.argv[1:])
