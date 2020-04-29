#!/usr/bin/env python3
import argparse
import sys
from typing import List

from memtrace.trace import Trace


def main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('--output')
    parser.add_argument('--start', default=0, type=int)
    parser.add_argument('--end', default=9999999999, type=int)
    args = parser.parse_args(argv)
    trace = Trace.load(args.memtrace_out)
    trace.dump(args.output, args.start, args.end)


if __name__ == '__main__':
    main(sys.argv)
