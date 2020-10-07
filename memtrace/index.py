#!/usr/bin/env python3
import argparse
import os

from memtrace.trace import Trace


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('memtrace_idx', nargs='?')
    args = parser.parse_args(argv)
    if args.memtrace_idx is None:
        memtrace_idx = os.path.join(
            os.path.dirname(args.memtrace_out), 'index-{}.bin')
    else:
        memtrace_idx = args.memtrace_idx
    trace = Trace.load(args.memtrace_out)
    trace.build_insn_index(memtrace_idx)


if __name__ == '__main__':
    main()
