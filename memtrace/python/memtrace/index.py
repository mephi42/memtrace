#!/usr/bin/env python3
import argparse

from memtrace.trace import Trace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('memtrace_idx', nargs='?', default='index-{}.bin')
    args = parser.parse_args()
    trace = Trace.load(args.memtrace_out)
    trace.build_insn_index(args.memtrace_idx)


if __name__ == '__main__':
    main()
