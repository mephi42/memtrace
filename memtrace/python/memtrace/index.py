#!/usr/bin/env python3
import argparse

import memtrace_ext


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('memtrace_idx', nargs='?', default='memtrace.idx')
    args = parser.parse_args()
    trace = memtrace_ext.Trace.load(args.memtrace_out)
    trace.build_insn_index(args.memtrace_idx)


if __name__ == '__main__':
    main()
