#!/usr/bin/env python3
import argparse
import sys

import memtrace_ext


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('--start', default=0, type=int)
    parser.add_argument('--end', default=999999999, type=int)
    parser.add_argument('--dot')
    parser.add_argument('--html')
    parser.add_argument('--csv')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    sys.exit(memtrace_ext.ud_file(
        args.memtrace_out,
        args.start,
        args.end,
        args.dot,
        args.html,
        args.csv,
        args.verbose,
    ))


if __name__ == '__main__':
    main()
