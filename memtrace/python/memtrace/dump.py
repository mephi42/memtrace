#!/usr/bin/env python3
import argparse
import sys

import memtrace_ext


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('--start', default=0, type=int)
    parser.add_argument('--end', default=9999999999, type=int)
    args = parser.parse_args()
    sys.exit(memtrace_ext.dump_file(args.memtrace_out, args.start, args.end))


if __name__ == '__main__':
    main()
