#!/usr/bin/env python3
import argparse
import sys

from memtrace.trace import Trace


def from_trace_file(path):
    return Trace.load(path).gather_stats()


def pp(stats, fp):
    tag_stats = {
        entry.key(): entry.data()
        for entry in stats.tag_stats
    }
    total_count = 0
    total_size = 0
    for tag, tag_stats in sorted(tag_stats.items(), key=str):
        fp.write(f'{tag} count={tag_stats.count} size={tag_stats.size}\n')
        total_count += tag_stats.count
        total_size += tag_stats.size
    fp.write(f'total count={total_count} size={total_size}\n')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    args = parser.parse_args(argv)
    stats = from_trace_file(args.memtrace_out)
    pp(stats, sys.stdout)


if __name__ == '__main__':
    main()
