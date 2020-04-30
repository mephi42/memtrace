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
    for tag, tag_stats in sorted(tag_stats.items(), key=str):
        fp.write(f'{tag} count={tag_stats.count} size={tag_stats.size}\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    args = parser.parse_args()
    stats = from_trace_file(args.memtrace_out)
    pp(stats, sys.stdout)


if __name__ == '__main__':
    main()
