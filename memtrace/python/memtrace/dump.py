#!/usr/bin/env python3
import argparse
import sys
from typing import List

from memtrace.analysis import Analysis
import memtrace_ext


def main(argv: List[str]) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('memtrace_out', nargs='?', default='memtrace.out')
    parser.add_argument('--output', default='/dev/stdout')
    parser.add_argument('--start', type=int)
    parser.add_argument('--end', type=int)
    parser.add_argument(
        '--tag', action='append', type=lambda x: memtrace_ext.Tag.names[x])
    parser.add_argument(
        '--insn-seq', action='append', type=lambda x: int(x, 0))
    args = parser.parse_args(argv)
    analysis = Analysis(
        args.memtrace_out,
        first_entry_index=args.start,
        last_entry_index=args.end,
        tags=args.tag,
        insn_seqs=args.insn_seq,
    )
    analysis.trace.dump(args.output)


if __name__ == '__main__':
    main(sys.argv[1:])
