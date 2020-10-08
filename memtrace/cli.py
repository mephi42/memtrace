#!/usr/bin/env python3
import signal
import sys

import click
import click.types

import memtrace
from memtrace.analysis import Analysis
import memtrace.tracer
from ._memtrace import Tag


@click.group(help='memtrace version ' + memtrace.__version__)
def main():
    pass


@main.command(
    context_settings={
        'ignore_unknown_options': True,
    },
    help='Run a command and record its execution trace into memtrace.out',
)
def record(argv):
    p = memtrace.tracer.popen(argv)
    while True:
        try:
            status = p.wait()
        except KeyboardInterrupt:
            p.send_signal(signal.SIGINT)
        else:
            sys.exit(status)


class TagParamType(click.ParamType):
    name = 'tag'

    def convert(self, value, param, ctx):
        return Tag.names[value]


class AnyIntParamType(click.types.IntParamType):
    def convert(self, value, param, ctx):
        return int(value, 0)


@main.command(
    help='Read out the trace stored in a memtrace.out file',
)
@click.option(
    '-i', '--input',
    default='memtrace.out',
    help='Input file name',
)
@click.option(
    '-o', '--output',
    default='/dev/stdout',
    help='Output file name',
)
@click.option(
    '--start',
    help='Index of the first entry (inclusive)',
    type=AnyIntParamType(),
)
@click.option(
    '--end',
    help='Index of the last entry (inclusive)',
    type=AnyIntParamType(),
)
@click.option(
    '--tag',
    help='Output only entries with the specified tags',
    multiple=True,
    type=TagParamType(),
)
@click.option(
    '--insn-seq',
    help='Output only entries related to the specified instructions',
    multiple=True,
    type=AnyIntParamType(),
)
def report(input, output, start, end, tag, insn_seq):
    if len(tag) == 0:
        tag = None
    if len(insn_seq) == 0:
        insn_seq = None
    analysis = Analysis(
        input,
        first_entry_index=start,
        last_entry_index=end,
        tags=tag,
        insn_seqs=insn_seq,
    )
    analysis.trace.dump(output)


if __name__ == '__main__':
    main()
