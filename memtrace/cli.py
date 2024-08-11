#!/usr/bin/env python3
import os
import signal
import sys
import threading

import click
import click.types

import memtrace
from memtrace.analysis import Analysis
import memtrace.tracer
from memtrace.notebook import open_notebook
from memtrace._memtrace import DumpKind, Tag
import memtrace.stats
from memtrace.trace import Trace


@click.group(help="memtrace version " + memtrace.__version__)
def main():
    pass


@main.command(
    help="Analyze the trace in a Jupyter notebook",
)
def notebook():
    with open_notebook(click.echo):
        click.echo("Press Ctrl+C to stop the container.")
        threading.Event().wait()


@main.command(
    context_settings={
        "ignore_unknown_options": True,
    },
    help="Run a command and record its execution trace",
)
@click.argument("argv", nargs=-1, type=click.UNPROCESSED)
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
    name = "tag"

    def convert(self, value, param, ctx):
        return Tag.names[value]


class AnyIntParamType(click.types.IntParamType):
    def convert(self, value, param, ctx):
        return int(value, 0)


def input_option(function):
    return click.option(
        "-i",
        "--input",
        default="memtrace.out",
        help="Input file name",
    )(function)


def output_option(function):
    return click.option(
        "-o",
        "--output",
        default="/dev/stdout",
        help="Output file name",
    )(function)


def start_option(function):
    return click.option(
        "--start",
        help="Index of the first entry (inclusive)",
        type=AnyIntParamType(),
    )(function)


def end_option(function):
    return click.option(
        "--end",
        help="Index of the last entry (inclusive)",
        type=AnyIntParamType(),
    )(function)


def index_option(function):
    return click.option(
        "--index",
        help="Instruction index files specified using the {} placeholder, "
        + "e.g., index-{}.bin",
    )(function)


def default_index(input, index):
    if index is None:
        index = os.path.join(os.path.dirname(input), "index-{}.bin")
    return index


def ud_option(function):
    return click.option(
        "--ud",
        help="Binary use-def analysis files specified using "
        + "the {} placeholder, e.g., ud-{}.bin",
    )(function)


@main.command(
    help="Print the trace as text",
)
@input_option
@output_option
@start_option
@end_option
@click.option(
    "--tag",
    help="Output only entries with the specified tags",
    multiple=True,
    type=TagParamType(),
)
@click.option(
    "--insn-seq",
    help="Output only entries related to the specified instructions",
    multiple=True,
    type=AnyIntParamType(),
)
@click.option(
    "--srcline",
    help="Output only source file names and line numbers",
    is_flag=True,
)
def report(input, output, start, end, tag, insn_seq, srcline):
    if len(tag) == 0:
        tag = None
    if len(insn_seq) == 0:
        insn_seq = None
    with Analysis(
        input,
        first_entry_index=start,
        last_entry_index=end,
        tags=tag,
        insn_seqs=insn_seq,
    ) as analysis:
        if srcline:
            analysis.init_insn_index()
            kind = DumpKind.Source
        else:
            kind = DumpKind.Raw
        analysis.trace.dump(output, kind)


@main.command(
    help="Perform use-def analysis on the trace",
)
@input_option
@index_option
@start_option
@end_option
@click.option(
    "--dot",
    help="Write the analysis results in the DOT format into this file",
)
@click.option(
    "--html",
    help="Write the analysis results in the HTML format into this file",
)
@click.option(
    "--csv",
    help="Write the analysis results in the CSV format into the "
    + "code, trace and uses files specified using the {} placeholder, "
    + "e.g., ud-{}.csv",
)
@ud_option
@click.option(
    "--log",
    help="Write the analysis log into this file",
)
def ud(input, index, start, end, dot, html, csv, ud, log):
    index = default_index(input, index)
    with Analysis(
        trace_path=input,
        index_path=index,
        ud_path=ud,
        ud_log=log,
        first_entry_index=start,
        last_entry_index=end,
    ) as analysis:
        if dot is not None:
            analysis.ud.dump_dot(dot)
        if html is not None:
            analysis.ud.dump_html(html)
        if csv is not None:
            analysis.ud.dump_csv(csv)


@main.command(
    help="Analyze distribution of tags in the trace",
)
@input_option
@output_option
def stats(input, output):
    stats = memtrace.stats.from_trace_file(input)
    with open(output, "w") as fp:
        memtrace.stats.pp(stats, fp)


@main.command(
    help="Generate instruction index from the trace",
)
@input_option
@index_option
def index(input, index):
    index = default_index(input, index)
    Trace.load(input).build_insn_index(index)


@main.command(
    help="Print the insn-in-trace indices corresponding to the "
    + "specified address or symbol",
)
@input_option
@index_option
@ud_option
@output_option
@click.argument("pc")
def traces_for_pc(input, index, ud, output, pc):
    index = default_index(input, index)
    with Analysis(
        trace_path=input,
        index_path=index,
        ud_path=ud,
    ) as analysis:
        analysis.ud
        analysis.trace.seek_end()
        resolved_pc = analysis.symbolizer.resolve(pc)
        if resolved_pc is None:
            print(f"Cannot find symbol '{pc}'", file=sys.stderr)
            sys.exit(1)
        with open(output, "w") as fp:
            for trace in analysis.get_traces_for_pc(resolved_pc):
                fp.write(f"{trace}\n")


if __name__ == "__main__":
    main()
