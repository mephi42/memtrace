#!/usr/bin/env python3
from collections import defaultdict
import os
import signal
import sys
import threading

import click
import click.types

import memtrace
from memtrace.analysis import Analysis
from memtrace.format import format_entry
from memtrace.interval_tree import IntervalTree
from memtrace._memtrace import DumpKind, InsnSeq, Tag, TraceIndex
from memtrace.notebook import open_notebook
import memtrace.stats
from memtrace.taint import BackwardAnalysis
from memtrace.trace import Trace, TraceFilter
import memtrace.tracer


@click.group(help="memtrace version " + memtrace.__version__)
def main():
    pass


@main.command(help="Analyze the trace in a Jupyter notebook")
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


class AnyIntRangeParamType(click.ParamType):
    name = "range"

    def convert(self, value, param, ctx):
        start, end = value.split("-")
        return int(start, 0), int(end, 0)


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


@main.command(help="Print the trace as text")
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
@click.option(
    "--header/--no-header",
    help="Show trace header",
    is_flag=True,
    default=True,
)
@click.option(
    "--summary/--no-summary",
    help="Show trace summary",
    is_flag=True,
    default=True,
)
def report(
    input, output, start, end, tag, insn_seq, srcline, header: bool, summary: bool
):
    if len(tag) == 0:
        tag = None
    if len(insn_seq) == 0:
        insn_seq = None
    else:
        insn_seq = [InsnSeq(value) for value in insn_seq]
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
        analysis.trace.dump(output, kind, header, summary)


@main.command(help="Perform use-def analysis on the trace")
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


@main.command(help="Analyze distribution of tags in the trace")
@input_option
@output_option
def stats(input, output):
    stats = memtrace.stats.from_trace_file(input)
    with open(output, "w") as fp:
        memtrace.stats.pp(stats, fp)


@main.command(help="Generate instruction index from the trace")
@input_option
@index_option
def index(input, index):
    index = default_index(input, index)
    Trace.load(input).build_insn_index(index)


def resolve_pc(analysis, pc):
    analysis.ud
    analysis.trace.seek_end()
    resolved_pc = analysis.symbolizer.resolve(pc)
    if resolved_pc is None:
        print(f"Cannot find symbol '{pc}'", file=sys.stderr)
        sys.exit(1)
    return resolved_pc


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
        resolved_pc = resolve_pc(analysis, pc)
        with open(output, "w") as fp:
            for trace_index in analysis.get_traces_for_pc(resolved_pc):
                fp.write(f"{trace_index.value}\n")


@main.command(help="Perform backward taint analysis on the trace")
@input_option
@index_option
@ud_option
@output_option
@click.option("--pc", help="Instruction address from which to start the analysis")
@click.option(
    "--trace",
    type=AnyIntParamType(),
    help="Insn-in-trace index from which to start the analysis",
)
@click.option("--depth", type=AnyIntParamType(), default="1", help="Analysis depth")
@click.option(
    "--ignore-register",
    type=AnyIntRangeParamType(),
    multiple=True,
    help="Do not follow these registers",
)
@click.option(
    "--ignore-trace",
    type=AnyIntParamType(),
    multiple=True,
    help="Do not follow these insn-in-trace indices",
)
def taint_backward(
    input, index, ud, output, pc, trace, depth, ignore_register, ignore_trace
):
    if (trace is None) == (pc is None):
        print("Specify either --pc or --trace", file=sys.stderr)
        sys.exit(1)
    index = default_index(input, index)
    with Analysis(
        trace_path=input,
        index_path=index,
        ud_path=ud,
    ) as analysis:
        if trace is None:
            resolved_pc = resolve_pc(analysis, pc)
            trace = analysis.get_last_trace_for_pc(resolved_pc)
        else:
            trace = TraceIndex(trace)
        backward = BackwardAnalysis(
            analysis,
            trace_index0=trace,
            depth=depth,
            ignore_registers=ignore_register,
            ignore_trace_indices={
                TraceIndex(trace_index) for trace_index in ignore_trace
            },
        )
        dag = backward.analyze()
        with open(output, "w") as fp:
            dag.pp(analysis, fp)


@main.command(help="Pretty-print trace entries")
@input_option
@index_option
@ud_option
@output_option
@click.option(
    "--start-trace",
    type=AnyIntParamType(),
    default="0",
    help="Insn-in-trace index to start pretty-printing from",
)
@click.option(
    "--count",
    type=AnyIntParamType(),
    default="10",
    help="Number of trace entries to pretty-print",
)
def dump_entries(input, index, ud, output, start_trace, count):
    index = default_index(input, index)
    with Analysis(
        trace_path=input,
        index_path=index,
        ud_path=ud,
    ) as analysis:
        analysis.ud
        analysis.trace.seek_insn(start_trace)
        with open(output, "w") as fp:
            for _ in range(count):
                entry = next(analysis.trace)
                entry_str = format_entry(
                    entry=entry,
                    endianness=analysis.endianness_str,
                    disasm=analysis.disasm,
                    trace=analysis.trace,
                )
                if entry.tag == Tag.MT_INSN_EXEC:
                    pc = analysis.ud.get_pc_for_code(entry.insn_seq)
                    disasm_str = analysis.ud.get_disasm_for_code(entry.insn_seq)
                    entry_str = f"{entry_str} 0x{pc:016x}: {disasm_str}"
                fp.write(f"{entry_str}\n")


@main.command(help="Show memory touched by specified instructions")
@input_option
@index_option
@ud_option
@output_option
@click.argument("pc-range", nargs=-1)
def ldst(input, index, ud, output, pc_range):
    index = default_index(input, index)
    with Analysis(
        trace_path=input,
        index_path=index,
        ud_path=ud,
    ) as analysis:
        pc_ranges = [
            (resolve_pc(analysis, start_addr), resolve_pc(analysis, end_addr))
            for pc_range in pc_range
            for start_addr, end_addr in (pc_range.split("-"),)
        ]
        filter = TraceFilter()
        filter.tags = (Tag.MT_LOAD, Tag.MT_STORE)
        filter.insn_seqs = analysis.ud.get_codes_for_pc_ranges(pc_ranges)
        analysis.trace.set_filter(filter)

        def merge(list_of_insn_seq2index2entry):
            result = defaultdict(dict)
            for insn_seq2index2entry in list_of_insn_seq2index2entry:
                for insn_seq, index2entry in insn_seq2index2entry.items():
                    for index, entry in index2entry.items():
                        result[insn_seq][index] = entry
            return result

        mem = IntervalTree(merge=merge)
        analysis.trace.seek_start()
        for entry in analysis.trace:
            start = entry.addr
            end = entry.addr + len(entry.value)
            entries = mem[start:end]
            entries[entry.insn_seq][entry.index] = entry
            mem[start:end] = entries
        with open(output, "w") as fp:
            for node in mem:
                fp.write(f"* 0x{node.start:x}-0x{node.end:x}\n")
                for insn_seq, index2entry in node.value.items():
                    disasm_str = analysis.pp_code(insn_seq)
                    fp.write(f"*** {disasm_str}\n")
                    for entry in index2entry.values():
                        entry_str = format_entry(
                            entry=entry,
                            endianness=analysis.endianness_str,
                            disasm=analysis.disasm,
                            trace=analysis.trace,
                        )
                        fp.write(f"***** {entry_str}\n")


if __name__ == "__main__":
    main()
