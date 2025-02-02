#!/usr/bin/env python3
import os
import tempfile
from typing import Generator, Iterable, Optional

from memtrace.symbolizer import Symbolizer
from memtrace.trace import Trace, TraceFilter
from memtrace.ud import Ud
from ._memtrace import Disasm, get_endianness_str, InsnSeq, Tag, TraceIndex


class Analysis:
    def __init__(
        self,
        trace_path: str,
        index_path: Optional[str] = None,
        ud_path: Optional[str] = None,
        ud_log: Optional[str] = None,
        first_entry_index: Optional[int] = None,
        last_entry_index: Optional[int] = None,
        tags: Optional[Iterable[Tag]] = None,
        insn_seqs: Optional[Iterable[InsnSeq]] = None,
    ):
        self.index_path = index_path
        self.ud_path = ud_path
        self.ud_log = ud_log
        self.trace = Trace.load(trace_path)
        if (
            first_entry_index is not None
            or last_entry_index is not None
            or tags is not None
            or insn_seqs is not None
        ):
            filter = TraceFilter()
            if first_entry_index is not None:
                filter.first_entry_index = first_entry_index
            if last_entry_index is not None:
                filter.last_entry_index = last_entry_index
            if tags is not None:
                filter.tags = tags
            if insn_seqs is not None:
                filter.insn_seqs = insn_seqs
            self.trace.set_filter(filter)
        self._ud: Optional[Ud] = None
        self.endianness_str = get_endianness_str(self.trace.get_endianness())
        self._disasm: Optional[Disasm] = None
        self._symbolizer: Optional[Symbolizer] = None

    def init_insn_index(self):
        if self.trace.has_insn_index():
            return
        if self.index_path is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                index_path = os.path.join(tmpdir, "{}.bin")
                self.trace.build_insn_index(index_path)
        elif not os.path.exists(self.index_path.replace("{}", "header")):
            self.trace.build_insn_index(self.index_path)
        else:
            self.trace.load_insn_index(self.index_path)

    @property
    def ud(self) -> Ud:
        if self._ud is None:
            self.init_insn_index()
            if self.ud_path is None or not os.path.exists(
                self.ud_path.replace("{}", "header")
            ):
                self._ud = Ud.analyze(self.ud_path, self.trace, self.ud_log)
            else:
                self._ud = Ud.load(self.ud_path, self.trace)
        return self._ud

    @property
    def disasm(self) -> Disasm:
        if self._disasm is None:
            self._disasm = Disasm(
                self.trace.get_machine_type(),
                self.trace.get_endianness(),
                self.trace.get_word_size(),
            )
        return self._disasm

    @property
    def symbolizer(self) -> Symbolizer:
        if self._symbolizer is None:
            self._symbolizer = Symbolizer(self.trace)
        return self._symbolizer

    def close(self):
        if self._symbolizer is not None:
            self._symbolizer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_traces_for_pc(self, pc) -> Generator[TraceIndex, None, None]:
        for code_index in self.ud.get_codes_for_pc(pc):
            for trace_index in self.ud.get_traces_for_code(code_index):
                yield trace_index

    def get_last_trace_for_pc(self, pc) -> TraceIndex:
        return max(self.get_traces_for_pc(pc))

    def pp_code(self, code_index: InsnSeq) -> str:
        pc = self.ud.get_pc_for_code(code_index)
        disasm_str = self.ud.get_disasm_for_code(code_index)
        symbolized_pc = self.symbolizer.symbolize(pc)
        return f"0x{pc:016x} {disasm_str} {symbolized_pc}"
