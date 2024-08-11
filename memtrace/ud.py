#!/usr/bin/env python3
import os
import tempfile
from typing import Any, List, Optional, Tuple

from memtrace.native import wrap_err
from memtrace.trace import Trace
from ._memtrace import Range, _Ud, VectorOfRanges


class Ud:
    @staticmethod
    def analyze(
        path: Optional[str],
        trace: Trace,
        log: Optional[str] = None,
    ) -> "Ud":
        if path is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                ud_path = os.path.join(tmpdir, "{}.bin")
                native = _Ud.analyze(ud_path, trace.native, log)
        else:
            native = _Ud.analyze(path, trace.native, log)
        if native is None:
            raise Exception("_Ud.analyze() failed")
        return Ud(native)

    @staticmethod
    def load(path: str, trace: Trace) -> "Ud":
        native = _Ud.load(path, trace.native)
        if native is None:
            raise Exception("_Ud.load() failed")
        return Ud(native)

    def __init__(self, native: _Ud):
        self.native = native

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native, name)

    @wrap_err
    def dump_dot(self, path):
        pass

    @wrap_err
    def dump_html(self, path):
        pass

    @wrap_err
    def dump_csv(self, path):
        pass

    def get_codes_for_pc_ranges(self, pc_ranges: List[Tuple[int, int]]) -> List[int]:
        native_pc_ranges = VectorOfRanges()
        native_pc_ranges.extend(
            Range(start_addr, end_addr) for start_addr, end_addr in pc_ranges
        )
        return self.native.get_codes_for_pc_ranges(native_pc_ranges)

    def get_codes_for_pc(self, pc: int) -> List[int]:
        return self.get_codes_for_pc_ranges([(pc, pc)])
