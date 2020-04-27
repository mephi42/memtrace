import os
from typing import Any

import memtrace_ext


class Trace:
    @staticmethod
    def load(path: str) -> 'Trace':
        native = memtrace_ext._Trace.load(path)
        if native is None:
            raise Exception('_Trace.load() failed')
        return Trace(native)

    def __init__(self, native: memtrace_ext._Trace):
        self.native = native

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native, name)

    def __iter__(self) -> 'Trace':
        return self

    def __next__(self) -> Any:
        return next(self.native)

    def build_insn_index(self, path: str, step_shift: int = 2) -> None:
        err = self.native.build_insn_index(path, step_shift)
        if err < 0:
            error_str = os.strerror(-err)
            raise Exception(f'_Trace.build_insn_index() failed: {error_str}')

    def load_insn_index(self, path) -> None:
        err = self.native.load_insn_index(path)
        if err < 0:
            error_str = os.strerror(-err)
            raise Exception(f'_Trace.load_insn_index() failed: {error_str}')

    def seek_insn(self, index: int) -> None:
        err = self.native.seek_insn(index)
        if err < 0:
            error_str = os.strerror(-err)
            raise Exception(f'_Trace.seek_insn({index}) failed: {error_str}')
