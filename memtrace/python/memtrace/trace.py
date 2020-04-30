from typing import Any, Optional

from memtrace.native import wrap_err
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

    @wrap_err
    def build_insn_index(self, path: str, step_shift: int = 2) -> None:
        pass

    @wrap_err
    def load_insn_index(self, path) -> None:
        pass

    @wrap_err
    def seek_insn(self, index: int) -> None:
        pass

    @wrap_err
    def dump(self, output: Optional[str]) -> None:
        pass
