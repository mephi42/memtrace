from typing import Any, Iterable, Optional

from memtrace.native import wrap_err
from memtrace._memtrace import DumpKind, Tag, _Trace, _TraceFilter, \
    VectorOfU32s


class TraceFilter:
    def __init__(self):
        self.native = _TraceFilter()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native, name)

    @property
    def tags(self) -> Iterable[Tag]:
        tags = []
        mask = self.native.tag_mask
        for i in range(int(Tag.MT_LAST) - int(Tag.MT_FIRST)):
            if mask & (1 << i):
                tags.append(Tag.values[(int(Tag.MT_FIRST) + i)])
        return tags

    @tags.setter
    def tags(self, tags: Iterable[Tag]):
        mask = 0
        for tag in tags:
            mask |= 1 << (int(tag) - int(Tag.MT_FIRST))
        self.native.tag_mask = mask

    @property
    def insn_seqs(self):
        return self.native.insn_seqs

    @insn_seqs.setter
    def insn_seqs(self, insn_seqs):
        native_insn_seqs = VectorOfU32s()
        native_insn_seqs.extend(insn_seqs)
        self.native.insn_seqs = native_insn_seqs


class Trace:
    @staticmethod
    def load(path: str) -> 'Trace':
        native = _Trace.load(path)
        if native is None:
            raise Exception('_Trace.load() failed')
        return Trace(native)

    def __init__(self, native: _Trace):
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
    def seek_end(self) -> None:
        pass

    @wrap_err
    def dump(self, output: Optional[str], kind: DumpKind) -> None:
        pass

    def set_filter(self, filter: Optional[TraceFilter]) -> None:
        if filter is None:
            self.native.set_filter(None)
        else:
            self.native.set_filter(filter.native)
