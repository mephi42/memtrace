from typing import Optional

from memtrace.trace import Trace


class Symbolizer:
    def __init__(self, trace: Trace):
        self.trace = trace

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def symbolize(self, addr: int) -> str:
        line = self.trace.symbolize(addr)
        if line.symbol is None:
            symbol = '??'
        else:
            symbol = line.symbol
        if line.offset == 0:
            plus = ''
        else:
            plus = f'+0x{line.offset:x}'
        if line.section is None:
            section = ''
        else:
            section = f' ({line.section})'
        if line.file is None:
            file = '??'
        else:
            file = line.file
        return f'in {symbol}{plus}{section} at {file}:{line.line}'

    def resolve(self, symbol: str) -> Optional[int]:
        return self.trace.resolve(symbol)
