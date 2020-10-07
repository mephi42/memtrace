from collections import defaultdict
import os
import subprocess
import tempfile
from typing import List, Union


def fake_maps(mappings):
    # Make proc_maps_report in libdwfl/linux-proc-maps.c happy.
    maps = tempfile.NamedTemporaryFile()
    mappings_by_name = defaultdict(list)
    for mapping in mappings:
        mappings_by_name[mapping.name].append(mapping)
    for mappings_for_name in mappings_by_name.values():
        for mapping in mappings_for_name:
            maps.write(
                (f'{mapping.start:x}-{mapping.end:x} ---- '
                 f'{mapping.offset:x} {os.major(mapping.dev):02x}:'
                 f'{os.minor(mapping.dev):02x} {mapping.inode} '
                 f'{mapping.name}\n').encode())
    maps.flush()
    return maps


class Symbolizer:
    def __init__(self, mappings: List[object]):
        self.maps = fake_maps(mappings)
        self.cmd: List[str] = [
            'stdbuf', '-i0', '-o0', '-e0',
            'eu-addr2line',
            f'--linux-process-map={self.maps.name}',
            '--addresses',
            '--demangle',
            '--symbols-sections',
        ]
        self.process = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def close(self) -> None:
        self.process.stdin.close()
        self.process.wait()
        self.process.stdout.close()
        self.maps.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def symbolize(self, addr: int) -> str:
        self.process.stdin.write(f'0x{addr:x}\n'.encode())
        self.process.stdin.flush()
        self.readline()
        line2 = self.readline()
        line3 = self.process.stdout.readline().strip().decode()
        return f'in {line2} at {line3}'

    def resolve(self, symbol: str) -> Union[int, None]:
        self.process.stdin.write(f'{symbol}\n'.encode())
        self.process.stdin.flush()
        line1 = self.readline()
        if ': cannot find symbol \'' in line1:
            return None
        self.readline()
        self.readline()
        return int(line1, 0)

    def readline(self):
        return self.process.stdout.readline().strip().decode()
