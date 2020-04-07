from collections import defaultdict
import subprocess
import tempfile
from typing import List

from memtrace_ext import MmapEntry


def fake_maps(mappings):
    # Make proc_maps_report in libdwfl/linux-proc-maps.c happy.
    maps = tempfile.NamedTemporaryFile()
    mappings_by_name = defaultdict(list)
    for mapping in mappings:
        mappings_by_name[mapping.name].append(mapping)
    for inode, mappings_for_name in enumerate(mappings_by_name.values()):
        for mapping in mappings_for_name:
            maps.write(
                (f'{mapping.start:x}-{mapping.end:x} ---- '
                 f'0 00:00 {inode} {mapping.name}\n').encode())
    maps.flush()
    return maps


class Symbolizer:
    def __init__(self, mappings: List[MmapEntry]):
        self.maps = fake_maps(mappings)
        self.cmd: List[str] = [
            'eu-addr2line',
            f'--linux-process-map={self.maps.name}',
            '--demangle',
            '--symbols-sections',
        ]
        self.process = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def close(self) -> None:
        self.process.stdin.close()
        returncode = self.process.wait()
        if returncode != 0:
            raise subprocess.CalledProcessError(returncode, self.cmd)
        self.maps.close()

    def symbolize(self, addr: int) -> str:
        self.process.stdin.write(f'0x{addr:x}\n'.encode())
        self.process.stdin.flush()
        function = self.process.stdout.readline().strip().decode()
        line = self.process.stdout.readline().strip().decode()
        return f'in {function} at {line}'
