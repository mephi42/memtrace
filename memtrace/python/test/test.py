#!/usr/bin/env python3
import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest

from memtrace_ext import Disasm, Entry, get_endianness_str, get_tag_str, \
    get_machine_type_str, InsnEntry, InsnExecEntry, LdStEntry, \
    LdStNxEntry, MmapEntry, Trace


class TestCommon(unittest.TestCase):
    def setUp(self) -> None:
        self.basedir = os.path.dirname(os.path.realpath(__file__))
        pythondir = os.path.dirname(self.basedir)
        memtracedir = os.path.dirname(pythondir)
        self.rootdir = os.path.dirname(memtracedir)
        self.vg_in_place = os.path.join(self.rootdir, 'vg-in-place')

    def _compile(self, workdir: str, target: str) -> None:
        args = [
            'cc',
            '-o', os.path.join(workdir, target),
            '-nostdlib',
            f'{target}.S',
        ]
        sys.stderr.write('{}\n'.format(' '.join(args)))
        subprocess.check_call(args, cwd=self.basedir)

    def _memtrace(self, workdir: str, target: str) -> None:
        args = [
            self.vg_in_place,
            '--tool=memtrace',
            '--pc-range=0-0xffffffffffffffff:imr',
            f'./{target}',
        ]
        sys.stderr.write('{}\n'.format(' '.join(args)))
        subprocess.check_call(args, cwd=workdir)

    def _filter_line(
            self, fp, line: bytes, rootdir: bytes, workdir: bytes) -> None:
        if rootdir in line:
            return
        if b'[stack]' in line:
            return
        line = line.replace(workdir, b'{workdir}')
        fp.write(line)

    def _dump(self, workdir: str, target: str) -> None:
        dump_txt = f'{target}-dump.txt'
        actual_dump_txt = os.path.join(workdir, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        args = ['python3', '-m', 'memtrace.dump']
        sys.stderr.write('{}\n'.format(' '.join(args)))
        p = subprocess.Popen(args, stdout=subprocess.PIPE, cwd=workdir)
        try:
            with open(actual_dump_txt, 'wb') as fp:
                rootdir_bytes = self.rootdir.encode()
                workdir_bytes = workdir.encode()
                for line in p.stdout:
                    self._filter_line(fp, line, rootdir_bytes, workdir_bytes)
        finally:
            returncode = p.wait()
            if returncode != 0:
                raise subprocess.CalledProcessError(returncode, args)
        subprocess.check_call([
            'diff',
            '-au',
            expected_dump_txt,
            actual_dump_txt,
        ])

    def _ud(self, workdir: str, target: str) -> None:
        ud_txt = f'{target}-ud.txt'
        actual_ud_txt = os.path.join(workdir, ud_txt)
        expected_ud_txt = os.path.join(self.basedir, ud_txt)
        args = ['python3', '-m', 'memtrace.ud', '--verbose']
        sys.stderr.write('{}\n'.format(' '.join(args)))
        with open(actual_ud_txt, 'w') as fp:
            subprocess.check_call(args, stdout=fp, cwd=workdir)
        subprocess.check_call([
            'diff',
            '-au',
            expected_ud_txt,
            actual_ud_txt,
        ])

    def _format_value(self, value: bytes, endianness: str) -> str:
        if len(value) == 1:
            return hex(struct.unpack(endianness + 'B', value)[0])
        elif len(value) == 2:
            return hex(struct.unpack(endianness + 'H', value)[0])
        elif len(value) == 4:
            return hex(struct.unpack(endianness + 'I', value)[0])
        elif len(value) == 8:
            return hex(struct.unpack(endianness + 'Q', value)[0])
        else:
            return value.hex()

    def _format_entry(
            self, entry: Entry, endianness: str, disasm: Disasm) -> str:
        # This is a private reimplementation of the dumping logic, which tests
        # that all the properties are accessible in python.
        s = '[{:10}] '.format(entry.index)
        if isinstance(entry, LdStEntry):
            s += '0x{:016x}: {} uint{}_t [0x{:x}] {}'.format(
                entry.pc,
                get_tag_str(entry.tag),
                len(entry.value) * 8,
                entry.addr,
                self._format_value(bytes(entry.value), endianness),
            )
        elif isinstance(entry, InsnEntry):
            s += '0x{:016x}: {} {} {}'.format(
                entry.pc,
                get_tag_str(entry.tag),
                bytes(entry.value).hex(),
                disasm.disasm_str(entry.value, entry.pc),
            )
        elif isinstance(entry, InsnExecEntry):
            s += '0x{:016x}: {}'.format(entry.pc, get_tag_str(entry.tag))
        elif isinstance(entry, LdStNxEntry):
            s += '0x{:016x}: {} uint{}_t [0x{:x}]'.format(
                entry.pc,
                get_tag_str(entry.tag),
                len(entry.value) * 8,
                entry.addr,
            )
        elif isinstance(entry, MmapEntry):
            s += '{} {:016x}-{:016x} {}{}{} {}'.format(
                get_tag_str(entry.tag),
                entry.start,
                entry.end + 1,
                'r' if entry.flags & 1 else '-',
                'w' if entry.flags & 2 else '-',
                'x' if entry.flags & 4 else '-',
                entry.name,
            )
        else:
            self.fail()
        return s

    def _trace(self, workdir: str, target: str) -> None:
        dump_txt = f'{target}-dump.txt'
        actual_dump_txt = os.path.join(workdir, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        trace = Trace.load(os.path.join(workdir, 'memtrace.out'))
        endianness = trace.get_endianness()
        endianness_str = get_endianness_str(endianness)
        disasm = Disasm(
            trace.get_machine_type(),
            endianness,
            trace.get_word_size(),
        )
        insn_count = 0
        with open(actual_dump_txt, 'wb') as fp:
            fp.write('Endian            : {}\n'.format(
                endianness_str).encode())
            fp.write('Word              : {}\n'.format(
                'I' if trace.get_word_size() == 4 else 'Q').encode())
            fp.write('Word size         : {}\n'.format(
                trace.get_word_size()).encode())
            fp.write('Machine           : {}\n'.format(
                get_machine_type_str(trace.get_machine_type())).encode())
            rootdir_bytes = self.rootdir.encode()
            workdir_bytes = workdir.encode()
            for entry in trace:
                if isinstance(entry, InsnExecEntry):
                    insn_count += 1
                line_str = self._format_entry(entry, endianness_str, disasm)
                line = (line_str + '\n').encode()
                self._filter_line(fp, line, rootdir_bytes, workdir_bytes)
            fp.write('Insns             : {}\n'.format(insn_count).encode())
        subprocess.check_call([
            'diff',
            '-au',
            expected_dump_txt,
            actual_dump_txt,
        ])

    def _seek(self, workdir: str, target: str) -> None:
        seek_txt = f'{target}-seek.txt'
        actual_seek_txt = os.path.join(workdir, seek_txt)
        expected_seek_txt = os.path.join(self.basedir, seek_txt)
        trace = Trace.load(os.path.join(workdir, 'memtrace.out'))
        endianness = trace.get_endianness()
        endianness_str = get_endianness_str(endianness)
        disasm = Disasm(
            trace.get_machine_type(),
            endianness,
            trace.get_word_size(),
        )
        i = 0
        with open(actual_seek_txt, 'w') as fp:
            while True:
                try:
                    trace.seek_insn(i)
                except ValueError:
                    break
                entry = next(trace)
                entry_str = self._format_entry(entry, endianness_str, disasm)
                fp.write(entry_str + '\n')
                i += 1
        subprocess.check_call([
            'diff',
            '-au',
            expected_seek_txt,
            actual_seek_txt,
        ])


class TestX86_64(TestCommon):
    def setUp(self) -> None:
        if platform.machine() != 'x86_64':
            raise unittest.SkipTest('x86_64 only')
        super().setUp()
        self.target = 'x86_64'
        self.workdir = tempfile.TemporaryDirectory()
        self._compile(self.workdir.name, self.target)
        self._memtrace(self.workdir.name, self.target)

    def tearDown(self) -> None:
        self.workdir.cleanup()

    def test_dump(self) -> None:
        self._dump(self.workdir.name, self.target)

    def test_ud(self) -> None:
        self._ud(self.workdir.name, self.target)

    def test_trace(self) -> None:
        self._trace(self.workdir.name, self.target)

    def test_seek_insn(self) -> None:
        self._seek(self.workdir.name, self.target)


if __name__ == '__main__':
    unittest.main()
