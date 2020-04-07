#!/usr/bin/env python3
import os
import platform
import subprocess
import sys
import tempfile
import unittest

from memtrace.format import format_entry
import memtrace.stats as stats
import memtrace.taint as taint
from memtrace_ext import Disasm, get_endianness_str, get_machine_type_str, \
    InsnExecEntry, Trace


class TestCommon(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target = cls.machines[0]
        if platform.machine() not in cls.machines:
            raise unittest.SkipTest(f'{cls.machines} only')
        cls.basedir = os.path.dirname(os.path.realpath(__file__))
        pythondir = os.path.dirname(cls.basedir)
        memtracedir = os.path.dirname(pythondir)
        cls.rootdir = os.path.dirname(memtracedir)
        cls.vg_in_place = os.path.join(cls.rootdir, 'vg-in-place')
        cls.workdir = tempfile.TemporaryDirectory()
        cls._compile(cls.workdir.name, cls.target)
        cls._memtrace(cls.workdir.name, cls.target)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.workdir.cleanup()

    @classmethod
    def _compile(cls, workdir: str, target: str) -> None:
        args = [
            'cc',
            '-o', os.path.join(workdir, target),
            '-nostdlib',
            '-static',
            *cls.cflags,
            f'{target}.S',
        ]
        sys.stderr.write('{}\n'.format(' '.join(args)))
        subprocess.check_call(args, cwd=cls.basedir)

    @classmethod
    def _memtrace(cls, workdir: str, target: str) -> None:
        args = [
            cls.vg_in_place,
            '--tool=memtrace',
            '--pc-range=0-0xffffffffffffffff:imr',
            f'./{target}',
        ]
        sys.stderr.write('{}\n'.format(' '.join(args)))
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(b'*')
            fp.flush()
            fp.seek(0)
            subprocess.check_call(args, stdin=fp, cwd=workdir)

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
            p.stdout.close()
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
                line_str = format_entry(entry, endianness_str, disasm)
                line = (line_str + '\n').encode()
                self._filter_line(fp, line, rootdir_bytes, workdir_bytes)
            fp.write('Insns             : {}\n'.format(insn_count).encode())
        subprocess.check_call([
            'diff',
            '-au',
            expected_dump_txt,
            actual_dump_txt,
        ])

    def _seek(self, workdir: str, target: str, with_index: bool) -> None:
        seek_txt = f'{target}-seek.txt'
        actual_seek_txt = os.path.join(workdir, seek_txt)
        expected_seek_txt = os.path.join(self.basedir, seek_txt)
        trace = Trace.load(os.path.join(workdir, 'memtrace.out'))
        if with_index:
            trace.build_insn_index(os.path.join(workdir, 'memtrace.idx'), 2)
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
                entry_str = format_entry(entry, endianness_str, disasm)
                fp.write(entry_str + '\n')
                i += 1
        subprocess.check_call([
            'diff',
            '-au',
            expected_seek_txt,
            actual_seek_txt,
        ])

    def _taint(self, workdir, target):
        taint_pc_txt = os.path.join(self.basedir, f'{target}-taint-pc.txt')
        taint_txt = f'{target}-taint.txt'
        actual_taint_txt = os.path.join(workdir, taint_txt)
        expected_taint_txt = os.path.join(self.basedir, taint_txt)
        backward = taint.Backward.from_trace_file(
            os.path.join(workdir, 'memtrace.out'))
        with open(taint_pc_txt) as fp:
            pc = int(fp.read(), 0)
        dag = backward.analyze(pc)
        with open(actual_taint_txt, 'w') as fp:
            dag.pp(backward, fp)
        subprocess.check_call([
            'diff',
            '-au',
            expected_taint_txt,
            actual_taint_txt,
        ])

    def _stats(self, workdir, target):
        stats_txt = f'{target}-stats.txt'
        actual_stats_txt = os.path.join(workdir, stats_txt)
        expected_stats_txt = os.path.join(self.basedir, stats_txt)
        result = stats.from_trace_file(
            os.path.join(workdir, 'memtrace.out'))
        with open(actual_stats_txt, 'w') as fp:
            stats.pp(result, fp)
        subprocess.check_call([
            'diff',
            '-au',
            expected_stats_txt,
            actual_stats_txt,
        ])


class TestX86_64(TestCommon):
    machines = ['x86_64']
    cflags = []

    def test_dump(self) -> None:
        self._dump(self.workdir.name, self.target)

    def test_ud(self) -> None:
        self._ud(self.workdir.name, self.target)

    def test_trace(self) -> None:
        self._trace(self.workdir.name, self.target)

    def test_seek_insn(self) -> None:
        self._seek(self.workdir.name, self.target, with_index=False)

    def test_seek_insn_with_index(self) -> None:
        self._seek(self.workdir.name, self.target, with_index=True)

    def test_taint(self) -> None:
        self._taint(self.workdir.name, self.target)

    def test_stats(self) -> None:
        self._stats(self.workdir.name, self.target)


class TestI386(TestCommon):
    machines = ['i386', 'x86_64']
    cflags = ['-m32']

    def test_dump(self) -> None:
        self._dump(self.workdir.name, self.target)

    def test_ud(self) -> None:
        self._ud(self.workdir.name, self.target)

    def test_trace(self) -> None:
        self._trace(self.workdir.name, self.target)

    def test_seek_insn(self) -> None:
        self._seek(self.workdir.name, self.target, with_index=False)

    def test_seek_insn_with_index(self) -> None:
        self._seek(self.workdir.name, self.target, with_index=True)

    def test_taint(self) -> None:
        self._taint(self.workdir.name, self.target)

    def test_stats(self) -> None:
        self._stats(self.workdir.name, self.target)


if __name__ == '__main__':
    unittest.main()
