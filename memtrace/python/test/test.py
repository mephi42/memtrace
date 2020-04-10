#!/usr/bin/env python3
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from typing import List
import unittest

from memtrace.analysis import Analysis
from memtrace.format import format_entry
import memtrace.stats as stats
from memtrace.symbolizer import Symbolizer
from memtrace.taint import BackwardAnalysis
from memtrace_ext import Disasm, get_endianness_str, get_machine_type_str, \
    Tag, Trace


def diff_files(expected, actual):
    if 'UPDATE_EXPECTATIONS' in os.environ:
        shutil.copyfile(actual, expected)
    subprocess.check_call([
        'diff',
        '-au',
        expected,
        actual,
    ])


class CommonTest(unittest.TestCase):
    @staticmethod
    def get_cflags() -> List[str]:
        return [
            '-Wall',
            '-Wextra',
            '-Wconversion',
            '-pedantic',
            '-O3',
        ]

    @staticmethod
    def get_target() -> str:
        raise NotImplementedError()

    @staticmethod
    def get_source_ext() -> str:
        raise NotImplementedError()

    @staticmethod
    def get_input() -> bytes:
        return b'*'

    @classmethod
    def setUpClass(cls) -> None:
        cls.basedir = os.path.dirname(os.path.realpath(__file__))
        pythondir = os.path.dirname(cls.basedir)
        memtracedir = os.path.dirname(pythondir)
        cls.rootdir = os.path.dirname(memtracedir)
        cls.vg_in_place = os.path.join(cls.rootdir, 'vg-in-place')
        cls.workdir = tempfile.TemporaryDirectory()
        cls._compile()
        cls._memtrace()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.workdir.cleanup()

    @classmethod
    def _compile(cls) -> None:
        args = [
            'cc',
            '-o', os.path.join(cls.workdir.name, cls.get_target()),
            *cls.get_cflags(),
            f'{cls.get_target()}{cls.get_source_ext()}',
        ]
        sys.stderr.write('{}\n'.format(' '.join(args)))
        subprocess.check_call(args, cwd=cls.basedir)

    @classmethod
    def _memtrace(cls) -> None:
        args = [
            cls.vg_in_place,
            '--tool=memtrace',
            f'./{cls.get_target()}',
        ]
        sys.stderr.write('{}\n'.format(' '.join(args)))
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(cls.get_input())
            fp.flush()
            fp.seek(0)
            subprocess.check_call(
                args,
                stdin=fp,
                stdout=subprocess.DEVNULL,
                cwd=cls.workdir.name,
            )


class MachineTest(CommonTest):
    @staticmethod
    def get_machines() -> List[str]:
        raise NotImplementedError()

    @classmethod
    def get_target(cls):
        return cls.get_machines()[0]

    @staticmethod
    def get_source_ext():
        return '.S'

    @classmethod
    def get_cflags(cls) -> List[str]:
        return super().get_cflags() + [
            '-nostdlib',
            '-static',
        ]

    @classmethod
    def setUpClass(cls) -> None:
        if cls == MachineTest:
            raise unittest.SkipTest('Subclasses only')
        if platform.machine() not in cls.get_machines():
            raise unittest.SkipTest(f'{cls.get_machines()} only')
        super().setUpClass()

    def _filter_line(
            self, fp, line: bytes, rootdir: bytes, workdir: bytes) -> None:
        if rootdir in line:
            return
        if b'[stack]' in line:
            return
        line = line.replace(workdir, b'{workdir}')
        line = re.sub(b'(lea [^,]+, )[^ ]+ ptr ', b'\\g<1>', line)
        fp.write(line)

    def check_call_filtered(self, args, workdir, output_path):
        p = subprocess.Popen(args, stdout=subprocess.PIPE, cwd=workdir)
        try:
            with open(output_path, 'wb') as fp:
                rootdir_bytes = self.rootdir.encode()
                workdir_bytes = workdir.encode()
                for line in p.stdout:
                    self._filter_line(fp, line, rootdir_bytes, workdir_bytes)
        finally:
            p.stdout.close()
            returncode = p.wait()
            if returncode != 0:
                raise subprocess.CalledProcessError(returncode, args)

    def test_dump(self) -> None:
        dump_txt = f'{self.get_target()}-dump.txt'
        actual_dump_txt = os.path.join(self.workdir.name, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        args = ['python3', '-m', 'memtrace.dump']
        sys.stderr.write('{}\n'.format(' '.join(args)))
        self.check_call_filtered(args, self.workdir.name, actual_dump_txt)
        diff_files(expected_dump_txt, actual_dump_txt)

    def test_ud(self) -> None:
        ud_txt = f'{self.get_target()}-ud.txt'
        actual_ud_txt = os.path.join(self.workdir.name, ud_txt)
        expected_ud_txt = os.path.join(self.basedir, ud_txt)
        args = ['python3', '-m', 'memtrace.ud', '--verbose']
        sys.stderr.write('{}\n'.format(' '.join(args)))
        self.check_call_filtered(args, self.workdir.name, actual_ud_txt)
        diff_files(expected_ud_txt, actual_ud_txt)

    def test_trace(self) -> None:
        dump_txt = f'{self.get_target()}-dump.txt'
        actual_dump_txt = os.path.join(self.workdir.name, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        trace = Trace.load(os.path.join(self.workdir.name, 'memtrace.out'))
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
            workdir_bytes = self.workdir.name.encode()
            for entry in trace:
                if entry.tag == Tag.MT_INSN_EXEC:
                    insn_count += 1
                line_str = format_entry(entry, endianness_str, disasm)
                line = (line_str + '\n').encode()
                self._filter_line(fp, line, rootdir_bytes, workdir_bytes)
            fp.write('Insns             : {}\n'.format(insn_count).encode())
        diff_files(expected_dump_txt, actual_dump_txt)

    def _seek(self, with_index: bool) -> None:
        seek_txt = f'{self.get_target()}-seek.txt'
        actual_seek_txt = os.path.join(self.workdir.name, seek_txt)
        expected_seek_txt = os.path.join(self.basedir, seek_txt)
        trace = Trace.load(os.path.join(self.workdir.name, 'memtrace.out'))
        if with_index:
            memtrace_idx = os.path.join(self.workdir.name, 'memtrace.idx')
            trace.build_insn_index(memtrace_idx, 2)
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
        diff_files(expected_seek_txt, actual_seek_txt)

    def test_seek_insn(self) -> None:
        self._seek(with_index=False)

    def test_seek_insn_with_index(self) -> None:
        self._seek(with_index=True)

    def test_taint(self) -> None:
        taint_pc_txt = os.path.join(
            self.basedir, f'{self.get_target()}-taint-pc.txt')
        taint_org = f'{self.get_target()}-taint.org'
        actual_taint_org = os.path.join(self.workdir.name, taint_org)
        expected_taint_org = os.path.join(self.basedir, taint_org)
        with open(taint_pc_txt) as fp:
            pc = int(fp.read(), 0)
        with Analysis(
                trace_path=os.path.join(self.workdir.name, 'memtrace.out'),
        ) as analysis:
            backward = BackwardAnalysis(
                analysis=analysis,
                trace_index0=analysis.get_last_trace_for_pc(pc),
                depth=9,
            )
            dag = backward.analyze()
            with open(actual_taint_org, 'w') as fp:
                dag.pp(analysis, fp)
        diff_files(expected_taint_org, actual_taint_org)

    def test_stats(self) -> None:
        stats_txt = f'{self.get_target()}-stats.txt'
        actual_stats_txt = os.path.join(self.workdir.name, stats_txt)
        expected_stats_txt = os.path.join(self.basedir, stats_txt)
        result = stats.from_trace_file(
            os.path.join(self.workdir.name, 'memtrace.out'))
        with open(actual_stats_txt, 'w') as fp:
            stats.pp(result, fp)
        diff_files(expected_stats_txt, actual_stats_txt)


class TestX86_64(MachineTest):
    @staticmethod
    def get_machines() -> List[str]:
        return ['x86_64']

    @classmethod
    def get_cflags(cls) -> List[str]:
        return super().get_cflags() + ['-m64']


class TestI386(MachineTest):
    @staticmethod
    def get_machines() -> List[str]:
        return ['i386', 'x86_64']

    @classmethod
    def get_cflags(cls) -> List[str]:
        return super().get_cflags() + ['-m32']


class TestCat(CommonTest):
    @staticmethod
    def get_target() -> str:
        return 'cat'

    @staticmethod
    def get_source_ext() -> str:
        return '.c'

    @staticmethod
    def get_input() -> bytes:
        return bytes(range(256)) * (128 * 1024 // 256)

    def test(self):
        trace = Trace.load(os.path.join(self.workdir.name, 'memtrace.out'))
        cat_buf = bytearray(128 * 1024)
        with Symbolizer(trace.get_mmap_entries()) as symbolizer:
            cat_buf_start = symbolizer.resolve('cat_buf')
        self.assertIsNotNone(cat_buf_start)
        cat_buf_end = cat_buf_start + len(cat_buf)
        for entry in trace:
            if (entry.tag == Tag.MT_STORE and
                    cat_buf_start <= entry.addr < cat_buf_end):
                value = entry.value
                end = entry.addr + len(value)
                self.assertLessEqual(end, cat_buf_end)
                offset = entry.addr - cat_buf_start
                cat_buf[offset:offset + len(value)] = value
        self.assertEqual(self.get_input(), cat_buf)


if __name__ == '__main__':
    unittest.main()
