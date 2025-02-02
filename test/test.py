#!/usr/bin/env python3
from contextlib import contextmanager
import ctypes
from fcntl import fcntl
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import List
import unittest

import memtrace.cli
from memtrace.format import format_entry
from memtrace.symbolizer import Symbolizer
from memtrace.trace import Trace
import memtrace.tracer
from memtrace.ud import Ud
from memtrace._memtrace import Disasm, DumpKind, get_endianness_str, Tag, TraceIndex

ADDR_NO_RANDOMIZE = 0x0040000
F_SETPIPE_SZ = 1031


def diff_files(expected, actual):
    if "UPDATE_EXPECTATIONS" in os.environ:
        shutil.copyfile(actual, expected)
    subprocess.check_call(
        [
            "diff",
            "-au",
            expected,
            actual,
        ]
    )


@contextmanager
def timeit(s):
    t0 = time.time()
    try:
        yield
    finally:
        print("{} done in {:2f}s".format(s, time.time() - t0), file=sys.stderr)


def check_wait(p):
    returncode = p.wait()
    if returncode != 0:
        raise subprocess.CalledProcessError(returncode, p.args)


class CommonTest(unittest.TestCase):
    @staticmethod
    def get_cflags() -> List[str]:
        return [
            "-Wall",
            "-Wextra",
            "-Wconversion",
            "-pedantic",
            "-O3",
            "-gdwarf-4",
        ]

    @staticmethod
    def get_target() -> str:
        raise NotImplementedError()

    @staticmethod
    def get_source_ext() -> str:
        raise NotImplementedError()

    @staticmethod
    def get_input() -> bytes:
        return b"*"

    @classmethod
    def setUpClass(cls) -> None:
        cls.basedir = os.path.dirname(os.path.realpath(__file__))
        cls.pydir = os.path.dirname(os.path.realpath(memtrace.__file__))
        cls.workdir = tempfile.TemporaryDirectory()
        cls.trace_path = os.path.join(cls.workdir.name, "memtrace.out")
        cls._compile()
        cls._memtrace()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.workdir.cleanup()

    @classmethod
    def _compile(cls) -> None:
        path = os.path.join(cls.workdir.name, cls.get_target())
        args = [
            os.environ.get("CC", "cc"),
            "-o",
            path,
            *cls.get_cflags(),
            f"{cls.get_target()}{cls.get_source_ext()}",
        ]
        sys.stderr.write("{}\n".format(" ".join(args)))
        subprocess.check_call(args, cwd=cls.basedir)
        args = [os.environ.get("OBJDUMP", "objdump"), "-x", path]
        sys.stderr.write("{}\n".format(" ".join(args)))
        subprocess.check_call(args, cwd=cls.basedir)

    @classmethod
    def disable_aslr(cls):
        libc = ctypes.CDLL("libc.so.6")
        libc.personality(libc.personality(0xFFFFFFFF) | ADDR_NO_RANDOMIZE)

    @classmethod
    def memtrace_call(cls, fp):
        p = memtrace.tracer.popen(
            ["--trace-id=fedcba98765432100123456789abcdef", f"./{cls.get_target()}"],
            stdin=fp,
            stdout=subprocess.DEVNULL,
            cwd=cls.workdir.name,
            env={},
            preexec_fn=cls.disable_aslr,
        )
        check_wait(p)

    @classmethod
    def _memtrace(cls) -> None:
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(cls.get_input())
            fp.flush()
            fp.seek(0)
            with timeit("memtrace"):
                cls.memtrace_call(fp)
            trace_size = os.stat(cls.trace_path).st_size / (1024 * 1024 * 1024)
            print("trace size is {:2f}G".format(trace_size), file=sys.stderr)

    @classmethod
    def load_trace(cls):
        return Trace.load(cls.trace_path)


class MachineTest(CommonTest):
    @staticmethod
    def get_machines() -> List[str]:
        raise NotImplementedError()

    @classmethod
    def get_target(cls):
        return cls.get_machines()[0]

    @staticmethod
    def get_source_ext():
        return ".S"

    @classmethod
    def get_cflags(cls) -> List[str]:
        return super().get_cflags() + [
            "-nostdlib",
            "-static",
        ]

    @classmethod
    def setUpClass(cls) -> None:
        if cls == MachineTest:
            raise unittest.SkipTest("Subclasses only")
        machine = platform.machine()
        if machine not in cls.get_machines():
            raise unittest.SkipTest(f"{machine} not in {cls.get_machines()}")
        super().setUpClass()

    def _filter_line(
        self,
        fp,
        line: bytes,
        pydir: bytes,
        workdir: bytes,
        testdir: bytes,
    ) -> None:
        if pydir in line:
            return
        if b"[stack]" in line:
            return
        line = line.replace(workdir, b"{workdir}")
        line = line.replace(testdir, b"{testdir}")
        line = re.sub(b"(lea [^,]+, )[^ ]+ ptr ", b"\\g<1>", line)
        line = re.sub(b"^(MT_MMAP count=\\d+ size=)\\d+$", b"\\g<1>", line)
        fp.write(line)

    def filter_file(self, path):
        pydir_bytes = self.pydir.encode()
        workdir_bytes = self.workdir.name.encode()
        basedir_bytes = self.basedir.encode()
        done = False
        with tempfile.NamedTemporaryFile(prefix=path, delete=False) as tmpfp:
            try:
                with open(path, "rb") as fp:
                    for line in fp:
                        self._filter_line(
                            fp=tmpfp,
                            line=line,
                            pydir=pydir_bytes,
                            workdir=workdir_bytes,
                            testdir=basedir_bytes,
                        )
                os.rename(tmpfp.name, path)
                done = True
            finally:
                if not done:
                    os.unlink(tmpfp.name)

    def test_dump(self) -> None:
        dump_txt = f"{self.get_target()}-dump.txt"
        actual_dump_txt = os.path.join(self.workdir.name, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        with self.assertRaises(SystemExit):
            memtrace.cli.main(
                [
                    "report",
                    "--input=" + os.path.join(self.workdir.name, "memtrace.out"),
                    f"--output={actual_dump_txt}",
                ]
            )
        self.filter_file(actual_dump_txt)
        diff_files(expected_dump_txt, actual_dump_txt)

    def test_dump_srcline(self) -> None:
        dump_txt = f"{self.get_target()}-dump-srcline.txt"
        actual_dump_txt = os.path.join(self.workdir.name, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        with self.assertRaises(SystemExit):
            memtrace.cli.main(
                [
                    "report",
                    "--input=" + os.path.join(self.workdir.name, "memtrace.out"),
                    f"--output={actual_dump_txt}",
                    "--srcline",
                ]
            )
        self.filter_file(actual_dump_txt)
        diff_files(expected_dump_txt, actual_dump_txt)

    def test_dump_seq(self) -> None:
        dump_txt = f"{self.get_target()}-dump-seq.txt"
        actual_dump_txt = os.path.join(self.workdir.name, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        with self.assertRaises(SystemExit):
            memtrace.cli.main(
                [
                    "report",
                    "--input=" + os.path.join(self.workdir.name, "memtrace.out"),
                    f"--output={actual_dump_txt}",
                    "--insn-seq=1",
                    "--no-header",
                    "--no-summary",
                ]
            )
        self.filter_file(actual_dump_txt)
        diff_files(expected_dump_txt, actual_dump_txt)

    def test_ud(self) -> None:
        ud_txt = f"{self.get_target()}-ud.txt"
        actual_ud_txt = os.path.join(self.workdir.name, ud_txt)
        expected_ud_txt = os.path.join(self.basedir, ud_txt)
        with self.assertRaises(SystemExit) as system_exit:
            input = os.path.join(self.workdir.name, "memtrace.out")
            dot = os.path.join(self.workdir.name, "memtrace.dot")
            html = os.path.join(self.workdir.name, "memtrace.html")
            csv = os.path.join(self.workdir.name, "memtrace-{}.csv")
            memtrace.cli.main(
                [
                    "ud",
                    f"--input={input}",
                    f"--dot={dot}",
                    f"--html={html}",
                    f"--csv={csv}",
                    f"--log={actual_ud_txt}",
                ]
            )
        self.assertEqual(0, system_exit.exception.code)
        self.filter_file(actual_ud_txt)
        diff_files(expected_ud_txt, actual_ud_txt)

    def test_trace(self) -> None:
        dump_txt = f"{self.get_target()}-dump.txt"
        actual_dump_txt = os.path.join(self.workdir.name, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        trace = self.load_trace()
        endianness = trace.get_endianness()
        endianness_str = get_endianness_str(endianness)
        disasm = Disasm(
            trace.get_machine_type(),
            endianness,
            trace.get_word_size(),
        )
        insn_count = 0
        with open(actual_dump_txt, "wb") as fp:
            fp.write("Endian            : {}\n".format(endianness_str).encode())
            fp.write(
                "Word              : {}\n".format(
                    "I" if trace.get_word_size() == 4 else "Q"
                ).encode()
            )
            fp.write("Word size         : {}\n".format(trace.get_word_size()).encode())
            fp.write(
                "Machine           : {}\n".format(trace.get_machine_type()).encode()
            )
            fp.write("Regs size         : {}\n".format(trace.get_regs_size()).encode())
            fp.write(
                "Trace ID          : {}\n".format(
                    bytes(trace.get_trace_id()).hex()
                ).encode()
            )
            pydir_bytes = self.pydir.encode()
            workdir_bytes = self.workdir.name.encode()
            testdir_bytes = self.basedir.encode()
            for entry in trace:
                if entry.tag == Tag.MT_INSN_EXEC:
                    insn_count += 1
                line_str = format_entry(entry, endianness_str, disasm, trace)
                line = (line_str + "\n").encode()
                self._filter_line(
                    fp=fp,
                    line=line,
                    pydir=pydir_bytes,
                    workdir=workdir_bytes,
                    testdir=testdir_bytes,
                )
            fp.write("Insns             : {}\n".format(insn_count).encode())
        diff_files(expected_dump_txt, actual_dump_txt)

    def _seek(self, with_index: bool) -> None:
        seek_txt = f"{self.get_target()}-seek.txt"
        actual_seek_txt = os.path.join(self.workdir.name, seek_txt)
        expected_seek_txt = os.path.join(self.basedir, seek_txt)
        trace = self.load_trace()
        if with_index:
            memtrace_idx = os.path.join(self.workdir.name, "index-{}.bin")
            trace.build_insn_index(memtrace_idx)
        endianness = trace.get_endianness()
        endianness_str = get_endianness_str(endianness)
        disasm = Disasm(
            trace.get_machine_type(),
            endianness,
            trace.get_word_size(),
        )
        i = 1  # kFirstTraceIndex
        with open(actual_seek_txt, "w") as fp:
            while True:
                try:
                    trace.seek_insn(TraceIndex(i))
                except RuntimeError as exc:
                    self.assertEqual(
                        "_Trace.seek_insn() failed: Invalid argument", str(exc)
                    )
                    break
                entry = next(trace)
                entry_str = format_entry(entry, endianness_str, disasm, trace)
                fp.write(entry_str + "\n")
                i += 1
        diff_files(expected_seek_txt, actual_seek_txt)

    def test_seek_insn(self) -> None:
        self._seek(with_index=False)

    def test_seek_insn_with_index(self) -> None:
        self._seek(with_index=True)

    def test_taint(self) -> None:
        taint_org = f"{self.get_target()}-taint.org"
        actual = os.path.join(self.workdir.name, taint_org)
        expected = os.path.join(self.basedir, taint_org)
        with self.assertRaises(SystemExit) as system_exit:
            input = os.path.join(self.workdir.name, "memtrace.out")
            memtrace.cli.main(
                [
                    "taint-backward",
                    f"--input={input}",
                    f"--output={actual}",
                    "--pc=_taintme",
                    "--depth=9",
                ]
            )
        self.assertEqual(0, system_exit.exception.code)
        self.filter_file(actual)
        diff_files(expected, actual)

    def test_stats(self) -> None:
        stats_txt = f"{self.get_target()}-stats.txt"
        actual_stats_txt = os.path.join(self.workdir.name, stats_txt)
        expected_stats_txt = os.path.join(self.basedir, stats_txt)
        with self.assertRaises(SystemExit) as system_exit:
            input = os.path.join(self.workdir.name, "memtrace.out")
            memtrace.cli.main(
                [
                    "stats",
                    f"--input={input}",
                    f"--output={actual_stats_txt}",
                ]
            )
        self.assertEqual(0, system_exit.exception.code)
        self.filter_file(actual_stats_txt)
        diff_files(expected_stats_txt, actual_stats_txt)

    def test_traces_for_pc(self) -> None:
        traces_for_pc = f"{self.get_target()}-traces-for-pc.txt"
        actual = os.path.join(self.workdir.name, traces_for_pc)
        expected = os.path.join(self.basedir, traces_for_pc)
        with self.assertRaises(SystemExit) as system_exit:
            input = os.path.join(self.workdir.name, "memtrace.out")
            memtrace.cli.main(
                [
                    "traces-for-pc",
                    f"--input={input}",
                    f"--output={actual}",
                    "_taintme",
                ]
            )
        self.assertEqual(0, system_exit.exception.code)
        self.filter_file(actual)
        diff_files(expected, actual)

    def test_ldst(self) -> None:
        dump_txt = f"{self.get_target()}-ldst.txt"
        actual_dump_txt = os.path.join(self.workdir.name, dump_txt)
        expected_dump_txt = os.path.join(self.basedir, dump_txt)
        with self.assertRaises(SystemExit):
            memtrace.cli.main(
                [
                    "ldst",
                    "--input=" + os.path.join(self.workdir.name, "memtrace.out"),
                    f"--output={actual_dump_txt}",
                    "0-0xffffffffffffffff",
                ]
            )
        self.filter_file(actual_dump_txt)
        diff_files(expected_dump_txt, actual_dump_txt)


class TestX86_64(MachineTest):
    @staticmethod
    def get_machines() -> List[str]:
        return ["x86_64"]

    @classmethod
    def get_cflags(cls) -> List[str]:
        return super().get_cflags() + [
            "-m64",
            "-Wl,--build-id=none",
            "-Wl,--script=x86_64.lds",
        ]


class TestI386(MachineTest):
    @staticmethod
    def get_machines() -> List[str]:
        return ["i386", "i686", "x86_64"]

    @classmethod
    def get_cflags(cls) -> List[str]:
        return super().get_cflags() + [
            "-m32",
            "-Wl,--build-id=none",
            "-Wl,--script=i386.lds",
        ]


class TestCat(CommonTest):
    @staticmethod
    def get_target() -> str:
        return "cat"

    @staticmethod
    def get_source_ext() -> str:
        return ".c"

    @staticmethod
    def get_input() -> bytes:
        return bytes(range(256)) * ((64 * 1024 + 256) // 256)

    @classmethod
    def memtrace_call(cls, fp):
        p = memtrace.tracer.popen(
            [f"./{cls.get_target()}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            cwd=cls.workdir.name,
        )
        try:
            expected = cls.get_input()
            # Check that TLV chunking works by increasing the pipe capacity,
            # so that it exceeds the maximum TLV length. This will allow
            # individual read() calls in cat.c to return that much data.
            fcntl(p.stdin.fileno(), F_SETPIPE_SZ, 128 * 1024)
            p.stdin.write(expected)
            p.stdin.flush()
            actual = bytearray()
            while len(actual) < len(expected):
                chunk = p.stdout.read(len(expected) - len(actual))
                if chunk == b"":
                    raise RuntimeError("Premature EOF")
                actual.extend(chunk)
            if actual != expected:
                raise RuntimeError("cat produced malformed output")
            p.send_signal(signal.SIGINT)
        finally:
            p.wait()
            p.stdin.close()
            p.stdout.close()

    def test(self):
        trace = self.load_trace()
        with timeit("index"):
            with tempfile.TemporaryDirectory() as tmp:
                trace.build_insn_index(os.path.join(tmp, "{}"))
        with timeit("ud"):
            ud = Ud.analyze(None, trace)
        self.assertIsNotNone(ud)
        expected = self.get_input()
        cat_buf = bytearray(len(expected))
        with Symbolizer(trace) as symbolizer:
            self.assertIsNone(symbolizer.resolve("cat_buf"))
            trace.seek_end()
            cat_buf_start = symbolizer.resolve("cat_buf")
            self.assertIsNotNone(cat_buf_start)
            trace.seek_start()
        cat_buf_end = cat_buf_start + len(cat_buf)
        for entry in trace:
            if entry.tag == Tag.MT_STORE and cat_buf_start <= entry.addr < cat_buf_end:
                value = entry.value
                end = entry.addr + len(value)
                self.assertLessEqual(end, cat_buf_end)
                offset = entry.addr - cat_buf_start
                cat_buf[offset : offset + len(value)] = value
        self.assertEqual(expected, cat_buf)

    def test_dump_srcline(self):
        trace = self.load_trace()
        with timeit("index"):
            with tempfile.TemporaryDirectory() as tmp:
                trace.build_insn_index(os.path.join(tmp, "{}"))
        with timeit("dump-srcline"):
            trace.dump(
                os.path.join(self.workdir.name, "dump-srcline.txt"),
                DumpKind.Source,
            )


if __name__ == "__main__":
    unittest.main()
