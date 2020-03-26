#!/usr/bin/env python3
import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest

from memtrace_ext import Disasm, get_endianness_str, get_tag_str, \
    get_machine_type_str, InsnEntry, InsnExecEntry, LdStEntry, \
    LdStNxEntry, MmapEntry, Trace


class Test(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.basedir = os.path.dirname(os.path.realpath(__file__))
        pythondir = os.path.dirname(self.basedir)
        memtracedir = os.path.dirname(pythondir)
        self.rootdir = os.path.dirname(memtracedir)
        self.vg_in_place = os.path.join(self.rootdir, 'vg-in-place')

    def _compile(self, workdir, target):
        args = [
            'cc',
            '-o', os.path.join(workdir, target),
            '-nostdlib',
            f'{target}.S',
        ]
        sys.stderr.write('{}\n'.format(' '.join(args)))
        subprocess.check_call(args, cwd=self.basedir)

    def _memtrace(self, workdir, target):
        args = [
            self.vg_in_place,
            '--tool=memtrace',
            '--pc-range=0-0xffffffffffffffff:imr',
            f'./{target}',
        ]
        sys.stderr.write('{}\n'.format(' '.join(args)))
        subprocess.check_call(args, cwd=workdir)

    def _filter_line(self, fp, line, rootdir_bytes, workdir_bytes):
        if rootdir_bytes in line:
            return
        if b'[stack]' in line:
            return
        line = line.replace(workdir_bytes, b'{workdir}')
        fp.write(line)

    def _dump(self, workdir, target):
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

    def _ud(self, workdir, target):
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

    def _format_value(self, value, endianness):
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

    def _format_entry(self, entry, endianness, disasm):
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

    def _trace(self, workdir, target):
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

    def _test_memtrace(self, target):
        with tempfile.TemporaryDirectory() as workdir:
            self._compile(workdir, target)
            self._memtrace(workdir, target)
            self._dump(workdir, target)
            self._ud(workdir, target)
            self._trace(workdir, target)

    @unittest.skipIf(platform.machine() != 'x86_64', 'x86_64 only')
    def test_memtrace_x86_64(self):
        self._test_memtrace('x86_64')


if __name__ == '__main__':
    unittest.main()
