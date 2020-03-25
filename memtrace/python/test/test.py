#!/usr/bin/env python3
import os
import platform
import subprocess
import sys
import tempfile
import unittest

from memtrace_ext import Trace


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
                    if rootdir_bytes in line:
                        continue
                    if b'[stack]' in line:
                        continue
                    line = line.replace(workdir_bytes, b'{workdir}')
                    fp.write(line)
        finally:
            returncode = p.wait()
            if returncode != 0:
                raise subprocess.CalledProcessError(returncode, args)
        subprocess.check_call([
            'diff',
            '-u',
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
            '-u',
            expected_ud_txt,
            actual_ud_txt,
        ])

    def _trace(self, workdir):
        Trace.load(os.path.join(workdir, 'memtrace.out'))

    def _test_memtrace(self, target):
        with tempfile.TemporaryDirectory() as workdir:
            self._compile(workdir, target)
            self._memtrace(workdir, target)
            self._dump(workdir, target)
            self._ud(workdir, target)
            self._trace(workdir)

    @unittest.skipIf(platform.machine() != 'x86_64', 'x86_64 only')
    def test_memtrace_x86_64(self):
        self._test_memtrace('x86_64')


if __name__ == '__main__':
    unittest.main()
