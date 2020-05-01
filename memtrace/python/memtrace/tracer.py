#!/usr/bin/env python3
import os
import subprocess
import sys


def main(argv, **kwargs):
    basedir = os.path.dirname(os.path.realpath(__file__))
    valgrind = os.path.join(basedir, 'tracer', 'bin', 'valgrind')
    valgrind_lib = os.path.join(basedir, 'tracer', 'lib', 'valgrind')
    env = {**kwargs.get('env', os.environ), 'VALGRIND_LIB': valgrind_lib}
    subprocess.check_call(
        [
            valgrind,
            '--tool=memtrace',
            *argv,
        ],
        **kwargs,
        env=env,
    )


if __name__ == '__main__':
    main(sys.argv[1:])
