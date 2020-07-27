#!/usr/bin/env python3
from glob import glob
import os
import signal
import subprocess
import sys


def popen(argv, **kwargs):
    basedir = os.path.dirname(os.path.realpath(__file__))
    uname = os.uname()
    tracer = os.path.join(
        basedir, 'tracer', f'{uname.sysname}-{uname.machine}')
    valgrind = os.path.join(tracer, 'bin', 'valgrind')
    valgrind_lib = os.path.join(tracer, 'lib', 'valgrind')
    env = {**kwargs.get('env', os.environ), 'VALGRIND_LIB': valgrind_lib}
    return subprocess.Popen(
        [
            valgrind,
            '--tool=memtrace',
            *argv,
        ],
        **kwargs,
        env=env,
    )


def main():
    p = popen(sys.argv[1:])
    while True:
        try:
            sys.exit(p.wait())
        except KeyboardInterrupt:
            p.send_signal(signal.SIGINT)
            continue


if __name__ == '__main__':
    main()
