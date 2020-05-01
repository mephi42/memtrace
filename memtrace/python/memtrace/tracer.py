#!/usr/bin/env python3
import os
import signal
import subprocess
import sys


def popen(argv, **kwargs):
    basedir = os.path.dirname(os.path.realpath(__file__))
    valgrind = os.path.join(basedir, 'tracer', 'bin', 'valgrind')
    valgrind_lib = os.path.join(basedir, 'tracer', 'lib', 'valgrind')
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


if __name__ == '__main__':
    p = popen(sys.argv[1:])
    while True:
        try:
            sys.exit(p.wait())
        except KeyboardInterrupt:
            p.send_signal(signal.SIGINT)
            continue
