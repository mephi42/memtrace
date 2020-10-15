#!/usr/bin/env python3
import os
import subprocess


def popen(argv, **kwargs):
    basedir = os.path.dirname(os.path.realpath(__file__))
    uname = os.uname()
    tracer = os.path.join(
        basedir, 'tracer', f'{uname.sysname}-{uname.machine}')
    valgrind = os.path.join(tracer, 'bin', 'valgrind')
    valgrind_lib = os.path.join(tracer, 'lib', 'valgrind')
    kwargs['env'] = kwargs.get('env', os.environ).copy()
    kwargs['env']['VALGRIND_LIB'] = valgrind_lib
    return subprocess.Popen(
        [
            valgrind,
            '--tool=memtrace',
            *argv,
        ],
        **kwargs,
    )
