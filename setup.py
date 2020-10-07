import os
import setuptools

import skbuild

uname = os.uname()
memtrace = os.path.join(os.path.dirname(__file__), 'memtrace')
tracer_dir = os.path.join(
    memtrace, 'tracer', f'{uname.sysname}-{uname.machine}')
tracer_files = []
for dirpath, dirnames, filenames in os.walk(tracer_dir):
    dirpath = os.path.relpath(dirpath, memtrace)
    tracer_files.extend(
        os.path.join(dirpath, filename) for filename in filenames)
skbuild.setup(
    name='memtrace',
    version='0.1.0',
    author='mephi42',
    author_email='mephi42@gmail.com',
    description='Valgrind tool for tracing memory accesses',
    url='https://github.com/mephi42/memtrace',
    packages=setuptools.find_packages(exclude=('test',)),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=[
        'dataclasses; python_version < \'3.7\'',
        'sortedcontainers',
    ],
    package_data={
        'memtrace': tracer_files,
    },
    entry_points={
        'console_scripts': [
            'memtrace=memtrace.tracer:main',
            'memtrace-analyze=memtrace.analysis:main',
            'memtrace-dump=memtrace.dump:main',
            'memtrace-index=memtrace.index:main',
            'memtrace-stats=memtrace.stats:main',
            'memtrace-ud=memtrace.ud:main',
        ],
    },
)
