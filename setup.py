import os

import skbuild

import memtrace

uname = os.uname()
skbuild.setup(
    name="memtrace",
    version=memtrace.__version__,
    author="mephi42",
    author_email="mephi42@gmail.com",
    description="Valgrind tool for tracing memory accesses",
    url="https://github.com/mephi42/memtrace",
    packages=[
        "memtrace",
        "memtrace_ext",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "click",
        "dataclasses; python_version < '3.7'",
        "sortedcontainers",
    ],
    package_data={
        "memtrace": [
            "memtrace.ipynb",
        ],
    },
    entry_points={
        "console_scripts": [
            "memtrace=memtrace.cli:main",
        ],
    },
)
