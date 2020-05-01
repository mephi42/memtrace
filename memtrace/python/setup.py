import setuptools

import skbuild

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
    include_package_data=True,
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
