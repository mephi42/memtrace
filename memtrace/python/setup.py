import setuptools
import sys

setuptools.setup(
    name='memtrace',
    version='0.0.8',
    author='mephi42',
    author_email='mephi42@gmail.com',
    description='memtrace post-processing scripts',
    url='https://github.com/mephi42/memtrace',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    ext_modules=[
        setuptools.Extension(
            'memtrace_ext',
            sources=['memtrace_ext/memtrace_ext.cpp'],
            libraries=[
                ('boost_python' +
                 str(sys.version_info[0]) +
                 str(sys.version_info[1])),
                'capstone',
            ],
            extra_compile_args=[
                '-std=c++17',
                '-Wextra',
                '-Wconversion',
                '-pedantic',
            ],
        )
    ],
    install_requires=[
        'dataclasses',
    ],
)
