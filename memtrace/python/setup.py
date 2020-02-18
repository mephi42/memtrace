import setuptools


setuptools.setup(
    name='memtrace',
    version='0.0.4',
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
)
