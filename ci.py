import subprocess


def git_ls_files():
    p = subprocess.Popen(["git", "ls-files"], stdout=subprocess.PIPE)
    try:
        for line in p.stdout:
            yield line.strip().decode()
    finally:
        if p.wait() != 0:
            raise subprocess.CalledProcessError(p.returncode, p.args)


def git_ls_py_files():
    for path in git_ls_files():
        if path.endswith(".py"):
            yield path
        else:
            try:
                with open(path, "rb") as fp:
                    if (
                        fp.read(2) == b"#!"
                        and fp.readline() == b"/usr/bin/env python3\n"
                    ):
                        yield path
            except (FileNotFoundError, IsADirectoryError):
                pass
