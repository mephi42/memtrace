from configparser import ConfigParser
import os
import shlex


class Config:
    def __init__(self):
        self.arches = []
        self.pythons = []


ARCH_PREFIX = "arch."
COMMIT_PREFIX = "commit."
PYTHON_PREFIX = "python."


def load_config():
    basedir = os.path.dirname(__file__)
    config = ConfigParser()
    config.read(os.path.join(basedir, "images.ini"))
    result = Config()
    commits = {}
    for section_name in config.sections():
        section = config[section_name]
        if section_name.startswith(ARCH_PREFIX):
            arch = section_name[len(ARCH_PREFIX) :]
            result.arches.append((arch, section["triple"]))
        elif section_name.startswith(COMMIT_PREFIX):
            commits[section_name[len(COMMIT_PREFIX) :]] = section["id"]
        elif section_name.startswith(PYTHON_PREFIX):
            result.pythons.append(
                (
                    section_name[len(PYTHON_PREFIX) :],
                    section["name_tag"],
                    section["git_tag"],
                    shlex.split(section.get("configure_flags", ""))
                    + ["--enable-shared"],
                    section["includes"],
                    [
                        commits[commit_name]
                        for commit_name in section.get("commits", "").split()
                    ],
                )
            )
        else:
            raise RuntimeError("Unsupported section: {}".format(section_name))
    return result
