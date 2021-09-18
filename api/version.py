import subprocess  # noqa: S404
from collections import namedtuple

Version = namedtuple("Version", ["commit", "branch", "description"])

cmd = "(git rev-parse HEAD && (git symbolic-ref --short HEAD || echo) && git describe --tags --always) 2> /dev/null"


def get_version() -> Version:
    return Version(*subprocess.getoutput(cmd + " || cat VERSION").splitlines())


if __name__ == "__main__":
    print(subprocess.getoutput(cmd + " | tee VERSION"))
