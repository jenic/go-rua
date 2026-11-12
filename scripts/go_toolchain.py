#!/usr/bin/env python3
"""Run Go with the exact toolchain declared by this checkout's go.mod.

Standard library only: this must work before Go or module dependencies are ready.
"""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def declared_toolchain(root=ROOT):
    declarations = []
    for line in (root / "go.mod").read_text(encoding="utf-8").splitlines():
        fields = line.split("//", 1)[0].split()
        if fields and fields[0] == "toolchain":
            declarations.append(fields)
    if len(declarations) != 1 or len(declarations[0]) != 2:
        raise ValueError("go.mod must contain exactly one explicit toolchain go1.X.Y directive")
    version = declarations[0][1]
    if not re.fullmatch(r"go1\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise ValueError("go.mod toolchain must be a stable go1.X.Y version; default and switching suffixes are unsupported")
    return version


def toolchain_env(version, root=ROOT, installed=False):
    env = dict(os.environ)
    requested = env.get("GOTOOLCHAIN")
    # setup-go exports local. Installed checks deliberately disable switching
    # and verify the compiler itself; execution must still use the exact pin.
    if requested and requested != version and not (installed and requested == "local"):
        raise ValueError(f"GOTOOLCHAIN={requested!r} conflicts with go.mod toolchain {version}; unset it or use {version}")
    env.update(GOTOOLCHAIN=version, GOWORK="off")
    for name, directory in (("GOPATH", ".gopath"), ("GOCACHE", ".gocache"),
                            ("GOMODCACHE", ".gomodcache")):
        if not env.get(name):
            env[name] = str(root / directory)
    return env


def check_version(go, version, env, installed=False):
    probe_env = dict(env, GOTOOLCHAIN="local") if installed else env
    result = subprocess.run([go, "env", "GOVERSION"], env=probe_env,
                            text=True, stdout=subprocess.PIPE)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, [go, "env", "GOVERSION"])
    actual = result.stdout.strip()
    if actual != version:
        raise ValueError(f"compiler {actual!r} does not match go.mod toolchain {version}")
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    commands.add_parser("print", help="print the exact go.mod toolchain without invoking Go")
    installed = commands.add_parser("check-installed", help="verify the installed compiler without switching")
    installed.add_argument("--go", default=os.environ.get("GO") or "go")
    installed.add_argument("--github-env", action="store_true",
                           help="export the verified exact toolchain for later GitHub Actions steps")
    execute = commands.add_parser("exec", help="verify and execute Go with the exact declared toolchain")
    execute.add_argument("go")
    execute.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        version = declared_toolchain()
        if args.mode == "print":
            print(version)
            return
        env = toolchain_env(version, installed=args.mode == "check-installed")
        check_version(args.go, version, env, installed=args.mode == "check-installed")
        if args.mode == "check-installed":
            if args.github_env:
                env_file = os.environ.get("GITHUB_ENV")
                if not env_file:
                    raise ValueError("--github-env requires the GITHUB_ENV environment file")
                with Path(env_file).open("a", encoding="utf-8") as destination:
                    destination.write(f"GOTOOLCHAIN={version}\n")
            print(f"go.mod toolchain: {version}; installed compiler: {version}")
            return
        os.execvpe(args.go, [args.go, *args.arguments], env)
    except subprocess.CalledProcessError as error:
        print("toolchain: unable to run the declared compiler; install or cache the exact go.mod toolchain", file=sys.stderr)
        sys.exit(error.returncode if error.returncode > 0 else 128 - error.returncode)
    except (OSError, ValueError) as error:
        parser.exit(1, f"toolchain: {error}\n")


if __name__ == "__main__":
    main()
