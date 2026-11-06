#!/usr/bin/env python3
"""Runs the fast contract files in parallel against one database.

Usage: fast.py [--workers N] BINARY [CONTRACT ...] with
RS_KEYCLOAK_DATABASE_URL set to a migrated database. Without contract names, every *_contract.py file runs
except the slow Docker-backed ones. Each file starts its own server on a
free port. Any test slower than the limit fails the run, so slow tests are
caught as they are written.
"""

import concurrent.futures
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
# Run elsewhere: oidc and cors by run.sh, which needs Docker and minutes,
# and bootstrap by database.sh, since it needs a fresh database.
SLOW = {"oidc_contract", "cors_contract", "bootstrap_contract"}
LIMIT_SECONDS = 0.5
DURATION = re.compile(r"^(\d+\.\d+)s\s+(\S+)")


def run(binary, name):
    process = subprocess.run(
        [sys.executable, str(HERE / f"{name}.py"), binary, "--durations", "0"],
        cwd=HERE,
        capture_output=True,
        text=True,
        timeout=300,
    )
    durations = [(float(match.group(1)), f"{name}.{match.group(2)}") for line in process.stderr.splitlines() if (match := DURATION.match(line))]
    return name, process.returncode, process.stderr, durations


def main():
    arguments = sys.argv[1:]
    # Not an environment variable: the server refuses unknown RS_KEYCLOAK_
    # settings, and the contract servers inherit this environment.
    workers = 2
    if arguments[:1] == ["--workers"] and len(arguments) > 1:
        workers, arguments = int(arguments[1]), arguments[2:]
    if not arguments:
        raise SystemExit(__doc__)
    binary = os.path.abspath(arguments[0])
    names = [name.removesuffix(".py") for name in arguments[1:]] or sorted(
        path.stem for path in HERE.glob("*_contract.py") if path.stem not in SLOW
    )
    failed, durations = [], []
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        for name, code, output, timings in pool.map(lambda name: run(binary, name), names):
            durations.extend(timings)
            if code != 0:
                failed.append(name)
                print(f"FAILED {name}\n{output[-3000:]}", file=sys.stderr)
    slow = [(seconds, test) for seconds, test in durations if seconds > LIMIT_SECONDS]
    for seconds, test in sorted(durations, reverse=True)[:5]:
        print(f"{seconds:.3f}s {test}")
    for seconds, test in slow:
        print(f"TOO SLOW {seconds:.3f}s {test}", file=sys.stderr)
    print(f"{len(names)} contract files, {len(durations)} tests, {len(failed)} failed, {len(slow)} over {LIMIT_SECONDS}s")
    return 1 if failed or slow else 0


if __name__ == "__main__":
    sys.exit(main())
