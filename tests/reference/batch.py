#!/usr/bin/env python3
"""Records or compares several reference baselines against one server start.

Usage: batch.py --archive PATH [--port N] [--record] MODULE=BASELINE ...

Each MODULE is a recorder in this directory with a run(base, secret,
record) function, and BASELINE its observations file here. With --record,
every baseline is written and then compared in a second pass against the
same server, so one start both records and checks that each case repeats.
Without it, every module only compares. Realms are random per run, so the
passes do not see each other's data.
"""
import argparse
import importlib
import json
import pathlib
import sys

import oauth

HERE = pathlib.Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--archive', required=True, type=pathlib.Path)
    parser.add_argument('--port', type=int, default=18081)
    parser.add_argument('--record', action='store_true')
    parser.add_argument('recorders', nargs='+', metavar='MODULE=BASELINE')
    args = parser.parse_args()
    recorders = []
    for item in args.recorders:
        module, _, baseline = item.partition('=')
        if not baseline or '/' in baseline:
            parser.error(f'expected MODULE=BASELINE in this directory, got {item}')
        recorders.append((importlib.import_module(module), HERE / baseline))
    with oauth.reference_server(args.archive, args.port) as (base, secret):
        if args.record:
            for module, baseline in recorders:
                baseline.write_text(json.dumps(module.run(base, secret, record=True)) + '\n')
                print(f'recorded {baseline.name}')
        for module, baseline in recorders:
            module.run(base, secret, record=False)
            print(f'compared {baseline.name}')


if __name__ == '__main__':
    try:
        main()
    except AssertionError as error:
        raise SystemExit(f'reference batch failed: {error}') from None
