#!/usr/bin/env python3
"""Extracts the pinned Keycloak account console for RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR.

Usage: extract_account_console.py ARCHIVE OUTPUT_DIR

ARCHIVE is the pinned distribution named in reference.lock, checked by its
digest. OUTPUT_DIR receives account/ (the keycloak.v3 account theme: built
resources, messages and theme properties) and common/ (the shared vendor
modules the console imports). Both come from Apache-2.0 Keycloak jars.
"""
import hashlib
import json
import pathlib
import shutil
import sys
import tarfile
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
# Jar, prefix inside the jar, destination below OUTPUT_DIR.
PARTS = [
    ('keycloak-account-ui', 'theme/keycloak.v3/account/', 'account/'),
    ('keycloak-themes-vendor', 'theme/keycloak/common/resources/', 'common/'),
]


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    archive, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    lock = json.loads((HERE / 'reference.lock').read_text())['keycloak']
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['distribution']['sha256']:
        raise SystemExit('distribution digest mismatch')
    version = lock['version']
    if output.exists() and any(output.iterdir()):
        raise SystemExit('output directory must be empty')
    with tempfile.TemporaryDirectory(prefix='rs-keycloak-console-') as scratch, tarfile.open(archive) as distribution:
        for jar, prefix, destination in PARTS:
            member = f'keycloak-{version}/lib/lib/main/org.keycloak.{jar}-{version}.jar'
            distribution.extract(member, scratch, filter='data')
            with zipfile.ZipFile(pathlib.Path(scratch) / member) as contents:
                for name in contents.namelist():
                    if not name.startswith(prefix) or name.endswith('/') or name.endswith('.ftl'):
                        continue
                    relative = pathlib.PurePosixPath(name[len(prefix):])
                    if '..' in relative.parts:
                        raise SystemExit(f'unsafe path in {jar}: {name}')
                    target = output / destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with contents.open(name) as source, open(target, 'wb') as sink:
                        shutil.copyfileobj(source, sink)
    print(f'account console {version} extracted to {output}')


if __name__ == '__main__':
    main()
