#!/usr/bin/env python3
"""Extracts the pinned Keycloak login or email theme's message bundles.

Usage: extract_login_messages.py ARCHIVE OUTPUT_DIR [THEME]

ARCHIVE is the pinned distribution named in reference.lock, checked by its
digest. OUTPUT_DIR, empty or missing, receives theme.properties (the
theme's locale list) and messages/ (every messages_*.properties bundle) of
the base THEME, `login` by default, which holds all its texts; the
keycloak.v2 login theme on top only adds theme descriptions. The server
embeds them from crates/http/src/login_theme and
crates/http/src/email_theme. The files are Apache-2.0 Keycloak sources.
"""
import hashlib
import json
import pathlib
import sys
import tarfile
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
THEMES = ('login', 'email')


def main():
    if len(sys.argv) not in (3, 4) or len(sys.argv) == 4 and sys.argv[3] not in THEMES:
        raise SystemExit(__doc__)
    archive, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    theme = sys.argv[3] if len(sys.argv) == 4 else 'login'
    prefix = f'theme/base/{theme}/'
    lock = json.loads((HERE / 'reference.lock').read_text())['keycloak']
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['distribution']['sha256']:
        raise SystemExit('distribution digest mismatch')
    version = lock['version']
    if output.exists() and any(output.iterdir()):
        raise SystemExit('output directory must be empty')
    member = f'keycloak-{version}/lib/lib/main/org.keycloak.keycloak-themes-{version}.jar'
    with tempfile.TemporaryDirectory(prefix='rs-keycloak-login-') as scratch, tarfile.open(archive) as distribution:
        distribution.extract(member, scratch, filter='data')
        with zipfile.ZipFile(pathlib.Path(scratch) / member) as contents:
            for name in contents.namelist():
                relative = name[len(prefix):] if name.startswith(prefix) else None
                if relative != 'theme.properties' and not (relative or '').startswith('messages/messages_'):
                    continue
                if '/' in relative.removeprefix('messages/') or not relative.endswith('.properties'):
                    raise SystemExit(f'unexpected path in the themes jar: {name}')
                target = output / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(contents.read(name))
    print(f'{theme} messages {version} extracted to {output}')


if __name__ == '__main__':
    main()
