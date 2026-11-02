#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
image=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["keycloak"]["image"])' "$root/compatibility/reference.lock")
case "${1:-}" in
  start)
    docker run --detach --rm --name rs-keycloak-reference --publish 127.0.0.1:18080:8080 "$image" start-dev --http-port=8080
    ;;
  start-distribution)
    archive=${2:?Pass the official Keycloak 26.8.1 distribution tar.gz}
    expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["keycloak"]["distribution"]["sha256"])' "$root/compatibility/reference.lock")
    actual=$(sha256sum "$archive")
    test "${actual%% *}" = "$expected" || { echo 'Distribution digest mismatch' >&2; exit 1; }
    reference_dir=$(mktemp -d /tmp/rs-keycloak-reference.XXXXXXXX)
    trap 'rm -rf "$reference_dir"' EXIT
    tar -xzf "$archive" -C "$reference_dir"
    "$reference_dir/keycloak-26.8.1/bin/kc.sh" start-dev --http-host=127.0.0.1 --http-port=18080
    ;;
  check)
    shift
    python3 "$root/tests/reference/check.py" --reference http://127.0.0.1:18080 "$@"
    ;;
  stop) docker stop rs-keycloak-reference ;;
  *) echo 'Usage: reference.sh start | start-distribution ARCHIVE | check [--target URL] | stop' >&2; exit 2 ;;
esac
