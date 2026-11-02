#!/usr/bin/env bash
# Run against an isolated, disposable PostgreSQL 18 container.
set -euo pipefail
cd "$(dirname "$0")/../.."
container="rs-keycloak-db-test-$$"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT
architecture=$(docker info --format '{{.Architecture}}')
case "$architecture" in
    x86_64|amd64) platform=linux/amd64 ;;
    aarch64|arm64) platform=linux/arm64/v8 ;;
    *) echo 'Unsupported reference test architecture' >&2; exit 1 ;;
esac
image=$(python3 -c 'import json,sys; print(json.load(open("compatibility/reference.lock"))["postgresql"]["platform_images"][sys.argv[1]])' "$platform")
docker run -d --rm --name "$container" -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1::5432 "$image" >/dev/null
ready=false
for _ in {1..60}; do
    if docker exec "$container" pg_isready -U postgres >/dev/null 2>&1; then ready=true; break; fi
    sleep 1
done
if [[ "$ready" != true ]]; then echo 'PostgreSQL did not become ready' >&2; exit 1; fi
port=$(docker port "$container" 5432/tcp)
port=${port##*:}
export RS_KEYCLOAK_LOCAL_DEV=true
export RS_KEYCLOAK_DATABASE_URL="postgres://postgres@127.0.0.1:$port/postgres?sslmode=disable"
bin=target/debug/rs-keycloak
sql() { docker exec "$container" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -qAtc "$1"; }
if "$bin" db check; then echo 'fresh schema check unexpectedly succeeded' >&2; exit 1; fi
"$bin" db migrate
"$bin" db check
"$bin" db migrate
# Simulate an installation at migration 1, then upgrade through the CLI.
sql 'DROP TABLE login_challenges, login_lockouts, login_policy, audit_events, bootstrap_admin, user_role_grants, roles; DROP FUNCTION rs_bump_user_revision() CASCADE; DROP FUNCTION rs_bump_credential_revision() CASCADE; DROP INDEX credentials_one_password_per_user; ALTER TABLE credentials DROP COLUMN revision; DELETE FROM rs_schema_history WHERE version >= 2'
if "$bin" db check; then echo 'old schema unexpectedly accepted' >&2; exit 1; fi
"$bin" db migrate
"$bin" db check
sql "INSERT INTO rs_schema_history(version, checksum) VALUES (1000000, decode('00', 'hex'))"
if "$bin" db migrate; then echo 'future schema unexpectedly accepted' >&2; exit 1; fi
[[ $(sql 'SELECT active FROM rs_maintenance') == f ]]
[[ $(sql 'SELECT count(*) FROM rs_schema_history WHERE version = 1000000') == 1 ]]
if "$bin" db check; then echo 'future schema check unexpectedly succeeded' >&2; exit 1; fi
sql 'DELETE FROM rs_schema_history WHERE version = 1000000'
"$bin" db check
sql "UPDATE rs_schema_history SET checksum = decode('00', 'hex')"
if "$bin" db migrate; then echo 'corrupt history unexpectedly accepted' >&2; exit 1; fi
[[ $(sql 'SELECT active FROM rs_maintenance') == f ]]
if "$bin" db check; then echo 'corrupt history check unexpectedly succeeded' >&2; exit 1; fi
sql 'DROP SCHEMA public CASCADE; CREATE SCHEMA public; CREATE TABLE realms (id text)'
if "$bin" db migrate; then echo 'conflicting DDL unexpectedly succeeded' >&2; exit 1; fi
[[ $(sql 'SELECT active FROM rs_maintenance') == t ]]
if "$bin" db check; then echo 'maintenance check unexpectedly succeeded' >&2; exit 1; fi
sql 'DROP TABLE realms'
"$bin" db migrate
"$bin" db check
python3 tests/public/bootstrap_contract.py "$bin"
[[ $(sql 'SELECT count(*) FROM bootstrap_admin') == 1 ]]
[[ $(sql 'SELECT count(*) FROM user_role_grants') == 1 ]]
[[ $(sql "SELECT count(*) FROM audit_events WHERE event_type = 'bootstrap_admin_created'") == 1 ]]
