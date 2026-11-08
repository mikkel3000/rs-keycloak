#!/usr/bin/env bash
# Run against an isolated, disposable PostgreSQL 18 container.
set -euo pipefail
: "${RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR:?must name a directory filled by compatibility/extract_account_console.py}"
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
# Build a v1 fixture, then upgrade it through the public CLI.
sql 'DROP SCHEMA public CASCADE; CREATE SCHEMA public'
docker exec -i "$container" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -q < migrations/0001_initial.sql
checksum=$(sha256sum migrations/0001_initial.sql)
checksum=${checksum%% *}
sql "CREATE TABLE rs_maintenance (singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), active boolean NOT NULL); INSERT INTO rs_maintenance VALUES (true, false); CREATE TABLE rs_schema_history (version bigint PRIMARY KEY, checksum bytea NOT NULL, applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP); INSERT INTO rs_schema_history (version, checksum) VALUES (1, decode('$checksum', 'hex'))"
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
python3 tests/public/lifecycle_contract.py "$bin"
python3 tests/public/client_contract.py "$bin"
python3 tests/public/userinfo_contract.py "$bin"
python3 tests/public/client_errors_contract.py "$bin"
python3 tests/public/client_credentials_contract.py "$bin"
python3 tests/public/admin_realms_contract.py "$bin"
python3 tests/public/admin_users_contract.py "$bin"
python3 tests/public/admin_clients_contract.py "$bin"
python3 tests/public/admin_roles_contract.py "$bin"
python3 tests/public/admin_groups_contract.py "$bin"
python3 tests/public/logout_contract.py "$bin"
python3 tests/public/sso_contract.py "$bin"
python3 tests/public/consent_contract.py "$bin"
python3 tests/public/otp_contract.py "$bin"
python3 tests/public/update_password_contract.py "$bin"
python3 tests/public/execute_actions_contract.py "$bin"
python3 tests/public/reset_credentials_contract.py "$bin"
python3 tests/public/verify_email_contract.py "$bin"
python3 tests/public/update_profile_contract.py "$bin"
python3 tests/public/account_api_contract.py "$bin"
python3 tests/public/client_roles_contract.py "$bin"
python3 tests/public/bearer_only_contract.py "$bin"
python3 tests/public/admin_client_update_contract.py "$bin"
python3 tests/public/admin_permissions_contract.py "$bin"
python3 tests/public/group_roles_contract.py "$bin"
python3 tests/public/role_composites_contract.py "$bin"
python3 tests/public/admin_user_update_contract.py "$bin"
python3 tests/public/role_mappings_contract.py "$bin"
python3 tests/public/redirect_matching_contract.py "$bin"
python3 tests/public/logout_redirects_contract.py "$bin"
python3 tests/public/user_search_contract.py "$bin"
python3 tests/public/role_updates_contract.py "$bin"
python3 tests/public/group_updates_contract.py "$bin"
python3 tests/public/admin_sessions_contract.py "$bin"
python3 tests/public/realm_settings_contract.py "$bin"
python3 tests/public/realm_keys_contract.py "$bin"
python3 tests/public/required_actions_admin_contract.py "$bin"
python3 tests/public/default_scopes_contract.py "$bin"
python3 tests/public/client_scopes_contract.py "$bin"
python3 tests/public/offline_access_contract.py "$bin"
python3 tests/public/account_console_api_contract.py "$bin"
python3 tests/public/partial_export_contract.py "$bin"
python3 tests/public/partial_import_contract.py "$bin"
python3 tests/public/partial_import_groups_contract.py "$bin"
python3 tests/public/export_import_contract.py "$bin"
python3 tests/public/user_credentials_create_contract.py "$bin"
python3 tests/public/account_console_contract.py "$bin"
python3 tests/public/account_settings_contract.py "$bin"
python3 tests/public/login_settings_contract.py "$bin"
python3 tests/public/login_messages_contract.py "$bin"
python3 tests/public/login_info_pages_contract.py "$bin"
python3 tests/public/realm_localization_contract.py "$bin"
python3 tests/public/login_email_contract.py "$bin"
python3 tests/public/totp_qr_contract.py "$bin"
python3 tests/public/verify_profile_contract.py "$bin"
python3 tests/public/remember_me_contract.py "$bin"
python3 tests/public/registration_contract.py "$bin"
python3 tests/public/otp_policy_contract.py "$bin"
