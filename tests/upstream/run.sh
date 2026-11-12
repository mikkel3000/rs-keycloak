#!/usr/bin/env bash
# Runs Keycloak's own tests/base suite, from the pinned source in ~/kcsrc, against
# rs-keycloak in the framework's remote mode, then prints pass, fail and
# cannot-run counts per test area. See compatibility/upstream-suite.md.
#
# Usage: tests/upstream/run.sh [BINARY] [-Dtest=Pattern]
#   BINARY defaults to target/release/rs-keycloak. Extra arguments go to Maven.
# Needs the fast database container (AGENTS/setup.md) and the framework built
# into ~/.m2 as compatibility/upstream-suite.md describes. The database
# upstream_suite is dropped and created again on every run.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
binary=${1:-$root/target/release/rs-keycloak}
[[ $# -gt 0 ]] && shift
source_dir=${KCSRC:-$HOME/kcsrc}
reports=$source_dir/tests/base/target/surefire-reports
log_dir=${UPSTREAM_LOG_DIR:-$root/target/upstream-suite}
mkdir -p "$log_dir"

for port in 8080 9001; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "port $port is in use; the framework needs 8080 and 9001 free" >&2
    exit 1
  fi
done

database=upstream_suite
docker exec rs-keycloak-fastdb psql -q -U postgres -c "DROP DATABASE IF EXISTS $database WITH (FORCE)"
docker exec rs-keycloak-fastdb psql -q -U postgres -c "CREATE DATABASE $database"

export RS_KEYCLOAK_LOCAL_DEV=true
export RS_KEYCLOAK_DATABASE_URL="postgres://postgres@127.0.0.1:55432/$database?sslmode=disable"
"$binary" db migrate
# The framework's fixed bootstrap credentials, from its Config class.
printf 'admin\n' | "$binary" bootstrap-admin admin
printf 'mysecret\n' | "$binary" client add-confidential master temp-admin http://localhost:8080/
"$binary" client enable-service-account master temp-admin
"$binary" client grant-master-admin temp-admin

# Keys are made per run and stay in this process's environment.
signing_key=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null \
  | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0)
secret_key=$(head -c 32 /dev/urandom | base64 -w0)
RS_KEYCLOAK_HTTP_LISTEN=127.0.0.1:8080 \
  RS_KEYCLOAK_MANAGEMENT_LISTEN=127.0.0.1:9001 \
  RS_KEYCLOAK_ISSUER=https://localhost:8443 \
  RS_KEYCLOAK_SIGNING_KEY_PKCS8=$signing_key \
  RS_KEYCLOAK_SECRET_KEY=$secret_key \
  "$binary" serve > "$log_dir/server.log" 2>&1 &
server=$!
unset signing_key secret_key
trap 'kill $server 2>/dev/null; wait $server 2>/dev/null || true' EXIT

for _ in $(seq 50); do
  if curl -fs -o /dev/null http://127.0.0.1:8080/realms/master; then break; fi
  sleep 0.2
done
curl -fs -o /dev/null http://127.0.0.1:8080/realms/master

rm -rf "$reports"
# Classes needing TLS on 8443 or an Infinispan server make the remote framework
# wait minutes for a server that never comes; they are counted from the source.
counts=$root/tests/upstream/counts.py
python3 -I "$counts" "$source_dir/tests/base" --exclusions > "$log_dir/excluded.txt"
# Each class gets a fresh JVM: in one long-lived JVM the time per test grew
# from 0.03 s to 11 s over 230 classes while the server stayed fast.
# The server variables stay out of Maven's environment.
(
  cd "$source_dir"
  env -u RS_KEYCLOAK_LOCAL_DEV -u RS_KEYCLOAK_DATABASE_URL KC_TEST_SERVER=remote \
    ./mvnw -B -pl tests/base test \
    -Dmaven.test.failure.ignore=true \
    -Dsurefire.failIfNoSpecifiedTests=false \
    -Dsurefire.excludesFile="$log_dir/excluded.txt" \
    -Djunit.jupiter.execution.timeout.default=60s \
    -DreuseForks=false \
    "$@"
) > "$log_dir/maven.log" 2>&1 || {
  tail -20 "$log_dir/maven.log" >&2
  exit 1
}

# A run limited with -Dtest leaves the excluded classes out of the counts.
flags=()
[[ $# -eq 0 ]] && flags+=(--with-excluded)
python3 -I "$counts" "$source_dir/tests/base" "$reports" "${flags[@]}"
python3 -I "$counts" "$source_dir/tests/base" "$reports" "${flags[@]}" --json > "$log_dir/counts.json"
