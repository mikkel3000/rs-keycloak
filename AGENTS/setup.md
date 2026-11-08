# Machine setup

Run from the repository root. Paths below are the ones `workflow.md` and the goal loop expect; tell a goal session if any differs.

1. Tools: Rust through rustup (`rust-toolchain.toml` pins the version with clippy and rustfmt), Docker, Python 3.12+, OpenJDK 25 and OpenSSL for the reference server, `jq`, and Claude Code at `~/.local/bin/claude`.
2. Reference distribution, checked against `compatibility/reference.lock`:
   ```bash
   mkdir -p ~/kcarchive && curl -fL -o ~/kcarchive/keycloak-26.8.1.tar.gz https://github.com/keycloak/keycloak/releases/download/26.8.1/keycloak-26.8.1.tar.gz
   echo "4e2740b181faa2ea623a1c2ecf00855935311e546046e2f857615a47ed24cbe8  $HOME/kcarchive/keycloak-26.8.1.tar.gz" | sha256sum -c
   ```
3. Pinned Keycloak source, to read before recording:
   ```bash
   mkdir -p ~/kcsrc && curl -fL -o ~/kcsrc.tar.gz https://api.github.com/repos/keycloak/keycloak/tarball/24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b
   echo "1e2ff1d7dc008515e15ed072eccd32c2c836e0ca0eb251591018f334ade60794  $HOME/kcsrc.tar.gz" | sha256sum -c
   tar -xzf ~/kcsrc.tar.gz -C ~/kcsrc --strip-components=1
   ```
4. Account console files for the console contracts:
   ```bash
   mkdir -p ~/console && python3 -I compatibility/extract_account_console.py ~/kcarchive/keycloak-26.8.1.tar.gz ~/console
   ```
5. Test database, the pinned PostgreSQL 18 image for the machine's platform from `compatibility/reference.lock` (amd64 shown):
   ```bash
   docker run -d --name rs-keycloak-fastdb --restart unless-stopped -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:55432:5432 docker.io/library/postgres@sha256:f4b419e350fd98d4a8429603295208976dea4c8fb8326d818d346d3e29f1db6f
   ```
6. Environment, in the shell profile:
   ```bash
   export RS_KEYCLOAK_LOCAL_DEV=true
   export RS_KEYCLOAK_DATABASE_URL='postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable'
   export RS_KEYCLOAK_ACCOUNT_CONSOLE_DIR="$HOME/console"
   ```
7. Build, migrate and check that the fast suite passes:
   ```bash
   cargo build --release -p rs-keycloak-server
   target/release/rs-keycloak db migrate
   (cd tests/public && python3 fast.py --workers 3 ../../target/release/rs-keycloak)
   ```
