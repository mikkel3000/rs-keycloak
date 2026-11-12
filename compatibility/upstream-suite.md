# Keycloak's own tests/base suite against rs-keycloak

This is a trial of Keycloak's `tests/base` suite, from the pinned source
(26.8.1, `24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b`, in `~/kcsrc`), against
`target/release/rs-keycloak` in the test framework's `remote` server mode. It
is the PLAN.md verification baseline: the counts below say how far the
server is from passing Keycloak's own tests, and which gaps block the most
tests. Trial run on 2026-11-12.

## Commands

Build the test framework and the test modules from the pinned source once.
The Maven wrapper downloads Maven and the dependencies; the Keycloak modules
the tests use but that are not built here (services, model, admin client)
come from Maven Central at 26.8.1, the same version as the source.

```bash
cd ~/kcsrc
./mvnw -B -q -pl test-framework,test-framework/bom,test-framework/builders,\
test-framework/core,test-framework/junit5-config,test-framework/test-containers,\
test-framework/db-edb,test-framework/db-mariadb,test-framework/db-mssql,\
test-framework/db-mysql,test-framework/db-oracle,test-framework/db-postgres,\
test-framework/db-tidb,test-framework/email-server,test-framework/infinispan-server,\
test-framework/oauth,test-framework/remote,test-framework/remote-providers,\
test-framework/ui,tests,tests/utils,tests/utils-shared,tests/custom-providers,\
tests/custom-scripts install -DskipTests
./mvnw -B -q -pl tests/base test-compile
```

Then rerun the suite and print the counts, from this repository:

```bash
cargo build --release -p rs-keycloak-server
tests/upstream/run.sh                       # whole suite, about 25 minutes
tests/upstream/run.sh target/release/rs-keycloak -Dtest=RealmCreateTest
```

`tests/upstream/run.sh` drops and creates the database `upstream_suite` in
the fast database container, creates the framework's fixed bootstrap
credentials (user `admin`/`admin`, client `temp-admin`/`mysecret`, from the
framework's `Config` class), starts the server on `127.0.0.1:8080` with
management on `127.0.0.1:9001`, and runs

```bash
KC_TEST_SERVER=remote ./mvnw -B -pl tests/base test \
  -Dmaven.test.failure.ignore=true -Dsurefire.failIfNoSpecifiedTests=false \
  -Dsurefire.excludesFile=target/upstream-suite/excluded.txt \
  -Djunit.jupiter.execution.timeout.default=60s -DreuseForks=false
```

`tests/upstream/counts.py` reads the surefire reports and prints the table;
logs, `counts.json` and the server log go to `target/upstream-suite/`.

Notes on the setup:

- Ports: `test-framework/docs/RUNNING_TESTS.md` names 8080, 8443 and 9001.
  rs-keycloak serves no TLS, so nothing listens on 8443. The remote server
  class (`RemoteKeycloakServer.getManagementBaseUrl`) uses 9000, not 9001,
  for management; only metrics and health tests use it, and they need
  server options anyway.
- `RS_KEYCLOAK_ISSUER` must be HTTPS, so the run uses
  `https://localhost:8443` while the framework talks to
  `http://localhost:8080`. Tokens and URLs the server builds name the
  issuer, so browser tests that follow them would leave 8080; no test got
  that far in this trial.
- Each test class gets a fresh JVM (`-DreuseForks=false`). In one long-lived
  JVM the time per test grew from 0.03 s to 11 s over 230 classes while the
  server answered in 22 ms, and the run did not finish in 2 hours.
- 22 classes are left out of the Maven run and counted from the source as
  cannot-run, since the remote framework waits 5 minutes per class for a
  TLS listener on 8443 (`@InjectCertificates`) that never comes.

## Server changes the framework needed to start

- `oidc: serve the public realm document`: the framework's
  `ReadinessProbe` waits for 200 on `GET /realms/master`, which had no
  route.
- `server: accept short bootstrap credentials in local development`: the
  framework signs in with `temp-admin`/`mysecret` and creates
  `admin`/`admin`, shorter than the 32- and 12-byte minimums.

With these two the framework starts, its admin client signs in with client
credentials, and every test reaches its own setup.

The realm document is recorded with `tests/reference/batch.py`
(`realm-info-observations.json`) and checked by
`tests/public/realm_info_contract.py`. The bootstrap change has no
reference recording, since it changes local CLI input rules, not an HTTP
response; the pinned `start-dev` takes any value for
`KC_BOOTSTRAP_ADMIN_CLIENT_SECRET` and `KC_BOOTSTRAP_ADMIN_PASSWORD`, and
`tests/public/bootstrap_client_contract.py` signs in to the admin API with
`mysecret`.

## Counts per test area

Tests are JUnit test methods, from 552 classes run plus 22 counted from the
source. The figures are the output of `tests/upstream/run.sh` on the release
binary at commit `92167dd`, with the settings above (fresh JVM per class).
An earlier run in one JVM was stopped at 233 classes and is not counted. A test counts as cannot-run when it needs something a remote
rs-keycloak cannot give (groups below), even if it would pass; the other
tests pass or fail as surefire reports them.

| Area | Pass | Fail | Cannot run |
| --- | ---: | ---: | ---: |
| account | 0 | 194 | 29 |
| actions | 0 | 14 | 0 |
| admin | 0 | 855 | 333 |
| authz | 0 | 0 | 11 |
| broker | 0 | 98 | 56 |
| cli | 0 | 0 | 71 |
| client | 2 | 280 | 119 |
| composites | 0 | 11 | 0 |
| cookies | 0 | 0 | 11 |
| cors | 0 | 0 | 1 |
| db | 0 | 6 | 10 |
| docker | 0 | 0 | 7 |
| error | 0 | 0 | 21 |
| events | 0 | 6 | 47 |
| exportimport | 0 | 1 | 11 |
| forms | 0 | 33 | 90 |
| httpclient | 0 | 0 | 2 |
| i18n | 0 | 10 | 18 |
| infinispan | 0 | 0 | 1 |
| keys | 0 | 70 | 30 |
| login | 0 | 8 | 6 |
| loginfailures | 0 | 0 | 3 |
| migration | 0 | 10 | 0 |
| model | 0 | 103 | 31 |
| oauth | 0 | 298 | 213 |
| oid4vc | 0 | 98 | 526 |
| oidc | 0 | 9 | 0 |
| organization | 0 | 343 | 74 |
| policy | 0 | 0 | 13 |
| providers | 0 | 0 | 2 |
| saml | 0 | 2 | 1 |
| securityprofile | 0 | 0 | 4 |
| session | 0 | 1 | 10 |
| sessionlimits | 0 | 2 | 23 |
| ssl | 0 | 2 | 7 |
| tracing | 0 | 0 | 13 |
| transactions | 0 | 0 | 2 |
| url | 0 | 2 | 14 |
| user | 3 | 64 | 11 |
| vault | 0 | 0 | 4 |
| welcomepage | 0 | 2 | 7 |
| workflow | 0 | 0 | 118 |
| x509 | 0 | 0 | 48 |
| **total** | **5** | **2522** | **1998** |

The 5 passes (`client.DefaultClientValidationTest`,
`user.profile.config.UPConfigUtilsTest`) run in the test JVM only and never
call the server.

## Why the cannot-run groups cannot run against a remote server

| Group | Tests | Why |
| --- | ---: | --- |
| server-options | 1315 | The class's `KeycloakServerConfig` sets server options or features (`.option`, `.features`, `.spiOption`): mostly preview features such as OID4VC (`VCTestServerConfig`, 251), fine-grained admin permissions v2 (184), workflows (100), dynamic scopes, token exchange delegation, vaults, metrics and tracing. In remote mode the framework only prints the start command; it cannot restart the server with them, so the tests would run against the wrong configuration. |
| providers | 239 | The config deploys provider jars (`.dependency`, such as `keycloak-tests-custom-providers`) into the server. Java SPI providers cannot be loaded into rs-keycloak; RUST-PROVIDERS.md covers the Rust alternative. |
| run-on-server | 238 | The test, or a helper it calls, uses `RunOnServerClient` or `TestClassServer`: the framework ships the test's lambda to the `testing-run-on-server` endpoint of the remote-providers jar and runs it inside the Keycloak JVM against `KeycloakSession` and the model API. |
| tls | 155 | `@InjectCertificates` starts the server with the framework's keystore and truststore on 8443 (HTTPS, mTLS, X.509 login, kcadm and kcreg truststores). rs-keycloak has no TLS listener; it expects TLS in front of it. |
| time-offset | 45 | `TimeOffSet` moves the server clock through the remote-providers endpoint inside the Keycloak JVM; there is no such clock control here. |
| skipped | 4 | Disabled by the suite itself (`@Disabled`, `@DisabledForServers`). |
| database | 2 | `@InjectTestDatabase` reads Keycloak's own JDBC schema, which rs-keycloak does not have. |

The run-on-server and time-offset groups count only the tests that use
those clients; many more classes inject them without using them in every
test.

## Most common failure causes

| Tests | Cause |
| ---: | --- |
| 2333 | Managed realm creation: `POST /admin/realms` answers 400 `Unsupported realm field: id`. `RealmSupplier` always sets `id` to the realm name, so these tests never reach their own steps. |
| 107 | Realm creation from JSON answers 413: the realm files of the OID4VC tests are over the 16 KiB body limit shared by all public and admin routes. |
| 29 | Tests that create objects themselves get 400 where they expect 201. |
| 17 | Other admin client calls inside tests get 400. |

To see the next layer, a throwaway build that ignores unknown realm fields
(never committed) was run once. Its first new failures:

- `OAuthClientSupplier` creates the `test-app` client with an audience
  protocol mapper; `POST /admin/realms/{realm}/clients` answers 400
  `Unsupported client field: protocolMappers` (109 tests at that layer,
  1446 failing tests are in classes that inject an OAuth client).
- `Events` and `AdminEvents` clear the realm's events after each test with
  `DELETE /admin/realms/{realm}/events` and `/admin-events`, which answer
  404. The failure aborts the framework's cleanup, the realm stays, and
  every later class using the same realm name gets 409 Conflict (2128 tests
  in that run).
- `UserSupplier` and `ClientSupplier` get 400 for user and client fields.

## Ten failing test classes that would unblock the most others

Each class tests the admin feature the framework itself uses to set tests
up, so making it pass removes a setup failure from many other classes. All
ten fail in the run. The choice of classes is a judgement from the failure
causes and the framework source; the "Blocked" figures are computed by
`tests/upstream/counts.py` (its `BLOCKERS` list) from the run's own reports
and printed by `tests/upstream/run.sh`. For `RealmCreateTest` it is the
failing tests whose managed realm creation failed with 400; for the others
it is the failing tests in classes, parents included, that use the
feature. The figures overlap: most classes need several of these. The
throwaway probe above only informed which features come next; none of its
figures are in this table.

| # | Class | Feature it checks | Blocked |
| ---: | --- | --- | ---: |
| 1 | `admin.realm.RealmCreateTest` | `POST /admin/realms` with `id` and the realm fields test realm configs set | 2333 |
| 2 | `admin.user.UserSearchTest` | users created and found with the full user representation (`@InjectUser`, realm `users`) | 2075 |
| 3 | `admin.ClientTest` | client creation with the full client representation (`@InjectClient`, realm `clients`) | 1897 |
| 4 | `admin.client.ClientProtocolMapperTest` | client protocol mappers, which the default OAuth test client carries | 1471 |
| 5 | `oauth.RefreshTokenTest` | password and code grants through `OAuthClient` against a managed realm | 1471 |
| 6 | `admin.event.EventConfigTest` | `eventsEnabled`, `adminEventsEnabled` and `adminEventsDetailsEnabled`, set by the events interceptors | 1103 |
| 7 | `admin.realm.RealmRolesCRUDTest` | realm roles in realm representations and the roles API | 996 |
| 8 | `admin.event.LoginEventsTest` | `GET` and `DELETE /admin/realms/{realm}/events` | 649 |
| 9 | `admin.realm.RealmUpdateTest` | `PUT /admin/realms/{realm}` with a full representation, used by `ManagedRealm.updateWithCleanup` | 562 |
| 10 | `admin.event.AdminEventTest` | `GET` and `DELETE /admin/realms/{realm}/admin-events` | 477 |
