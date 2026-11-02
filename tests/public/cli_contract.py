"""Public CLI security checks; run with a built rs-keycloak binary path."""

import os
from pathlib import Path
import secrets
import subprocess
import sys
import unittest


BINARY = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else "rs-keycloak"


class CliContract(unittest.TestCase):
    def invoke(self, *args, settings=None):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("RS_KEYCLOAK_")}
        environment.update(settings or {})
        return subprocess.run(
            [BINARY, *args], env=environment, text=True,
            capture_output=True, timeout=5, check=False,
        )

    def test_version_needs_no_database(self):
        result = self.invoke("version")
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout, r"rs-keycloak \d+\.\d+\.\d+")

    def test_unknown_command_fails(self):
        self.assertNotEqual(self.invoke("unknown-command").returncode, 0)

    def test_missing_configuration_fails(self):
        self.assertNotEqual(self.invoke("config", "check").returncode, 0)

    def test_invalid_database_input_is_not_echoed(self):
        marker = secrets.token_hex(24)
        result = self.invoke("config", "check", settings={
            "RS_KEYCLOAK_DATABASE_URL": "invalid:" + marker,
            "RS_KEYCLOAK_ISSUER": "https://login.example.test",
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(marker, result.stdout + result.stderr)

    def test_insecure_public_issuer_is_rejected_without_echo(self):
        marker = secrets.token_hex(24)
        result = self.invoke("config", "check", settings={
            "RS_KEYCLOAK_DATABASE_URL": "postgresql://localhost/unused?sslmode=verify-full",
            "RS_KEYCLOAK_ISSUER": "http://login.example.test/" + marker,
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(marker, result.stdout + result.stderr)

    def test_validation_does_not_connect_to_database(self):
        result = self.invoke("config", "check", settings={
            "RS_KEYCLOAK_DATABASE_URL": "postgresql://127.0.0.1:1/unused?sslmode=verify-full",
            "RS_KEYCLOAK_ISSUER": "https://login.example.test",
        })
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_remote_database_requires_verified_tls_even_in_local_dev(self):
        for mode in ("disable", "prefer", "require", "verify-ca"):
            with self.subTest(mode=mode):
                result = self.invoke("config", "check", settings={
                    "RS_KEYCLOAK_DATABASE_URL": "postgresql://db.example.test/unused?sslmode=" + mode,
                    "RS_KEYCLOAK_ISSUER": "https://login.example.test",
                    "RS_KEYCLOAK_LOCAL_DEV": "true",
                })
                self.assertNotEqual(result.returncode, 0)

    def test_unknown_setting_is_rejected(self):
        result = self.invoke("config", "check", settings={
            "RS_KEYCLOAK_DATABASE_URL": "postgresql://localhost/unused?sslmode=verify-full",
            "RS_KEYCLOAK_ISSUER": "https://login.example.test",
            "RS_KEYCLOAK_UNKNOWN": "true",
        })
        self.assertNotEqual(result.returncode, 0)

    def test_database_url_cannot_override_checked_security_settings(self):
        for query in (
            "sslmode=verify-full&ssl-mode=disable",
            "sslmode=disable&host=db.example.test",
            "sslmode=disable&hostaddr=192.0.2.1",
            "sslmode=verify-full&options=-c%20synchronous_commit%3Doff",
            "sslmode=verify-full&options[synchronous_commit]=off",
        ):
            with self.subTest(query=query):
                result = self.invoke("config", "check", settings={
                    "RS_KEYCLOAK_DATABASE_URL": "postgresql://localhost/unused?" + query,
                    "RS_KEYCLOAK_ISSUER": "https://login.example.test",
                    "RS_KEYCLOAK_LOCAL_DEV": "true",
                })
                self.assertNotEqual(result.returncode, 0)

    def test_management_is_private_by_default(self):
        result = self.invoke("config", "check", settings={
            "RS_KEYCLOAK_DATABASE_URL": "postgresql://localhost/unused?sslmode=verify-full",
            "RS_KEYCLOAK_ISSUER": "https://login.example.test",
            "RS_KEYCLOAK_MANAGEMENT_LISTEN": "0.0.0.0:9000",
        })
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
