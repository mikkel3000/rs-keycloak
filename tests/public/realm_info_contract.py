"""Public realm endpoint compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/realm-info-observations.json. The
upstream test framework polls GET /realms/master until it answers 200.
"""

import base64
import json
import pathlib
import unittest

from fixture import ISSUER_BASE, AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/realm-info-observations.json").read_text()
)["observations"]


class RealmInfoContract(AdminCase):
    def observe(self, realm):
        status, headers, body = self.request("GET", f"/realms/{realm}", {"Origin": "https://other.example.test"})
        parsed = json.loads(body)
        jwks = json.loads(self.request("GET", f"/realms/{realm}/protocol/openid-connect/certs")[2])["keys"]
        rsa = [key["n"] for key in jwks if key["kty"] == "RSA" and key.get("use") == "sig"]
        issuer = f"{ISSUER_BASE}/realms/{realm}"
        # The SubjectPublicKeyInfo carries the JWKS modulus.
        modulus = base64.urlsafe_b64decode(rsa[0] + "=" * (-len(rsa[0]) % 4))
        self.assertIn(modulus, base64.b64decode(parsed["public_key"]))
        return {
            "status": status,
            "content_type": headers["content-type"],
            "cache_control": headers.get("cache-control"),
            "allow_origin": headers.get("access-control-allow-origin"),
            "fields": sorted(parsed),
            "realm": parsed["realm"] == realm,
            "token_service": parsed["token-service"] == issuer + "/protocol/openid-connect",
            "account_service": parsed["account-service"] == issuer + "/account",
            "tokens_not_before": parsed["tokens-not-before"],
            "public_key_is_pem_body": parsed["public_key"].startswith("MII") and "\n" not in parsed["public_key"],
            "rsa_signing_keys": len(rsa),
        }

    def test_master_and_new_realm(self):
        # Content types differ only in the charset parameter.
        for name, realm in (("master", "master"), ("new-realm", self.realm)):
            expected = dict(REFERENCE[name], content_type="application/json")
            self.assertEqual(self.observe(realm), expected, name)

    def test_unknown_and_disabled_realm(self):
        status, headers, body = self.request("GET", "/realms/missing-realm")
        expected = REFERENCE["unknown-realm"]
        self.assertEqual({"status": status, "content_type": headers["content-type"], "body": json.loads(body)}, expected)
        self.assertEqual(self.call("PUT", f"/admin/realms/{self.realm}", {"enabled": False})[0], 204)
        status, headers, body = self.request("GET", f"/realms/{self.realm}")
        expected = dict(REFERENCE["disabled-realm"], content_type="application/json")
        self.assertEqual({"status": status, "content_type": headers["content-type"], "fields": sorted(json.loads(body))}, expected)


if __name__ == "__main__":
    unittest.main()
