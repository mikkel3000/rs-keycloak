"""Admin realm keys compared with recorded Keycloak 26.8.1 behavior.

Expected cases come from tests/reference/realm-key-observations.json. Every
realm here signs with one RS256 key, so the listing has that key alone,
without a certificate, provider component or encryption keys.
"""

import base64
import json
import pathlib
import unittest

from fixture import AdminCase


REFERENCE = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "reference/realm-key-observations.json").read_text()
)["observations"]


class RealmKeysContract(AdminCase):
    def test_signing_key_matches_jwks(self):
        status, headers, body = self.call("GET", f"/admin/realms/{self.realm}/keys")
        expected = REFERENCE["keys"]
        self.assertEqual((status, headers["content-type"]), (expected["status"], expected["content_type"]))
        parsed = json.loads(body)
        self.assertEqual(sorted(parsed), expected["fields"])
        jwks = json.loads(self.request("GET", f"/realms/{self.realm}/protocol/openid-connect/certs")[2])["keys"]
        self.assertEqual(parsed["active"], {"RS256": jwks[0]["kid"]})
        [key] = parsed["keys"]
        rs256 = next(item for item in expected["keys"] if item[0] == "RS256")
        self.assertEqual([key["algorithm"], key["type"], key["use"], key["status"], key["providerPriority"], "publicKey" in key, key["kid"] == jwks[0]["kid"]], rs256[:6] + [rs256[7]])
        self.assertEqual(key["publicKey"][:4], REFERENCE["rs256/matches-jwks"]["public_key_base64"])
        # The SubjectPublicKeyInfo carries the JWKS modulus.
        modulus = base64.urlsafe_b64decode(jwks[0]["n"] + "=" * (-len(jwks[0]["n"]) % 4))
        self.assertIn(modulus, base64.b64decode(key["publicKey"]))

    def test_errors(self):
        status, _, body = self.call("GET", "/admin/realms/missing-realm/keys")
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["keys/unknown-realm"])
        status, _, body = self.call("GET", f"/admin/realms/{self.realm}/keys", token=False)
        self.assertEqual({"status": status, "body": json.loads(body)}, REFERENCE["keys/no-token"])


if __name__ == "__main__":
    unittest.main()
