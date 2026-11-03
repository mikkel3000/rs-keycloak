use std::io::Write;
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature;
use rs_keycloak_crypto::signing::{SigningKey, TokenClaims};

#[test]
fn rs256_jwt_verifies_with_published_jwk() {
    // Generate a disposable key in memory so no private key is written to disk.
    let key = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .stderr(Stdio::null())
        .output()
        .expect("openssl is required for this integration test");
    assert!(key.status.success());
    let mut convert = Command::new("openssl")
        .args(["pkcs8", "-topk8", "-nocrypt", "-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    convert
        .stdin
        .take()
        .unwrap()
        .write_all(&key.stdout)
        .unwrap();
    let der = convert.wait_with_output().unwrap();
    assert!(der.status.success());
    let signing = SigningKey::from_pkcs8(&der.stdout).unwrap();
    let claims = TokenClaims {
        iss: "https://issuer.example",
        sub: "user",
        aud: "client",
        iat: 100,
        exp: 200,
        jti: "token",
        azp: "client",
        sid: "session",
        scope: "openid",
    };
    let token = signing.sign(&claims).unwrap();
    let parts: Vec<_> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let jwk = serde_json::to_value(signing.public_jwk()).unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["kid"], jwk["kid"]);
    let modulus = URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap();
    let exponent = URL_SAFE_NO_PAD.decode(jwk["e"].as_str().unwrap()).unwrap();
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    signature::RsaPublicKeyComponents {
        n: &modulus,
        e: &exponent,
    }
    .verify(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &signature,
    )
    .unwrap();
}
