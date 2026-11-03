use axum::http::{HeaderMap, HeaderValue, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rs_keycloak_http::client_auth::{self, ClientCredentials};
use uuid::Uuid;
use zeroize::Zeroizing;

#[test]
fn basic_form_encoding_and_ambiguous_methods() {
    let secret = format!("{}+&", Uuid::new_v4());
    let encoded_secret: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
    let encoded = STANDARD.encode(format!("service%3Aone:{encoded_secret}"));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
    );
    match client_auth::parse(&headers, None, None).unwrap() {
        ClientCredentials::Confidential {
            client_id,
            secret: decoded,
        } => {
            assert_eq!(client_id, "service:one");
            assert_eq!(decoded.as_slice(), secret.as_bytes());
        }
        ClientCredentials::Public(_) => panic!("confidential client parsed as public"),
    }
    assert!(client_auth::parse(&headers, None, Some(Zeroizing::new(secret))).is_err());
    headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
    );
    assert!(client_auth::parse(&headers, None, None).is_err());
}
