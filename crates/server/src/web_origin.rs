//! Explicit browser origin registration.

use std::env;

use rs_keycloak_storage_postgres::Storage;
use url::Url;

pub(crate) async fn add(realm: &str, client_id: &str, origin: &str) -> Result<(), &'static str> {
    if realm.is_empty()
        || realm.len() > 255
        || client_id.is_empty()
        || client_id.len() > 255
        || origin.len() > 2048
    {
        return Err("Realm, client ID, or origin is invalid");
    }
    let parsed = Url::parse(origin).map_err(|_| "Web origin is invalid")?;
    let local = env::var("RS_KEYCLOAK_LOCAL_DEV").ok().as_deref() == Some("true")
        && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !(parsed.scheme() == "https" || (parsed.scheme() == "http" && local))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(
            "Web origin must be a canonical HTTPS origin; loopback HTTP requires local development",
        );
    }
    let storage = Storage::connect(&super::database_url()?)
        .await
        .map_err(|_| "Database check failed")?;
    let realm_id = storage
        .realm_id_by_name(realm)
        .await
        .map_err(|_| "Realm lookup failed")?
        .ok_or("Realm is missing or disabled")?;
    if !storage
        .add_client_web_origin(&realm_id, client_id, origin)
        .await
        .map_err(|_| "Web origin registration failed")?
    {
        return Err("Client is missing or disabled");
    }
    Ok(())
}
