//! Explicit browser origin registration.

use std::env;

use rs_keycloak_storage_postgres::Storage;

pub(crate) async fn add(realm: &str, client_id: &str, origin: &str) -> Result<(), &'static str> {
    if realm.is_empty()
        || realm.len() > 255
        || client_id.is_empty()
        || client_id.len() > 255
        || origin.len() > 2048
    {
        return Err("Realm, client ID, or origin is invalid");
    }
    let local = env::var("RS_KEYCLOAK_LOCAL_DEV").ok().as_deref() == Some("true");
    rs_keycloak_protocols::client_urls::validate_web_origin(origin, local)?;
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
