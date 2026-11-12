//! Protected local provisioning for confidential clients.

use std::io::{self, IsTerminal, Read};

use rs_keycloak_storage_postgres::{
    ClientAuthEntry, ClientAuthMaterial, ConfidentialRegistration, Storage, StorageError,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) async fn add_confidential_client(
    realm: &str,
    client_id: &str,
    redirect_uri: &str,
) -> Result<(), &'static str> {
    super::validate_client_input(realm, client_id, redirect_uri)?;
    let url = super::database_url()?;
    if io::stdin().is_terminal() {
        return Err("Supply the client secret through protected standard input, not a terminal");
    }
    let mut secret = Zeroizing::new(Vec::new());
    io::stdin()
        .take(1026)
        .read_to_end(&mut secret)
        .map_err(|_| "Could not read client secret")?;
    if secret.last() == Some(&b'\n') {
        secret.pop();
        if secret.last() == Some(&b'\r') {
            secret.pop();
        }
    }
    if secret.len() < super::minimum_secret_length(32)
        || secret.len() > 1024
        || secret.iter().any(|byte| matches!(byte, b'\n' | b'\r' | 0))
        || std::str::from_utf8(&secret).is_err()
    {
        return Err("Client secret must be 32-1024 UTF-8 bytes on a single line");
    }
    let storage = Storage::connect(&url)
        .await
        .map_err(|_| "Database check failed")?;
    let realm_id = storage
        .realm_id_by_name(realm)
        .await
        .map_err(|_| "Realm lookup failed")?
        .ok_or("Realm is missing or disabled")?;
    let (secret, hash) = tokio::task::spawn_blocking(move || {
        let hash = rs_keycloak_crypto::hash_password(&secret);
        (secret, hash)
    })
    .await
    .map_err(|_| "Client secret hashing failed")?;
    let hash = Zeroizing::new(hash.map_err(|_| "Client secret hashing failed")?);
    let result = storage
        .create_confidential_client(
            &realm_id,
            &Uuid::new_v4().to_string(),
            client_id,
            redirect_uri,
            hash.as_bytes(),
        )
        .await
        .map_err(|_| "Confidential client registration failed")?;
    if let ConfidentialRegistration::Existing {
        secret_phc,
        revision,
    } = result
    {
        let valid = tokio::task::spawn_blocking(move || {
            let encoded = std::str::from_utf8(&secret_phc).map_err(|_| ())?;
            rs_keycloak_crypto::verify_password(&secret, encoded).map_err(|_| ())
        })
        .await
        .map_err(|_| "Confidential client registration failed")?
        .map_err(|_| "Confidential client registration failed")?;
        if !valid {
            return Err("Confidential client registration conflicts with an existing client");
        }
        match storage
            .client_auth_material(&realm_id, client_id)
            .await
            .map_err(|_| "Confidential client registration failed")?
        {
            Some(ClientAuthEntry {
                material:
                    ClientAuthMaterial::Confidential {
                        revision: current, ..
                    },
                ..
            }) if current == revision => (),
            _ => return Err("Confidential client changed during registration"),
        }
    }
    Ok(())
}

/// Rotate only after verifying the old secret and rechecking its revision.
pub(crate) async fn rotate_client_secret(realm: &str, client_id: &str) -> Result<(), &'static str> {
    if realm.is_empty() || realm.len() > 255 || client_id.is_empty() || client_id.len() > 255 {
        return Err("Realm and client ID must be 1-255 bytes");
    }
    let url = super::database_url()?;
    if io::stdin().is_terminal() {
        return Err(
            "Supply the old and new client secrets through protected standard input, not a terminal",
        );
    }
    let mut input = Zeroizing::new(Vec::new());
    io::stdin()
        .take(2052)
        .read_to_end(&mut input)
        .map_err(|_| "Could not read client secrets")?;
    let mut lines = input.split(|byte| *byte == b'\n');
    let old = lines.next().ok_or("Two client secrets are required")?;
    let new = lines.next().ok_or("Two client secrets are required")?;
    if lines.next().is_some_and(|line| !line.is_empty()) || lines.next().is_some() {
        return Err("Exactly two client secrets are required");
    }
    let old = old.strip_suffix(b"\r").unwrap_or(old);
    let new = new.strip_suffix(b"\r").unwrap_or(new);
    for secret in [old, new] {
        if secret.len() < 32
            || secret.len() > 1024
            || secret.contains(&0)
            || secret.contains(&b'\r')
            || std::str::from_utf8(secret).is_err()
        {
            return Err("Client secrets must each be 32-1024 UTF-8 bytes on separate lines");
        }
    }
    let old = Zeroizing::new(old.to_vec());
    let new = Zeroizing::new(new.to_vec());
    let storage = Storage::connect(&url)
        .await
        .map_err(|_| "Database check failed")?;
    let realm_id = storage
        .realm_id_by_name(realm)
        .await
        .map_err(|_| "Realm lookup failed")?
        .ok_or("Realm is missing or disabled")?;
    let (secret_phc, revision) = match storage
        .client_auth_material(&realm_id, client_id)
        .await
        .map_err(|_| "Client lookup failed")?
    {
        Some(ClientAuthEntry {
            material:
                ClientAuthMaterial::Confidential {
                    secret_phc,
                    revision,
                },
            ..
        }) => (Zeroizing::new(secret_phc), revision),
        _ => return Err("Client secret rotation failed"),
    };
    let hash = tokio::task::spawn_blocking(move || {
        let encoded = std::str::from_utf8(&secret_phc).map_err(|_| ())?;
        if !rs_keycloak_crypto::verify_password(&old, encoded).map_err(|_| ())? {
            return Err(());
        }
        rs_keycloak_crypto::hash_password(&new).map_err(|_| ())
    })
    .await
    .map_err(|_| "Client secret rotation failed")?
    .map_err(|_| "Client secret rotation failed")?;
    let hash = Zeroizing::new(hash);
    if !storage
        .rotate_client_secret(&realm_id, client_id, revision, hash.as_bytes())
        .await
        .map_err(|_| "Client secret rotation failed")?
    {
        return Err("Client secret rotation failed");
    }
    Ok(())
}

/// Enables the client-credentials grant for an existing confidential client.
pub(crate) async fn enable_service_account(
    realm: &str,
    client_id: &str,
) -> Result<(), &'static str> {
    if realm.is_empty() || realm.len() > 255 || client_id.is_empty() || client_id.len() > 255 {
        return Err("Realm and client ID must be 1-255 bytes");
    }
    let storage = Storage::connect(&super::database_url()?)
        .await
        .map_err(|_| "Database check failed")?;
    let realm_id = storage
        .realm_id_by_name(realm)
        .await
        .map_err(|_| "Realm lookup failed")?
        .ok_or("Realm is missing or disabled")?;
    match storage
        .enable_service_account(&realm_id, client_id, &Uuid::new_v4().to_string())
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err("Client is missing, disabled, or public"),
        Err(StorageError::Conflict) => {
            Err("Another user already holds the service-account username")
        }
        Err(_) => Err("Service account setup failed"),
    }
}

/// Grants the master `admin` role to a master client's service account, so it
/// can call the admin API with client-credentials tokens.
pub(crate) async fn grant_master_admin(client_id: &str) -> Result<(), &'static str> {
    if client_id.is_empty() || client_id.len() > 255 {
        return Err("Client ID must be 1-255 bytes");
    }
    let storage = Storage::connect(&super::database_url()?)
        .await
        .map_err(|_| "Database check failed")?;
    match storage.grant_master_admin(client_id).await {
        Ok(true) => Ok(()),
        Ok(false) => Err("Master client is missing or has no service account"),
        Err(_) => Err("Admin role grant failed"),
    }
}
