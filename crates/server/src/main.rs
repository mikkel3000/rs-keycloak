use std::env;
use std::io::{self, IsTerminal, Read};
use std::net::SocketAddr;
use std::process::ExitCode;

use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const USAGE: &str = "Usage: rs-keycloak <serve|config check|db check|db migrate|bootstrap-admin <username>|version>";

struct Config {
    database_url: String,
    management_listen: SocketAddr,
}

fn database_url() -> Result<String, &'static str> {
    let value =
        env::var("RS_KEYCLOAK_DATABASE_URL").map_err(|_| "RS_KEYCLOAK_DATABASE_URL is required")?;
    let parsed = Url::parse(&value).map_err(|_| "RS_KEYCLOAK_DATABASE_URL is invalid")?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") || parsed.host_str().is_none() {
        return Err("RS_KEYCLOAK_DATABASE_URL must be a PostgreSQL URL with a host");
    }
    let local_dev = env::var("RS_KEYCLOAK_LOCAL_DEV").ok().as_deref() == Some("true");
    let host = parsed.host_str().unwrap_or_default();
    let local_host = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    // SQLx accepts query overrides for authority and startup settings. Restrict
    // this surface so the validated host, TLS and durability cannot change.
    for (key, _) in parsed.query_pairs() {
        if !matches!(
            key.as_ref(),
            "sslmode"
                | "ssl-mode"
                | "sslrootcert"
                | "ssl-root-cert"
                | "ssl-ca"
                | "sslcert"
                | "ssl-cert"
                | "sslkey"
                | "ssl-key"
                | "application_name"
                | "statement-cache-capacity"
        ) {
            return Err(
                "Unsupported database URL query option; configure host and identity in the URL authority",
            );
        }
    }
    let ssl_modes: Vec<_> = parsed
        .query_pairs()
        .filter(|(key, _)| key == "sslmode" || key == "ssl-mode")
        .collect();
    if ssl_modes.len() > 1 {
        return Err("RS_KEYCLOAK_DATABASE_URL must specify sslmode at most once");
    }
    if !(local_dev && local_host)
        && !matches!(ssl_modes.first(), Some((_, mode)) if mode == "verify-full")
    {
        return Err(
            "RS_KEYCLOAK_DATABASE_URL requires sslmode=verify-full; local databases may use RS_KEYCLOAK_LOCAL_DEV=true",
        );
    }
    Ok(value)
}

fn config() -> Result<Config, &'static str> {
    for (key, _) in env::vars_os() {
        let key = key.to_string_lossy();
        if key.starts_with("RS_KEYCLOAK_")
            && !matches!(
                key.as_ref(),
                "RS_KEYCLOAK_DATABASE_URL"
                    | "RS_KEYCLOAK_ISSUER"
                    | "RS_KEYCLOAK_MANAGEMENT_LISTEN"
                    | "RS_KEYCLOAK_LOCAL_DEV"
                    | "RS_KEYCLOAK_ALLOW_REMOTE_MANAGEMENT"
            )
        {
            return Err("Unknown RS_KEYCLOAK_ environment variable");
        }
    }
    for key in [
        "RS_KEYCLOAK_LOCAL_DEV",
        "RS_KEYCLOAK_ALLOW_REMOTE_MANAGEMENT",
    ] {
        if let Ok(value) = env::var(key)
            && value != "true"
            && value != "false"
        {
            return Err("Boolean RS_KEYCLOAK_ settings must be true or false");
        }
    }
    let database_url = database_url()?;
    let issuer = env::var("RS_KEYCLOAK_ISSUER").map_err(|_| "RS_KEYCLOAK_ISSUER is required")?;
    let issuer = Url::parse(&issuer).map_err(|_| "RS_KEYCLOAK_ISSUER is invalid")?;
    if issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(
            "RS_KEYCLOAK_ISSUER must be an HTTPS URL without credentials, query, or fragment",
        );
    }
    let management_listen = env::var("RS_KEYCLOAK_MANAGEMENT_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:9000".to_owned())
        .parse::<SocketAddr>()
        .map_err(|_| "RS_KEYCLOAK_MANAGEMENT_LISTEN must be an IP address and port")?;
    if !management_listen.ip().is_loopback()
        && env::var("RS_KEYCLOAK_ALLOW_REMOTE_MANAGEMENT")
            .ok()
            .as_deref()
            != Some("true")
    {
        return Err("Remote management binding requires RS_KEYCLOAK_ALLOW_REMOTE_MANAGEMENT=true");
    }
    Ok(Config {
        database_url,
        management_listen,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), &'static str> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["version"] | ["--version"] => println!("rs-keycloak {}", env!("CARGO_PKG_VERSION")),
        ["--help"] | ["-h"] => println!("{USAGE}"),
        ["config", "check"] => {
            config()?;
            println!("Configuration is valid");
        }
        ["db", "check"] => {
            rs_keycloak_storage_postgres::check(&database_url()?)
                .await
                .map_err(|_| "Database check failed")?;
            println!("Database check passed");
        }
        ["db", "migrate"] => {
            rs_keycloak_storage_postgres::migrate(&database_url()?)
                .await
                .map_err(|_| "Database migration failed")?;
            println!("Database migration complete");
        }
        ["bootstrap-admin", username] => {
            bootstrap_admin(username).await?;
            println!(
                "Bootstrap admin record created; sign-in and admin handover are not implemented"
            );
        }
        ["serve"] => {
            let config = config()?;
            rs_keycloak_storage_postgres::check(&config.database_url)
                .await
                .map_err(|_| "Database check failed")?;
            let listener = tokio::net::TcpListener::bind(config.management_listen)
                .await
                .map_err(|_| "Management listener failed")?;
            eprintln!(
                "Management listener started; authentication is not implemented and readiness remains closed"
            );
            axum::serve(listener, rs_keycloak_http::management_router())
                .with_graceful_shutdown(shutdown_signal())
                .await
                .map_err(|_| "Management server failed")?;
        }
        _ => return Err(USAGE),
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

// The password must be supplied on a pipe or other protected input descriptor;
// terminal input would echo and expose it. Bound input before hashing.
async fn bootstrap_admin(username: &str) -> Result<(), &'static str> {
    if username.is_empty()
        || username.len() > 255
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        return Err("Bootstrap username must be 1-255 ASCII letters, digits, or ._-@");
    }
    let url = database_url()?;
    if io::stdin().is_terminal() {
        return Err(
            "Supply the bootstrap password through protected standard input, not a terminal",
        );
    }
    let mut password = Zeroizing::new(Vec::new());
    io::stdin()
        .take(1026)
        .read_to_end(&mut password)
        .map_err(|_| "Could not read bootstrap password")?;
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if password.len() < 12
        || password.len() > 1024
        || password
            .iter()
            .any(|byte| matches!(byte, b'\n' | b'\r' | 0))
    {
        return Err("Bootstrap password must be 12-1024 bytes on a single line");
    }
    let hash = tokio::task::spawn_blocking(move || rs_keycloak_crypto::hash_password(&password))
        .await
        .map_err(|_| "Password hashing failed")?
        .map_err(|_| "Password hashing failed")?;
    let storage = rs_keycloak_storage_postgres::Storage::connect(&url)
        .await
        .map_err(|_| "Database check failed")?;
    storage
        .bootstrap_admin(
            &Uuid::new_v4().to_string(),
            &Uuid::new_v4().to_string(),
            username,
            &username.to_ascii_lowercase(),
            hash.as_bytes(),
        )
        .await
        .map_err(|error| match error {
            rs_keycloak_storage_postgres::StorageError::AlreadyBootstrapped => {
                "Bootstrap admin already exists or the master realm is initialized"
            }
            _ => "Bootstrap admin creation failed",
        })?;
    Ok(())
}
