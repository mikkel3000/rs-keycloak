//! Admin events: a record of each successful admin API change in realms
//! with admin events on, written by one middleware around the admin
//! routes, and GET and DELETE `/admin/realms/{realm}/admin-events`. They
//! follow the reference's `AdminEventBuilder` uses and
//! `tests/reference/admin-event-observations.json`.

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, RawQuery, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rs_keycloak_storage_postgres::{
    AdminEventQuery, AdminEventRecord, EventSettings, NewAdminEvent,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::login_events::{all, ascending, paging, parameters, single, time_bound};
use super::{Access, AdminError, REALM_BODY_LIMIT, authorize, json_text, token_caller};
use crate::events::client_address;
use crate::oidc::OidcState;

pub(super) fn routes() -> Router<OidcState> {
    Router::new().route(
        "/admin/realms/{realm}/admin-events",
        get(list_events).delete(clear_events),
    )
}

/// What an admin request changes, as the reference's admin resources name
/// it in their events.
#[derive(Debug, PartialEq, Eq)]
struct Change {
    /// The realm changed; `None` for realm creation.
    realm: Option<String>,
    operation: &'static str,
    resource_type: &'static str,
    kind: Kind,
}

/// Where an event is stored and what its resource path is.
#[derive(Debug, PartialEq, Eq)]
enum Kind {
    /// A change inside the realm; the path is the request's below it, or
    /// for a creation the new resource's.
    Inside,
    /// The realm itself, created or deleted: stored in the acting token's
    /// realm with the realm name as path.
    Realm,
    /// The realm's own update: no path.
    RealmUpdate,
    /// The events config: stored when admin events were on before or are
    /// on after.
    EventsConfig,
}

/// Classifies an admin request; `None` for requests that record nothing.
fn classify(method: &Method, path: &str) -> Option<Change> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }
    let rest = path.strip_prefix("/admin/realms")?;
    if rest.is_empty() || rest == "/" {
        return (*method == Method::POST).then_some(Change {
            realm: None,
            operation: "CREATE",
            resource_type: "REALM",
            kind: Kind::Realm,
        });
    }
    let mut segments = rest.strip_prefix('/')?.split('/');
    let realm = segments.next()?.to_owned();
    let below: Vec<&str> = segments.collect();
    let by_method = match *method {
        Method::POST => "CREATE",
        Method::PUT => "UPDATE",
        Method::DELETE => "DELETE",
        _ => return None,
    };
    let change = |operation, resource_type, kind| {
        Some(Change {
            realm: Some(realm.clone()),
            operation,
            resource_type,
            kind,
        })
    };
    let mapping = |kind_segment: Option<&&str>| match kind_segment {
        Some(&"clients") => "CLIENT_ROLE_MAPPING",
        _ => "REALM_ROLE_MAPPING",
    };
    match below.as_slice() {
        [] => match *method {
            Method::PUT => change("UPDATE", "REALM", Kind::RealmUpdate),
            Method::DELETE => change("DELETE", "REALM", Kind::Realm),
            _ => None,
        },
        ["events", "config"] => change("UPDATE", "REALM", Kind::EventsConfig),
        // Clearing events, exports and imports record nothing here.
        ["events"] | ["admin-events"] | ["partial-export"] | ["partial-import"] => None,
        [
            "users",
            _,
            "reset-password" | "logout" | "execute-actions-email" | "send-verify-email",
        ]
        | ["users", _, "credentials" | "consents", _] => change("ACTION", "USER", Kind::Inside),
        ["users", _, "groups", _] => change(
            if *method == Method::DELETE {
                "DELETE"
            } else {
                "CREATE"
            },
            "GROUP_MEMBERSHIP",
            Kind::Inside,
        ),
        ["users" | "groups", _, "role-mappings", rest @ ..] => {
            change(by_method, mapping(rest.first()), Kind::Inside)
        }
        ["users", ..] => change(by_method, "USER", Kind::Inside),
        ["clients", _, "client-secret"] => change("ACTION", "CLIENT", Kind::Inside),
        ["clients", _, "roles", ..] => change(by_method, "CLIENT_ROLE", Kind::Inside),
        ["clients", _, "protocol-mappers", ..] => {
            change(by_method, "PROTOCOL_MAPPER", Kind::Inside)
        }
        [
            "clients",
            _,
            "default-client-scopes" | "optional-client-scopes",
            ..,
        ] => change(by_method, "CLIENT_SCOPE_CLIENT_MAPPING", Kind::Inside),
        ["clients", ..] => change(by_method, "CLIENT", Kind::Inside),
        ["roles" | "roles-by-id", ..] => change(by_method, "REALM_ROLE", Kind::Inside),
        ["groups", ..] => change(by_method, "GROUP", Kind::Inside),
        [
            "client-scopes" | "default-default-client-scopes" | "default-optional-client-scopes",
            ..,
        ] => change(by_method, "CLIENT_SCOPE", Kind::Inside),
        ["authentication", "required-actions", ..] => {
            change(by_method, "REQUIRED_ACTION", Kind::Inside)
        }
        ["localization", ..] => change(by_method, "REALM_LOCALIZATION", Kind::Inside),
        ["attack-detection", ..] => change(by_method, "USER_LOGIN_FAILURE", Kind::Inside),
        ["sessions", ..] => change(by_method, "USER_SESSION", Kind::Inside),
        _ => change(by_method, "REALM", Kind::Inside),
    }
}

/// The request representation an event keeps: the JSON body without
/// credentials and with client secrets masked, as the reference strips
/// them. An events config always has `eventsEnabled`, a plain boolean in
/// the reference's representation.
fn representation(body: &[u8], events_config: bool) -> Option<String> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    if let Value::Object(fields) = &mut value {
        if events_config {
            fields.entry("eventsEnabled").or_insert(json!(false));
        }
        fields.remove("credentials");
        if fields.get("secret").is_some_and(Value::is_string) {
            fields.insert("secret".into(), json!("**********"));
        }
    }
    Some(value.to_string())
}

/// The path of a created resource below its realm, from the `Location`
/// header.
fn created_path(location: Option<&str>, realm: &str) -> Option<String> {
    let location = location?;
    let marker = format!("/admin/realms/{realm}/");
    let start = location.find(&marker)? + marker.len();
    Some(location[start..].to_owned())
}

/// Records an admin event for each successful change the admin routes
/// make. The event is written after the change commits; a failed write
/// answers 503 although the change stays.
pub(super) async fn record(
    State(state): State<OidcState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(change) = classify(request.method(), request.uri().path()) else {
        return next.run(request).await;
    };
    let path = request.uri().path().to_owned();
    let headers = request.headers().clone();
    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, REALM_BODY_LIMIT).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let before = match &change.realm {
        Some(realm) => match state.storage.realm_event_settings(realm).await {
            Ok(settings) => settings,
            Err(_) => return AdminError::Unavailable.into_response(),
        },
        None => None,
    };
    let response = next
        .run(Request::from_parts(parts, Body::from(body.clone())))
        .await;
    if !response.status().is_success() {
        return response;
    }
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    match write(
        &state,
        &headers,
        &change,
        &path,
        &body,
        before,
        location.as_deref(),
    )
    .await
    {
        Ok(()) => response,
        Err(error) => error.into_response(),
    }
}

async fn write(
    state: &OidcState,
    headers: &HeaderMap,
    change: &Change,
    path: &str,
    body: &Bytes,
    before: Option<(String, EventSettings)>,
    location: Option<&str>,
) -> Result<(), AdminError> {
    let Ok((token_realm, actor, client)) = token_caller(state, headers).await else {
        return Ok(());
    };
    let (realm_id, settings, resource_path) = match change.kind {
        Kind::Realm => {
            let name = match &change.realm {
                Some(realm) => realm.clone(),
                None => location
                    .and_then(|location| location.rsplit('/').next())
                    .unwrap_or_default()
                    .to_owned(),
            };
            let Some((realm_id, settings)) =
                state.storage.realm_event_settings(&token_realm).await?
            else {
                return Ok(());
            };
            if !settings.admin_events_enabled {
                return Ok(());
            }
            (realm_id, settings, Some(name))
        }
        Kind::Inside | Kind::RealmUpdate | Kind::EventsConfig => {
            let (Some(realm), Some((realm_id, before))) = (&change.realm, before) else {
                return Ok(());
            };
            let after = state
                .storage
                .realm_event_settings(realm)
                .await?
                .map(|(_, after)| after);
            let stored = before.admin_events_enabled
                || (change.kind == Kind::EventsConfig
                    && after
                        .as_ref()
                        .is_some_and(|after| after.admin_events_enabled));
            if !stored {
                return Ok(());
            }
            let resource_path = match change.kind {
                Kind::RealmUpdate => None,
                _ if change.operation == "CREATE" => created_path(location, realm).or_else(|| {
                    path.split_once(&format!("/admin/realms/{realm}/"))
                        .map(|(_, rest)| rest.to_owned())
                }),
                _ => path
                    .split_once(&format!("/admin/realms/{realm}/"))
                    .map(|(_, rest)| rest.to_owned()),
            };
            (realm_id, after.unwrap_or(before), resource_path)
        }
    };
    // As AdminEventBuilder.send, the details setting is read when the event
    // is sent, after the change.
    let representation = (settings.admin_events_details_enabled
        && matches!(change.operation, "CREATE" | "UPDATE"))
    .then(|| representation(body, change.kind == Kind::EventsConfig))
    .flatten();
    let address = client_address();
    state
        .storage
        .record_admin_event(&NewAdminEvent {
            id: &Uuid::new_v4().to_string(),
            realm_id: &realm_id,
            operation_type: change.operation,
            resource_type: change.resource_type,
            resource_path: resource_path.as_deref(),
            representation: representation.as_deref(),
            auth_realm_id: &actor.realm_id,
            auth_client: &client,
            auth_user_id: &actor.user_id,
            ip_address: address.as_deref(),
        })
        .await?;
    Ok(())
}

fn event_representation(event: &AdminEventRecord) -> Value {
    let mut auth = json!({ "realmId": event.auth_realm_id, "userId": event.auth_user_id });
    if let Some(client) = &event.auth_client_id {
        auth["clientId"] = json!(client);
    }
    if let Some(address) = &event.ip_address {
        auth["ipAddress"] = json!(address);
    }
    let mut value = json!({
        "id": event.id,
        "time": event.time,
        "realmId": event.realm_id,
        "authDetails": auth,
        "operationType": event.operation_type,
        "resourceType": event.resource_type,
    });
    if let Some(path) = &event.resource_path {
        value["resourcePath"] = json!(path);
    }
    if let Some(representation) = &event.representation {
        value["representation"] = json!(representation);
    }
    value
}

async fn realm_id(state: &OidcState, realm: &str) -> Result<String, AdminError> {
    state
        .storage
        .realm_id_by_name(realm)
        .await?
        .ok_or(AdminError::RealmNotFound)
}

async fn list_events(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    authorize(&state, &headers, &realm, Access::ViewEvents).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let parameters = parameters(query.as_deref());
    let (first, max) = paging(&parameters)?;
    let owned = |name| single(&parameters, name).map(str::to_owned);
    let query = AdminEventQuery {
        operation_types: all(&parameters, "operationTypes"),
        resource_types: all(&parameters, "resourceTypes"),
        resource_path: owned("resourcePath"),
        auth_realm: owned("authRealm"),
        auth_client: owned("authClient"),
        auth_user: owned("authUser"),
        auth_ip_address: owned("authIpAddress"),
        from: time_bound(&parameters, "dateFrom", false)?,
        to: time_bound(&parameters, "dateTo", true)?,
        first,
        max,
        ascending: ascending(&parameters)?,
    };
    let events = state.storage.admin_events(&realm_id, &query).await?;
    Ok(json_text(&Value::Array(
        events.iter().map(event_representation).collect(),
    )))
}

async fn clear_events(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm, Access::ManageEvents).await?;
    let realm_id = realm_id(&state, &realm).await?;
    state.storage.clear_admin_events(&realm_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(method: Method, path: &str) -> Option<(&'static str, &'static str)> {
        classify(&method, path).map(|change| (change.operation, change.resource_type))
    }

    #[test]
    fn requests_map_to_the_reference_resource_types() {
        assert_eq!(
            kind(Method::POST, "/admin/realms"),
            Some(("CREATE", "REALM"))
        );
        assert_eq!(kind(Method::GET, "/admin/realms/r/users"), None);
        assert_eq!(
            kind(Method::POST, "/admin/realms/r/users"),
            Some(("CREATE", "USER"))
        );
        assert_eq!(
            kind(Method::PUT, "/admin/realms/r/users/u/reset-password"),
            Some(("ACTION", "USER"))
        );
        assert_eq!(
            kind(Method::PUT, "/admin/realms/r/users/u/groups/g"),
            Some(("CREATE", "GROUP_MEMBERSHIP"))
        );
        assert_eq!(
            kind(
                Method::POST,
                "/admin/realms/r/users/u/role-mappings/clients/c"
            ),
            Some(("CREATE", "CLIENT_ROLE_MAPPING"))
        );
        assert_eq!(
            kind(
                Method::POST,
                "/admin/realms/r/clients/c/protocol-mappers/models"
            ),
            Some(("CREATE", "PROTOCOL_MAPPER"))
        );
        assert_eq!(
            kind(Method::PUT, "/admin/realms/r/events/config"),
            Some(("UPDATE", "REALM"))
        );
        assert_eq!(kind(Method::DELETE, "/admin/realms/r/admin-events"), None);
        assert_eq!(
            kind(Method::DELETE, "/admin/realms/r"),
            Some(("DELETE", "REALM"))
        );
    }

    #[test]
    fn representations_drop_credentials_and_mask_secrets() {
        let kept = representation(
            br#"{"username":"a","credentials":[{"value":"p"}],"secret":"s"}"#,
            false,
        );
        assert_eq!(
            kept.as_deref(),
            Some(r#"{"secret":"**********","username":"a"}"#)
        );
        assert_eq!(representation(b"not json", false), None);
    }
}
