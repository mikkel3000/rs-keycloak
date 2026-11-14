//! Client protocol mappers: the `protocolMappers` of client
//! representations and the `/protocol-mappers` admin resources, following
//! `ProtocolMappersResource` and
//! `tests/reference/protocol-mapper-observations.json`. The OpenID Connect
//! audience mapper is the one mapper type; tokens apply it.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use rs_keycloak_storage_postgres::{MapperCreation, NewProtocolMapper, ProtocolMapperRecord};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::users::{json_response, realm_id, unparsable};
use super::{Access, AdminError, authorize};
use crate::oidc::OidcState;

pub(super) fn routes() -> Router<OidcState> {
    Router::new()
        .route(
            "/admin/realms/{realm}/clients/{client}/protocol-mappers/models",
            get(list).post(create),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/protocol-mappers/models/{id}",
            get(read).put(update).delete(delete),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/protocol-mappers/protocol/{protocol}",
            get(list_protocol),
        )
        .route(
            "/admin/realms/{realm}/clients/{client}/protocol-mappers/add-models",
            post(create_many),
        )
}

/// The mapper types this server applies.
const MAPPER_TYPES: [&str; 1] = ["oidc-audience-mapper"];

/// The protocols this server serves.
const PROTOCOLS: [&str; 1] = ["openid-connect"];

/// Fields of a mapper representation; `consentRequired` and `consentText`
/// are read and dropped, as the reference no longer keeps them.
const FIELDS: [&str; 7] = [
    "id",
    "name",
    "protocol",
    "protocolMapper",
    "consentRequired",
    "consentText",
    "config",
];

/// A parsed mapper representation.
pub(super) struct MapperInput {
    id: String,
    name: String,
    protocol: String,
    mapper_type: String,
    config: String,
}

impl MapperInput {
    pub(super) fn stored(&self) -> NewProtocolMapper<'_> {
        NewProtocolMapper {
            id: &self.id,
            name: &self.name,
            protocol: &self.protocol,
            mapper_type: &self.mapper_type,
            config: &self.config,
        }
    }
}

/// The reference's answer to a mapper without a name or protocol, which
/// its database refuses as a constraint violation.
fn missing_column() -> AdminError {
    AdminError::OAuth(StatusCode::CONFLICT, "conflict", "Duplicate resource error")
}

fn text(fields: &Map<String, Value>, name: &str) -> Result<Option<String>, AdminError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() <= 255 => Ok(Some(value.clone())),
        Some(_) => Err(unparsable()),
    }
}

/// Reads one mapper representation. `unknown_type` is the error for a
/// mapper type this server does not have: the models resource answers 404
/// as the reference does, client representations a 400 naming the type.
fn parse(value: &Value, unknown_type: fn(&str) -> AdminError) -> Result<MapperInput, AdminError> {
    let Value::Object(fields) = value else {
        return Err(unparsable());
    };
    if let Some(field) = fields.keys().find(|key| !FIELDS.contains(&key.as_str())) {
        return Err(AdminError::bad_request(format!(
            "Unsupported protocol mapper field: {field}"
        )));
    }
    let mapper_type = text(fields, "protocolMapper")?.unwrap_or_default();
    if !MAPPER_TYPES.contains(&mapper_type.as_str()) {
        return Err(unknown_type(&mapper_type));
    }
    let name = text(fields, "name")?.filter(|name| !name.is_empty());
    let protocol = text(fields, "protocol")?.filter(|protocol| !protocol.is_empty());
    let (Some(name), Some(protocol)) = (name, protocol) else {
        return Err(missing_column());
    };
    if !PROTOCOLS.contains(&protocol.as_str()) {
        return Err(AdminError::bad_request(format!(
            "Unsupported protocol mapper protocol: {protocol}"
        )));
    }
    if !matches!(
        fields.get("consentRequired"),
        None | Some(Value::Null | Value::Bool(_))
    ) {
        return Err(unparsable());
    }
    let config = match fields.get("config") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(config)) if config.len() <= 64 => {
            if config.iter().any(|(key, value)| {
                key.len() > 255 || !value.as_str().is_some_and(|v| v.len() <= 4096)
            }) {
                return Err(unparsable());
            }
            config.clone()
        }
        Some(_) => return Err(unparsable()),
    };
    Ok(MapperInput {
        id: Uuid::new_v4().to_string(),
        name,
        protocol,
        mapper_type,
        config: Value::Object(config).to_string(),
    })
}

fn provider_not_found(_: &str) -> AdminError {
    AdminError::Error(
        StatusCode::NOT_FOUND,
        "ProtocolMapper provider not found".into(),
    )
}

fn unsupported_type(mapper_type: &str) -> AdminError {
    AdminError::bad_request(format!("Unsupported protocol mapper: {mapper_type}"))
}

/// Reads the `protocolMappers` of a client representation, or `None` when
/// absent.
pub(super) fn parse_client_mappers(
    fields: &Map<String, Value>,
) -> Result<Option<Vec<MapperInput>>, AdminError> {
    match fields.get("protocolMappers") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(mappers)) if mappers.len() <= 64 => mappers
            .iter()
            .map(|mapper| parse(mapper, unsupported_type))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(unparsable()),
    }
}

/// A mapper's representation. The models resources show the effective
/// configuration of `AbstractOIDCProtocolMapper.getEffectiveModel`: with
/// `access.token.claim` set, `introspection.token.claim` defaults to it,
/// and with `id.token.claim` set, `userinfo.token.claim` defaults to it.
pub(super) fn representation(mapper: &ProtocolMapperRecord, effective: bool) -> Value {
    let mut config = match serde_json::from_str::<Value>(&mapper.config) {
        Ok(Value::Object(config)) => config,
        _ => Map::new(),
    };
    if effective {
        for (set, derived) in [
            ("access.token.claim", "introspection.token.claim"),
            ("id.token.claim", "userinfo.token.claim"),
        ] {
            if let Some(value) = config.get(set).cloned() {
                let included = config
                    .get(derived)
                    .map_or(value == json!("true"), |derived| derived == &json!("true"));
                config.insert(derived.into(), json!(included.to_string()));
            }
        }
    }
    json!({
        "id": mapper.id,
        "name": mapper.name,
        "protocol": mapper.protocol,
        "protocolMapper": mapper.mapper_type,
        "consentRequired": false,
        "config": config,
    })
}

fn model_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "Model not found".into())
}

fn client_not_found() -> AdminError {
    AdminError::Error(StatusCode::NOT_FOUND, "Could not find client".into())
}

async fn mappers(
    state: &OidcState,
    realm: &str,
    client: &str,
    headers: &HeaderMap,
) -> Result<Vec<ProtocolMapperRecord>, AdminError> {
    authorize(state, headers, realm, Access::ViewClients).await?;
    let realm_id = realm_id(state, realm).await?;
    state
        .storage
        .protocol_mappers(&realm_id, client)
        .await?
        .ok_or_else(client_not_found)
}

async fn list(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let mappers = mappers(&state, &realm, &client, &headers).await?;
    Ok(json_response(Value::Array(
        mappers
            .iter()
            .map(|mapper| representation(mapper, true))
            .collect(),
    )))
}

async fn list_protocol(
    State(state): State<OidcState>,
    Path((realm, client, protocol)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let mappers = mappers(&state, &realm, &client, &headers).await?;
    Ok(json_response(Value::Array(
        mappers
            .iter()
            .filter(|mapper| mapper.protocol == protocol)
            .map(|mapper| representation(mapper, true))
            .collect(),
    )))
}

async fn read(
    State(state): State<OidcState>,
    Path((realm, client, id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let mappers = mappers(&state, &realm, &client, &headers).await?;
    let mapper = mappers
        .iter()
        .find(|mapper| mapper.id == id)
        .ok_or_else(model_not_found)?;
    Ok(json_response(representation(mapper, true)))
}

async fn add(
    state: &OidcState,
    realm: &str,
    client: &str,
    headers: &HeaderMap,
    inputs: &[MapperInput],
) -> Result<(), AdminError> {
    authorize(state, headers, realm, Access::ManageClients).await?;
    let realm_id = realm_id(state, realm).await?;
    let stored: Vec<_> = inputs.iter().map(MapperInput::stored).collect();
    match state
        .storage
        .create_protocol_mappers(&realm_id, client, &stored)
        .await?
    {
        MapperCreation::Created => Ok(()),
        MapperCreation::NameTaken => Err(AdminError::Message(
            StatusCode::CONFLICT,
            "Protocol mapper exists with same name".into(),
        )),
        MapperCreation::ClientNotFound => Err(client_not_found()),
    }
}

async fn create(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AdminError> {
    let value: Value = serde_json::from_slice(&body).map_err(|_| unparsable())?;
    let input = parse(&value, provider_not_found)?;
    add(
        &state,
        &realm,
        &client,
        &headers,
        std::slice::from_ref(&input),
    )
    .await?;
    let location = format!(
        "{}/admin/realms/{realm}/clients/{client}/protocol-mappers/models/{}",
        state.issuer_base.trim_end_matches('/'),
        input.id
    );
    let location = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
    Ok((StatusCode::CREATED, [(header::LOCATION, location)]).into_response())
}

async fn create_many(
    State(state): State<OidcState>,
    Path((realm, client)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    let Ok(Value::Array(values)) = serde_json::from_slice::<Value>(&body) else {
        return Err(unparsable());
    };
    if values.len() > 64 {
        return Err(unparsable());
    }
    let inputs = values
        .iter()
        .map(|value| parse(value, provider_not_found))
        .collect::<Result<Vec<_>, _>>()?;
    add(&state, &realm, &client, &headers, &inputs).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Replaces a mapper's configuration. As the reference's store, the name,
/// protocol and type keep their stored values.
async fn update(
    State(state): State<OidcState>,
    Path((realm, client, id)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm, Access::ManageClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    let mappers = state
        .storage
        .protocol_mappers(&realm_id, &client)
        .await?
        .ok_or_else(client_not_found)?;
    let stored = mappers
        .iter()
        .find(|mapper| mapper.id == id)
        .ok_or_else(model_not_found)?;
    let value: Value = serde_json::from_slice(&body).map_err(|_| unparsable())?;
    if value
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|given| given != id)
    {
        return Err(AdminError::bad_request(
            "Protocol mapper id does not match path id",
        ));
    }
    let input = parse(&value, provider_not_found)?;
    if input.mapper_type != stored.mapper_type {
        return Err(AdminError::bad_request(
            "Changing a protocol mapper's type is not supported",
        ));
    }
    if !state
        .storage
        .update_protocol_mapper_config(&realm_id, &client, &id, &input.config)
        .await?
    {
        return Err(model_not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete(
    State(state): State<OidcState>,
    Path((realm, client, id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm, Access::ManageClients).await?;
    let realm_id = realm_id(&state, &realm).await?;
    if state
        .storage
        .delete_protocol_mapper(&realm_id, &client, &id)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(model_not_found())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(config: Value) -> ProtocolMapperRecord {
        ProtocolMapperRecord {
            id: "m".into(),
            name: "audience".into(),
            protocol: "openid-connect".into(),
            mapper_type: "oidc-audience-mapper".into(),
            config: config.to_string(),
        }
    }

    #[test]
    fn effective_configuration_derives_introspection_and_userinfo() {
        let shown = representation(&record(json!({"access.token.claim": "true"})), true);
        assert_eq!(shown["config"]["introspection.token.claim"], json!("true"));
        let kept = representation(
            &record(json!({"access.token.claim": "true", "introspection.token.claim": "false"})),
            true,
        );
        assert_eq!(kept["config"]["introspection.token.claim"], json!("false"));
        let stored = representation(&record(json!({"id.token.claim": "true"})), false);
        assert!(stored["config"].get("userinfo.token.claim").is_none());
    }
}
