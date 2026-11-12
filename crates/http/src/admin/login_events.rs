//! Listing and clearing a realm's stored login events with GET and DELETE
//! `/admin/realms/{realm}/events`, following `RealmAdminResource.getEvents`
//! and `tests/reference/login-event-observations.json`.

use axum::Router;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use rs_keycloak_storage_postgres::{LoginEventQuery, LoginEventRecord};
use serde_json::{Value, json};

use super::{Access, AdminError, authorize, json_text};
use crate::oidc::OidcState;

pub(super) fn routes() -> Router<OidcState> {
    Router::new().route(
        "/admin/realms/{realm}/events",
        get(list_events).delete(clear_events),
    )
}

/// The reference's `Constants.DEFAULT_MAX_RESULTS`.
pub(super) const DEFAULT_MAX_RESULTS: i64 = 100;

/// The query parameters of an event listing, each name with its values in
/// order.
pub(super) fn parameters(query: Option<&str>) -> Vec<(String, String)> {
    url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

/// The last value of a parameter, as JAX-RS takes a single one.
pub(super) fn single<'a>(parameters: &'a [(String, String)], name: &str) -> Option<&'a str> {
    parameters
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Every value of a parameter.
pub(super) fn all(parameters: &[(String, String)], name: &str) -> Vec<String> {
    parameters
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .collect()
}

/// Days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The epoch day of a `yyyy-MM-dd` date, as `LocalDate.parse` reads it.
fn epoch_day(date: &str) -> Option<i64> {
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| {
        let text = &date[range];
        text.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| text.parse::<i64>().ok())
            .flatten()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let length = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (1..=length)
        .contains(&day)
        .then(|| days_from_civil(year, month, day))
}

/// A `dateFrom` or `dateTo` value as `DateUtil` reads it: a date with a
/// dash is the start or the end of that UTC day, anything else epoch
/// milliseconds.
pub(super) fn time_bound(
    parameters: &[(String, String)],
    name: &'static str,
    end_of_day: bool,
) -> Result<Option<i64>, AdminError> {
    let Some(value) = single(parameters, name) else {
        return Ok(None);
    };
    let invalid = || {
        AdminError::Error(
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid value for '{name}', expected format is yyyy-MM-dd or an Epoch timestamp"
            ),
        )
    };
    if value.contains('-') {
        let day = epoch_day(value).ok_or_else(invalid)?;
        let start = day * 86_400_000;
        Ok(Some(if end_of_day {
            start + 86_399_999
        } else {
            start
        }))
    } else {
        value.parse::<i64>().map(Some).map_err(|_| invalid())
    }
}

/// The order of a listing: newest first unless `direction=asc`.
pub(super) fn ascending(parameters: &[(String, String)]) -> Result<bool, AdminError> {
    match single(parameters, "direction") {
        None | Some("desc") => Ok(false),
        Some("asc") => Ok(true),
        Some(_) => Err(AdminError::Error(
            StatusCode::BAD_REQUEST,
            "Invalid value for sortDirection, expected value is asc or desc".to_owned(),
        )),
    }
}

/// `first` and `max`; a negative `max` lists every event.
pub(super) fn paging(parameters: &[(String, String)]) -> Result<(i64, i64), AdminError> {
    let number = |name: &str, default: i64| match single(parameters, name) {
        None => Ok(default),
        Some(value) => value
            .parse::<i64>()
            .map_err(|_| AdminError::bad_request(format!("Invalid value for '{name}'"))),
    };
    let first = number("first", 0)?.max(0);
    let max = number("max", DEFAULT_MAX_RESULTS)?;
    Ok((first, if max < 0 { i64::MAX } else { max }))
}

fn representation(event: &LoginEventRecord) -> Value {
    let mut value = json!({
        "id": event.id,
        "time": event.time,
        "type": event.event_type,
        "realmId": event.realm_id,
    });
    let optional = [
        ("clientId", &event.client_id),
        ("userId", &event.user_id),
        ("sessionId", &event.session_id),
        ("ipAddress", &event.ip_address),
        ("error", &event.error),
    ];
    for (name, field) in optional {
        if let Some(field) = field {
            value[name] = json!(field);
        }
    }
    if let Ok(Value::Object(details)) = serde_json::from_str::<Value>(&event.details)
        && !details.is_empty()
    {
        value["details"] = Value::Object(details);
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
    let query = LoginEventQuery {
        types: all(&parameters, "type"),
        client: single(&parameters, "client").map(str::to_owned),
        user: single(&parameters, "user").map(str::to_owned),
        ip_address: single(&parameters, "ipAddress").map(str::to_owned),
        from: time_bound(&parameters, "dateFrom", false)?,
        to: time_bound(&parameters, "dateTo", true)?,
        first,
        max,
        ascending: ascending(&parameters)?,
    };
    let events = state.storage.login_events(&realm_id, &query).await?;
    Ok(json_text(&Value::Array(
        events.iter().map(representation).collect(),
    )))
}

async fn clear_events(
    State(state): State<OidcState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, AdminError> {
    authorize(&state, &headers, &realm, Access::ManageEvents).await?;
    let realm_id = realm_id(&state, &realm).await?;
    state.storage.clear_login_events(&realm_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_utc_days() {
        assert_eq!(epoch_day("1970-01-01"), Some(0));
        assert_eq!(epoch_day("2026-11-12"), Some(20_769));
        assert_eq!(epoch_day("2024-02-29"), Some(19_782));
        assert_eq!(epoch_day("2023-02-29"), None);
        assert_eq!(epoch_day("yesterday"), None);
    }
}
