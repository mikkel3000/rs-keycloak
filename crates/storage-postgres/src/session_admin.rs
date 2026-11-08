//! Admin listing and ending of user sessions.

use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::logout::end_session;
use crate::{Actor, Storage, StorageError, audit};

/// A live user session with the fields of the admin representation.
pub struct SessionRecord {
    /// Session identifier.
    pub id: String,
    /// The signed-in user.
    pub user_id: String,
    /// The user's username.
    pub username: String,
    /// Start time in Unix milliseconds.
    pub started: i64,
    /// Latest start or token refresh in Unix milliseconds.
    pub last_access: i64,
    /// Whether the user asked to be remembered.
    pub remember_me: bool,
    /// Clients in the session as `(internal id, public identifier)`.
    pub clients: Vec<(String, String)>,
}

/// One client's live session count.
pub struct ClientSessionCount {
    /// Internal client identifier.
    pub id: String,
    /// Public client identifier.
    pub client_identifier: String,
    /// Live user sessions that include the client.
    pub active: i64,
    /// Live offline sessions of the client.
    pub offline: i64,
}

/// Live sessions with their columns; `$1` is the realm and the caller adds
/// the remaining conditions on `us`.
const SESSION_SELECT: &str = "SELECT us.id, us.user_id, u.username, us.remember_me, floor(EXTRACT(EPOCH FROM us.created_at) * 1000)::bigint AS started, floor(EXTRACT(EPOCH FROM GREATEST(us.created_at, (SELECT max(t.consumed_at) FROM refresh_families f JOIN refresh_tokens t ON t.family_id = f.id WHERE f.realm_id = us.realm_id AND f.user_session_id = us.id))) * 1000)::bigint AS last_access, ARRAY(SELECT c.id FROM client_sessions cs JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE cs.realm_id = us.realm_id AND cs.user_session_id = us.id ORDER BY c.client_id) AS client_ids, ARRAY(SELECT c.client_id FROM client_sessions cs JOIN clients c ON c.realm_id = cs.realm_id AND c.id = cs.client_id WHERE cs.realm_id = us.realm_id AND cs.user_session_id = us.id ORDER BY c.client_id) AS client_identifiers FROM user_sessions us JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id WHERE us.realm_id = $1 AND us.revoked_at IS NULL AND NOT us.steps_pending AND us.expires_at > clock_timestamp()";

fn session_row(row: &PgRow) -> Result<SessionRecord, StorageError> {
    let ids: Vec<String> = row.try_get("client_ids")?;
    let identifiers: Vec<String> = row.try_get("client_identifiers")?;
    Ok(SessionRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        username: row.try_get("username")?,
        started: row.try_get("started")?,
        last_access: row.try_get("last_access")?,
        remember_me: row.try_get("remember_me")?,
        clients: ids.into_iter().zip(identifiers).collect(),
    })
}

impl Storage {
    /// Lists a user's live sessions, newest first, or `None` if the user
    /// does not exist.
    pub async fn user_session_list(
        &self,
        realm_id: &str,
        user_id: &str,
    ) -> Result<Option<Vec<SessionRecord>>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2)",
        )
        .bind(realm_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
        let sessions = if exists {
            let rows = sqlx::query(&format!(
                "{SESSION_SELECT} AND us.user_id = $2 ORDER BY us.created_at DESC, us.id"
            ))
            .bind(realm_id)
            .bind(user_id)
            .fetch_all(&mut *conn)
            .await?;
            Some(rows.iter().map(session_row).collect::<Result<_, _>>()?)
        } else {
            None
        };
        tx.commit().await?;
        Ok(sessions)
    }

    /// Lists the live sessions that include a client, newest first.
    pub async fn client_session_list(
        &self,
        realm_id: &str,
        client_id: &str,
        first: i64,
        max: i64,
    ) -> Result<Vec<SessionRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query(&format!("{SESSION_SELECT} AND EXISTS (SELECT 1 FROM client_sessions cs WHERE cs.realm_id = us.realm_id AND cs.user_session_id = us.id AND cs.client_id = $2) ORDER BY us.created_at DESC, us.id OFFSET $3 LIMIT $4"))
            .bind(realm_id).bind(client_id).bind(first).bind(max).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter().map(session_row).collect()
    }

    /// Lists a client's live offline sessions, of one user when given,
    /// newest first; each lists only that client, as in the reference.
    pub async fn offline_session_list(
        &self,
        realm_id: &str,
        client_id: &str,
        user_id: Option<&str>,
    ) -> Result<Vec<SessionRecord>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query("SELECT f.user_session_id AS id, us.user_id, u.username, us.remember_me, floor(EXTRACT(EPOCH FROM us.created_at) * 1000)::bigint AS started, floor(EXTRACT(EPOCH FROM GREATEST(us.created_at, (SELECT max(t.consumed_at) FROM refresh_tokens t WHERE t.family_id = f.id))) * 1000)::bigint AS last_access, ARRAY[c.id] AS client_ids, ARRAY[c.client_id] AS client_identifiers FROM refresh_families f JOIN user_sessions us ON us.realm_id = f.realm_id AND us.id = f.user_session_id JOIN users u ON u.realm_id = us.realm_id AND u.id = us.user_id JOIN clients c ON c.realm_id = f.realm_id AND c.id = f.client_id WHERE f.realm_id = $1 AND f.client_id = $2 AND ($3::text IS NULL OR us.user_id = $3) AND f.offline AND f.revoked_at IS NULL AND f.expires_at > clock_timestamp() ORDER BY us.created_at DESC, f.id")
            .bind(realm_id).bind(client_id).bind(user_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter().map(session_row).collect()
    }

    /// Counts the live online and offline sessions of every client that has
    /// one.
    pub async fn client_session_counts(
        &self,
        realm_id: &str,
    ) -> Result<Vec<ClientSessionCount>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query("SELECT * FROM (SELECT c.id, c.client_id, (SELECT count(DISTINCT us.id) FROM client_sessions cs JOIN user_sessions us ON us.realm_id = cs.realm_id AND us.id = cs.user_session_id WHERE cs.realm_id = c.realm_id AND cs.client_id = c.id AND us.revoked_at IS NULL AND NOT us.steps_pending AND us.expires_at > clock_timestamp()) AS active, (SELECT count(*) FROM refresh_families f WHERE f.realm_id = c.realm_id AND f.client_id = c.id AND f.offline AND f.revoked_at IS NULL AND f.expires_at > clock_timestamp()) AS offline FROM clients c WHERE c.realm_id = $1) counts WHERE active > 0 OR offline > 0 ORDER BY client_id")
            .bind(realm_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(ClientSessionCount {
                    id: row.try_get("id")?,
                    client_identifier: row.try_get("client_id")?,
                    active: row.try_get("active")?,
                    offline: row.try_get("offline")?,
                })
            })
            .collect()
    }

    /// Ends one live session for every client; false if it does not exist.
    pub async fn admin_end_session(
        &self,
        realm_id: &str,
        session_id: &str,
        actor: &Actor,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let live: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_sessions WHERE realm_id = $1 AND id = $2 AND revoked_at IS NULL FOR UPDATE)")
            .bind(realm_id).bind(session_id).fetch_one(&mut *conn).await?;
        if !live {
            tx.commit().await?;
            return Ok(false);
        }
        end_session(conn, realm_id, session_id).await?;
        audit(conn, actor, "session_ended").await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Ends every session of a user, or of the whole realm for `None`;
    /// false if the user does not exist.
    pub async fn admin_end_sessions(
        &self,
        realm_id: &str,
        user_id: Option<&str>,
        actor: &Actor,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        if let Some(user_id) = user_id {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM users WHERE realm_id = $1 AND id = $2)",
            )
            .bind(realm_id)
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await?;
            if !exists {
                tx.commit().await?;
                return Ok(false);
            }
        }
        let sessions: Vec<String> = sqlx::query_scalar("SELECT id FROM user_sessions WHERE realm_id = $1 AND ($2::text IS NULL OR user_id = $2) AND revoked_at IS NULL FOR UPDATE")
            .bind(realm_id).bind(user_id).fetch_all(&mut *conn).await?;
        for session in &sessions {
            end_session(conn, realm_id, session).await?;
        }
        let event = if user_id.is_some() {
            "user_sessions_ended"
        } else {
            "realm_sessions_ended"
        };
        audit(conn, actor, event).await?;
        tx.commit().await?;
        Ok(true)
    }
}
