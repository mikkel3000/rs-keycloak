//! Client protocol mappers: stored with their client, managed through the
//! admin API, and read when tokens are issued.

use sqlx::{PgConnection, Row};

use crate::{Storage, StorageError};

/// A protocol mapper to store.
pub struct NewProtocolMapper<'a> {
    /// Mapper id.
    pub id: &'a str,
    /// Name, unique per protocol within the client.
    pub name: &'a str,
    /// Protocol, such as `openid-connect`.
    pub protocol: &'a str,
    /// Mapper type, such as `oidc-audience-mapper`.
    pub mapper_type: &'a str,
    /// Configuration as a JSON object of strings.
    pub config: &'a str,
}

/// A stored protocol mapper.
pub struct ProtocolMapperRecord {
    /// Mapper id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Protocol.
    pub protocol: String,
    /// Mapper type.
    pub mapper_type: String,
    /// Configuration as a JSON object of strings.
    pub config: String,
}

/// Outcome of adding protocol mappers.
pub enum MapperCreation {
    /// Every mapper was added.
    Created,
    /// The client already has a mapper with one of the names.
    NameTaken,
    /// The client does not exist.
    ClientNotFound,
}

/// The audiences a client's audience mappers add to its tokens.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TokenAudiences {
    /// Audiences of access tokens.
    pub access: Vec<String>,
    /// Audiences of ID tokens.
    pub id: Vec<String>,
}

/// Adds mappers to a client in the caller's transaction; returns false if
/// a name is taken, leaving the transaction to be rolled back.
pub(crate) async fn insert_mappers(
    connection: &mut PgConnection,
    realm_id: &str,
    client_id: &str,
    mappers: &[NewProtocolMapper<'_>],
) -> Result<bool, StorageError> {
    for mapper in mappers {
        let inserted = sqlx::query("INSERT INTO client_protocol_mappers (realm_id, client_id, id, name, protocol, mapper_type, config) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb) ON CONFLICT DO NOTHING")
            .bind(realm_id).bind(client_id).bind(mapper.id).bind(mapper.name)
            .bind(mapper.protocol).bind(mapper.mapper_type).bind(mapper.config)
            .execute(&mut *connection).await?.rows_affected();
        if inserted == 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Makes a client's mappers the given ones, as the reference's
/// `updateClientProtocolMappers`: a mapper with the same protocol and name
/// keeps its id and takes the new type and configuration, new ones are
/// added and the others removed.
pub(crate) async fn replace_mappers(
    connection: &mut PgConnection,
    realm_id: &str,
    client_id: &str,
    mappers: &[NewProtocolMapper<'_>],
) -> Result<(), StorageError> {
    let names: Vec<String> = mappers
        .iter()
        .map(|m| format!("{}\n{}", m.protocol, m.name))
        .collect();
    sqlx::query("DELETE FROM client_protocol_mappers WHERE realm_id = $1 AND client_id = $2 AND NOT (protocol || E'\\n' || name = ANY($3))")
        .bind(realm_id).bind(client_id).bind(&names)
        .execute(&mut *connection).await?;
    for mapper in mappers {
        sqlx::query("INSERT INTO client_protocol_mappers (realm_id, client_id, id, name, protocol, mapper_type, config) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb) ON CONFLICT (realm_id, client_id, protocol, name) DO UPDATE SET mapper_type = EXCLUDED.mapper_type, config = EXCLUDED.config")
            .bind(realm_id).bind(client_id).bind(mapper.id).bind(mapper.name)
            .bind(mapper.protocol).bind(mapper.mapper_type).bind(mapper.config)
            .execute(&mut *connection).await?;
    }
    Ok(())
}

impl Storage {
    /// Lists a client's mappers by name; `None` if the client is missing.
    pub async fn protocol_mappers(
        &self,
        realm_id: &str,
        client_id: &str,
    ) -> Result<Option<Vec<ProtocolMapperRecord>>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM clients WHERE realm_id = $1 AND id = $2)",
        )
        .bind(realm_id)
        .bind(client_id)
        .fetch_one(&mut *conn)
        .await?;
        if !exists {
            tx.commit().await?;
            return Ok(None);
        }
        let rows = sqlx::query("SELECT id, name, protocol, mapper_type, config::text AS config FROM client_protocol_mappers WHERE realm_id = $1 AND client_id = $2 ORDER BY name, protocol")
            .bind(realm_id).bind(client_id).fetch_all(&mut *conn).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok(ProtocolMapperRecord {
                    id: row.try_get("id")?,
                    name: row.try_get("name")?,
                    protocol: row.try_get("protocol")?,
                    mapper_type: row.try_get("mapper_type")?,
                    config: row.try_get("config")?,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()
            .map(Some)
    }

    /// Lists the mappers of every client in a realm by client id and name,
    /// for client listings.
    pub async fn realm_protocol_mappers(
        &self,
        realm_id: &str,
    ) -> Result<Vec<(String, ProtocolMapperRecord)>, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let rows = sqlx::query("SELECT client_id, id, name, protocol, mapper_type, config::text AS config FROM client_protocol_mappers WHERE realm_id = $1 ORDER BY client_id, name, protocol")
            .bind(realm_id).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get("client_id")?,
                    ProtocolMapperRecord {
                        id: row.try_get("id")?,
                        name: row.try_get("name")?,
                        protocol: row.try_get("protocol")?,
                        mapper_type: row.try_get("mapper_type")?,
                        config: row.try_get("config")?,
                    },
                ))
            })
            .collect()
    }

    /// Adds mappers to a client, all or none.
    pub async fn create_protocol_mappers(
        &self,
        realm_id: &str,
        client_id: &str,
        mappers: &[NewProtocolMapper<'_>],
    ) -> Result<MapperCreation, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let conn = tx.connection();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM clients WHERE realm_id = $1 AND id = $2 FOR UPDATE)",
        )
        .bind(realm_id)
        .bind(client_id)
        .fetch_one(&mut *conn)
        .await?;
        if !exists {
            tx.commit().await?;
            return Ok(MapperCreation::ClientNotFound);
        }
        if !insert_mappers(conn, realm_id, client_id, mappers).await? {
            return Ok(MapperCreation::NameTaken);
        }
        tx.commit().await?;
        Ok(MapperCreation::Created)
    }

    /// Replaces a mapper's configuration; returns false if it is missing.
    pub async fn update_protocol_mapper_config(
        &self,
        realm_id: &str,
        client_id: &str,
        id: &str,
        config: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let changed = sqlx::query("UPDATE client_protocol_mappers SET config = $4::jsonb WHERE realm_id = $1 AND client_id = $2 AND id = $3")
            .bind(realm_id).bind(client_id).bind(id).bind(config)
            .execute(tx.connection()).await?.rows_affected();
        tx.commit().await?;
        Ok(changed > 0)
    }

    /// Removes a mapper; returns false if it is missing.
    pub async fn delete_protocol_mapper(
        &self,
        realm_id: &str,
        client_id: &str,
        id: &str,
    ) -> Result<bool, StorageError> {
        let mut tx = self.begin_request(false).await?;
        let deleted = sqlx::query("DELETE FROM client_protocol_mappers WHERE realm_id = $1 AND client_id = $2 AND id = $3")
            .bind(realm_id).bind(client_id).bind(id)
            .execute(tx.connection()).await?.rows_affected();
        tx.commit().await?;
        Ok(deleted > 0)
    }

    /// The audiences a client's OpenID Connect audience mappers add, as the
    /// reference's `AudienceProtocolMapper`: a named client audience only
    /// while that client exists and is enabled, else the custom audience.
    pub async fn token_audiences(
        &self,
        realm_id: &str,
        client_identifier: &str,
    ) -> Result<TokenAudiences, StorageError> {
        let mut tx = self.begin_request(true).await?;
        let rows = sqlx::query("SELECT m.config->>'access.token.claim' = 'true' AS access, m.config->>'id.token.claim' = 'true' AS id_token, CASE WHEN m.config ? 'included.client.audience' THEN (SELECT c.client_id FROM clients c WHERE c.realm_id = m.realm_id AND c.client_id = m.config->>'included.client.audience' AND c.enabled) ELSE m.config->>'included.custom.audience' END AS audience FROM client_protocol_mappers m JOIN clients owner ON owner.realm_id = m.realm_id AND owner.id = m.client_id WHERE m.realm_id = $1 AND owner.client_id = $2 AND m.protocol = 'openid-connect' AND m.mapper_type = 'oidc-audience-mapper' ORDER BY m.name")
            .bind(realm_id).bind(client_identifier).fetch_all(tx.connection()).await?;
        tx.commit().await?;
        let mut audiences = TokenAudiences::default();
        for row in rows {
            let Some(audience) = row.try_get::<Option<String>, _>("audience")? else {
                continue;
            };
            if row.try_get::<Option<bool>, _>("access")?.unwrap_or(false) {
                audiences.access.push(audience.clone());
            }
            if row.try_get::<Option<bool>, _>("id_token")?.unwrap_or(false) {
                audiences.id.push(audience);
            }
        }
        Ok(audiences)
    }
}
