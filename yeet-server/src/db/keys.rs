use axum::http::StatusCode;
use ed25519_dalek::VerifyingKey;

#[derive(thiserror::Error, Debug, axum_thiserror::ErrorStatus)]
pub enum KeyError {
    #[error(transparent)]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    SQLXError(#[from] sqlx::Error),
}
type Result<T> = core::result::Result<T, KeyError>;

pub async fn host_by_key(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<Option<String>> {
    let key = &key.as_bytes()[..];
    Ok(
        sqlx::query_scalar!(r#"SELECT hostname from keys WHERE verifying_key = $1"#, key)
            .fetch_optional(conn)
            .await?,
    )
}

pub async fn add_host(
    conn: &mut sqlx::SqliteConnection,
    keyid: String,
    key: VerifyingKey,
    hostname: String,
) -> Result<()> {
    let key = &key.as_bytes()[..];
    sqlx::query!(
        r#"
        INSERT INTO keys (keyid, verifying_key, hostname)
        VALUES ( $1, $2, $3)"#,
        keyid,
        key,
        hostname
    )
    .execute(conn)
    .await?;
    Ok(())
}
