use axum::http::StatusCode;
use ed25519_dalek::VerifyingKey;
use jiff_sqlx::ToSqlx as _;
use rand::RngExt as _;

use crate::db;

#[derive(thiserror::Error, Debug, axum_thiserror::ErrorStatus)]
pub enum VerificationError {
    #[error("Key already in an verification attempt")]
    #[status(StatusCode::BAD_REQUEST)]
    KeyPendingVerification,

    #[error("Provided key is already verified")]
    #[status(StatusCode::BAD_REQUEST)]
    KeyAlreadyInUse,

    #[error("Too many attempts. Try again later")]
    #[status(StatusCode::BAD_REQUEST)]
    TooManyAttempts,

    #[error(transparent)]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    KeysError(#[from] db::keys::KeyError),

    #[error(transparent)]
    #[status(StatusCode::INTERNAL_SERVER_ERROR)]
    SQLXError(#[from] sqlx::Error),
}

type Result<T> = core::result::Result<T, VerificationError>;

/// Add a new verification attempt from an unknown host (Agent)
/// This can be approved by an admin with `approve_attempt`
///
/// The return value is a six digit number. This number should be displayed on the agent
/// There is no other way to get to this value than reading it from the agent.
/// This ensures that the agent that attempt the verification is actually the agent you are trying to setup
/// The traffic is susceptible to MITM attack. The agent should use certificate pinning (TODO)
///
/// # Security
/// This is the only method that is done without any form of authentication.
/// It may be advised to but this behind a firewall
/// However no DDoS can come from this because the attempt count is hard limited at 10
pub async fn add_verification_attempt(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
    store_path: api::StorePath,
    nixos_facter: Option<String>,
) -> Result<i64> {
    // delete old attemps to give room for new ones
    delete_old_attempts(conn).await?;

    // If the client has an attempt already we abort
    if key_exists(conn, key).await? {
        return Err(VerificationError::KeyPendingVerification);
    }

    // check if key already is in registered keys
    if db::keys::host_by_key(conn, key).await?.is_some() {
        return Err(VerificationError::KeyAlreadyInUse);
    }

    // limit concurrent attempts
    if count_attempts(conn).await? >= 10 {
        return Err(VerificationError::TooManyAttempts);
    }

    let id = rand::rng().random_range(100_000..=999_999);

    let now = jiff::Timestamp::now().to_sqlx();
    let key = &key.as_bytes()[..];
    let row_id = sqlx::query!(
        r#"
        INSERT INTO verification_attempt (id, verifying_key, timestamp, store_path, nixos_facter)
        VALUES ( $1, $2, $3, $4, $5)
        "#,
        id,
        key,
        now,
        store_path,
        nixos_facter
    )
    .execute(conn)
    .await?
    .last_insert_rowid();

    assert_eq!(id, row_id);

    Ok(id)
}

/// Approve an request
pub async fn approve_attempt(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
    store_path: api::StorePath,
    nixos_facter: Option<String>,
) -> Result<i64> {
    // delete old attemps to give room for new ones
    delete_old_attempts(conn).await?;

    // If the client has an attempt already we abort
    if key_exists(conn, key).await? {
        return Err(VerificationError::KeyPendingVerification);
    }

    // check if key already is in registered keys
    if db::keys::host_by_key(conn, key).await?.is_some() {
        return Err(VerificationError::KeyAlreadyInUse);
    }

    // limit concurrent attempts
    if count_attempts(conn).await? >= 10 {
        return Err(VerificationError::TooManyAttempts);
    }

    let id = rand::rng().random_range(100_000..=999_999);

    let now = jiff::Timestamp::now().to_sqlx();
    let key = &key.as_bytes()[..];
    let row_id = sqlx::query!(
        r#"
        INSERT INTO verification_attempt (id, verifying_key, timestamp, store_path, nixos_facter)
        VALUES ( $1, $2, $3, $4, $5)
        "#,
        id,
        key,
        now,
        store_path,
        nixos_facter
    )
    .execute(conn)
    .await?
    .last_insert_rowid();

    assert_eq!(id, row_id);

    Ok(id)
}

async fn count_attempts(conn: &mut sqlx::SqliteConnection) -> Result<i64> {
    Ok(
        sqlx::query_scalar!(r#"SELECT COUNT(*) FROM verification_attempt"#)
            .fetch_one(conn)
            .await?,
    )
}

async fn key_exists(conn: &mut sqlx::SqliteConnection, key: VerifyingKey) -> Result<bool> {
    let key = &key.as_bytes()[..];
    Ok(sqlx::query_scalar!(
        r#"SELECT EXISTS(SELECT 1 FROM verification_attempt WHERE verifying_key = $1) AS 'exists!: bool'"#,
        key
    )
    .fetch_one(conn)
    .await?)
}

async fn delete_old_attempts(conn: &mut sqlx::SqliteConnection) -> Result<u64> {
    // threshold: 2min
    let cutoff = jiff::Timestamp::now() - jiff::Span::new().minutes(2);

    let result = sqlx::query("DELETE FROM verification_attempt WHERE timestamp < $1")
        .bind(cutoff.to_sqlx())
        .execute(conn)
        .await?;

    // Return the number of rows deleted
    Ok(result.rows_affected())
}

#[cfg(test)]
mod test_verification {

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use jiff_sqlx::ToSqlx as _;
    use rand::RngExt as _;

    use crate::db::{self, verification::VerificationError};

    #[sqlx::test]
    async fn add_verification(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();

        db::verification::add_verification_attempt(
            &mut conn,
            VerifyingKey::default(),
            "some_path".to_owned(),
            None,
        )
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn key_already_requestd(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();

        db::verification::add_verification_attempt(
            &mut conn,
            VerifyingKey::default(),
            "some_path".to_owned(),
            None,
        )
        .await
        .unwrap();

        let err = db::verification::add_verification_attempt(
            &mut conn,
            VerifyingKey::default(),
            "some_path".to_owned(),
            None,
        )
        .await;
        match err {
            Err(VerificationError::KeyPendingVerification) => {}
            _ => panic!(),
        }
    }

    #[sqlx::test]
    async fn key_already_in_use(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();

        db::keys::add_host(
            &mut conn,
            "keyid".to_owned(),
            VerifyingKey::default(),
            "hostname".to_owned(),
        )
        .await
        .unwrap();

        let err = db::verification::add_verification_attempt(
            &mut conn,
            VerifyingKey::default(),
            "some_path".to_owned(),
            None,
        )
        .await;

        match err {
            Err(VerificationError::KeyAlreadyInUse) => {}
            _ => panic!(),
        }
    }

    #[sqlx::test]
    async fn no_more_than_10(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();

        for _ in 0..10 {
            db::verification::add_verification_attempt(
                &mut conn,
                SigningKey::from_bytes(&rand::random()).verifying_key(),
                "some_path".to_owned(),
                None,
            )
            .await
            .unwrap();
        }

        let err = db::verification::add_verification_attempt(
            &mut conn,
            VerifyingKey::default(),
            "some_path".to_owned(),
            None,
        )
        .await;

        match err {
            Err(VerificationError::TooManyAttempts) => {}
            _ => panic!(),
        }
    }

    #[sqlx::test]
    async fn delete_old_attempts(pool: sqlx::SqlitePool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::migrate!("../migrations")
            .run(&mut conn)
            .await
            .unwrap();

        let id = rand::rng().random_range(100_000..=999_999);

        let before = (jiff::Timestamp::now() - jiff::Span::new().minutes(3)).to_sqlx();
        let key = &[0; 32][..];
        let str = String::new();
        sqlx::query!(
            r#"
            INSERT INTO verification_attempt (id, verifying_key, timestamp, store_path, nixos_facter)
            VALUES ( $1, $2, $3, $4, $5)
            "#,
            id,
            key,
            before,
            str,
            None::<String>
        )
        .execute(&mut *conn)
        .await.unwrap()
        .last_insert_rowid();

        db::verification::add_verification_attempt(
            &mut conn,
            SigningKey::from_bytes(&rand::random()).verifying_key(),
            "some_path".to_owned(),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            db::verification::count_attempts(&mut conn).await.unwrap(),
            1 // two were added but only one is still valid
        )
    }
}
