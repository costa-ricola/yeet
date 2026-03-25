use ed25519_dalek::VerifyingKey;
use sqlx::Acquire as _;

use crate::db;

pub async fn fetch_by_key(
    conn: &mut sqlx::SqliteConnection,
    key: VerifyingKey,
) -> Result<Option<api::UserID>, sqlx::Error> {
    let key = &key.as_bytes()[..];
    let user = sqlx::query_scalar!(
        r#"
        SELECT users.id from users
        JOIN keys on keys.id = users.key_id
        WHERE verifying_key = $1"#,
        key
    )
    .fetch_optional(conn)
    .await?;

    Ok(user.map(api::UserID::new))
}

// TODO
// pub async fn allow_all_tag(
//     conn: &mut sqlx::SqliteConnection,
//     user: api::UserID,
// ) -> Result<api::auth::TagID, sqlx::Error> {
//     let tag_id = sqlx::query!(r#"UPDATE users SET all_tag = 1 WHERE id = $1"#, user)
//         .execute(conn)
//         .await?
//         .last_insert_rowid();

//     Ok(api::auth::TagID::new(tag_id))
// }

pub async fn create_user(
    conn: &mut sqlx::SqliteConnection,
    keyid: String,
    key: VerifyingKey,
    name: String,
    level: api::AuthLevel,
    all_tag: bool,
) -> Result<api::UserID, sqlx::Error> {
    let mut tx = conn.begin().await?;

    let key = db::keys::add_key(&mut tx, keyid, key).await?;

    let user = sqlx::query!(
        r#"
        INSERT INTO users (key_id, level, username, all_tag)
        VALUES ($1, $2, $3, $4)"#,
        key,
        level,
        name,
        all_tag
    )
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();
    tx.commit().await?;
    Ok(api::UserID::new(user))
}

pub async fn rename_user(
    conn: &mut sqlx::SqliteConnection,
    id: api::UserID,
    new: String,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE users
        SET username = $1
        WHERE id = $2"#,
        new,
        id
    )
    .execute(conn)
    .await?;
    Ok(())
}
