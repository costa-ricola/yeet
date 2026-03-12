use std::{collections::HashMap, str::FromStr};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{
    YeetState,
    db::{self},
    error::{BadRequest, InternalError, WithStatusCode},
    httpsig::{HttpSig, VerifiedJson},
    state::{AppState, StateError},
};

pub async fn add_secret(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::AddSecretRequest { name, secret }): VerifiedJson<api::AddSecretRequest>,
) -> Result<Json<api::SecretID>, (StatusCode, String)> {
    // state.auth_admin(&key)?;
    let mut conn = state.pool.acquire().await.internal_server()?;

    let id = db::secrets::add_secret(&mut conn, name, secret, &*state.age_key)
        .await
        .bad_request()?;
    Ok(Json(id))
}

pub async fn rename_secret(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    Path(id): Path<api::SecretID>,
    VerifiedJson(api::RenameSecretRequest {
        current_name,
        new_name,
    }): VerifiedJson<api::RenameSecretRequest>,
) -> Result<StatusCode, StateError> {
    todo!()

    // state.auth_admin(&key)?;
    // state.rename_secret(current_name, new_name);
    // Ok(StatusCode::OK)
}

pub async fn remove_secret(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::RemoveSecretRequest { secret_name }): VerifiedJson<api::RemoveSecretRequest>,
) -> Result<StatusCode, StateError> {
    todo!()
    // let mut state = state.write_arc();
    // state.auth_admin(&key)?;
    // // state.remove_secret(secret_name);
    // Ok(StatusCode::OK)
}

pub async fn allow_host(
    State(state): State<YeetState>,
    Path((secret_id, host_id)): Path<(api::SecretID, api::HostID)>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    // state.auth_admin(&key)?;
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::secrets::add_access_for(&mut conn, secret_id, host_id)
        .await
        .bad_request()?;

    Ok(StatusCode::OK)
}

pub async fn get_all_acl(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<Json<HashMap<String, Vec<String>>>, StateError> {
    todo!()
    // let state = state.read_arc();
    // state.auth_admin(&key)?;
    // Ok(Json(state.get_all_acl()))
}

pub async fn list(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<Json<Vec<String>>, StateError> {
    todo!()
    // let state = state.read_arc();
    // state.auth_admin(&key)?;
    // Ok(Json(state.list_secrets()))
}

pub async fn get_server_age_key(
    State(state): State<YeetState>,
    HttpSig(_key): HttpSig,
) -> Json<String> {
    Json(state.age_key.to_public().to_string())
}

pub async fn get_secret(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
    VerifiedJson(api::GetSecretRequest { secret, recipient }): VerifiedJson<api::GetSecretRequest>,
) -> Result<Json<Option<Vec<u8>>>, (StatusCode, String)> {
    let mut conn = state
        .pool
        .acquire()
        .await
        .with_code(StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };

    let recipient =
        age::x25519::Recipient::from_str(&recipient).with_code(StatusCode::BAD_REQUEST)?;

    let secret = db::secrets::get_secret_for(&mut conn, &secret, &*state.age_key, host, &recipient)
        .await
        .bad_request()?;

    Ok(Json(secret))
}
#[cfg(test)]
mod test_verification {
    use std::str::FromStr;

    use sqlx::SqlitePool;

    #[sqlx::test]
    async fn add_secret(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;
        let identity = age::x25519::Identity::generate();

        let recipient = {
            let recipient: String = server.get("/secret/server_key").await.json();
            age::x25519::Recipient::from_str(&recipient).unwrap()
        };

        let secret = age::encrypt(&recipient, b"plaintext").unwrap();

        let id: api::SecretID = server
            .post("/secret/add")
            .json(&api::AddSecretRequest {
                name: "secretstuff".to_owned(),
                secret,
            })
            .await
            .json();

        server.put(&format!("/secret/{id}/allow/1")).await;

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "secretstuff".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();
        let decrypted = age::decrypt(&identity, &secret.unwrap()).unwrap();
        assert_eq!(decrypted, b"plaintext")
    }

    #[sqlx::test]
    async fn unauthorized(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;
        let identity = age::x25519::Identity::generate();

        let recipient = {
            let recipient: String = server.get("/secret/server_key").await.json();
            age::x25519::Recipient::from_str(&recipient).unwrap()
        };

        let secret = age::encrypt(&recipient, b"plaintext").unwrap();

        let _id: api::SecretID = server
            .post("/secret/add")
            .json(&api::AddSecretRequest {
                name: "secretstuff".to_owned(),
                secret,
            })
            .await
            .json();

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "secretstuff".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();

        assert!(secret.is_none())
    }

    #[sqlx::test]
    async fn no_secret(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;
        let mut conn = pool.acquire().await.unwrap();
        crate::add_default_host(&mut conn).await;
        let identity = age::x25519::Identity::generate();

        let secret: Option<Vec<u8>> = server
            .post("/secret")
            .json(&api::GetSecretRequest {
                secret: "secretstuff".to_owned(),
                recipient: identity.to_public().to_string(),
            })
            .await
            .json();

        assert!(secret.is_none())
    }
}
