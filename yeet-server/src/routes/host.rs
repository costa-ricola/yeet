use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::{YeetState, db, error::InternalError as _, httpsig::HttpSig};

pub async fn list(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<Json<Vec<api::host::Host>>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    Ok(Json(db::hosts::list(&mut conn).await.internal_server()?))
}

pub async fn rename_host(
    State(state): State<YeetState>,
    Path((id, name)): Path<(api::HostID, String)>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;
    db::keys::auth_admin(&mut conn, key).await?;
    db::hosts::rename(&mut conn, id, name)
        .await
        .internal_server()?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod test_host {

    use axum_test::TestServer;
    use ed25519_dalek::VerifyingKey;
    use sqlx::SqlitePool;

    async fn add_host(server: &TestServer) {
        let code: i64 = server
            .post("/verification/add")
            .json(&api::verify::VerificationAttempt {
                key: VerifyingKey::default(),
                nixos_facter: Some("hi".to_owned()),
            })
            .await
            .json();

        assert!(code >= 100_000 && code <= 999_999);

        let facter: Option<String> = server
            .put(&format!("/verification/{code}/accept"))
            .json(&"myhost".to_owned())
            .await
            .json();
        assert_eq!(facter, Some("hi".to_owned()));
    }

    #[sqlx::test]
    async fn list(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;

        add_host(&server).await;

        let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();

        assert_eq!(
            hosts,
            vec![api::host::Host {
                id: api::HostID::new(1),
                key: VerifyingKey::default(),
                hostname: "myhost".to_owned()
            }]
        );
    }

    #[sqlx::test]
    async fn rename(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;

        add_host(&server).await;

        server.put("/host/1/rename/otherhost").await;

        let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();

        assert_eq!(
            hosts,
            vec![api::host::Host {
                id: api::HostID::new(1),
                key: VerifyingKey::default(),
                hostname: "otherhost".to_owned()
            }]
        );
    }

    #[sqlx::test]
    async fn delete(pool: SqlitePool) {
        let server = crate::test_server(pool.clone()).await;

        add_host(&server).await;

        server
            .delete("/key/delete")
            .json(&VerifyingKey::default())
            .await;

        let hosts: Vec<api::host::Host> = server.get("/host/list").await.json();

        assert_eq!(hosts, vec![]);
    }
}
