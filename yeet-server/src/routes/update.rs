use std::sync::Arc;

use axum::{extract::State, http::StatusCode};

use crate::{
    YeetState, db,
    error::{BadRequest, InternalError as _},
    httpsig::{HttpSig, VerifiedJson},
    state::StateError,
};

/// Endpoint to set a new version for a host.
/// The whole request needs to be signed by a build machine.
/// The update consist of a simple `key` -> `version` and a `substitutor` which is where the agent should get its update
/// This means that for each origin e.g. cachix, you need to call update seperately
pub async fn update_hosts(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,

    VerifiedJson(api::HostUpdateRequest {
        hosts,
        public_key,
        substitutor,
    }): VerifiedJson<api::HostUpdateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    db::keys::auth_build(&mut conn, key).await?;

    db::hosts::update(&mut conn, hosts.iter(), public_key, substitutor)
        .await
        .bad_request()?;

    Ok(StatusCode::CREATED)
}
