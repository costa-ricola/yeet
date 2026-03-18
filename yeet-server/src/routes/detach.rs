use axum::{extract::State, http::StatusCode};

use crate::{YeetState, db, error::InternalError as _, httpsig::HttpSig};

// TODO: currently there are no detach permissions
// all hosts are allowed to detach
// /// Inquire if you (current system) are allowed to detach your own system
// /// If you are an admin and want to see if hosts are allowed to detach, use the hosts api
// pub async fn is_detach_allowed(
//     State(state): State<Arc<RwLock<AppState>>>,
//     HttpSig(key): HttpSig,
// ) -> Result<Json<bool>, StateError> {
//     let state = state.read_arc();
//     Ok(Json(state.is_detach_allowed(&key)?))
// }

// /// Set the detach permission either Global or PerHost. PerHost will always take over the global setting
// pub async fn set_detach_permission(
//     State(state): State<Arc<RwLock<AppState>>>,
//     HttpSig(key): HttpSig,
//     VerifiedJson(set_detach): VerifiedJson<api::SetDetachPermission>,
// ) -> Result<StatusCode, StateError> {
//     let mut state = state.write_arc();
//     state.auth_admin(&key)?;

//     match set_detach {
//         api::SetDetachPermission::Global(allowed) => state.set_global_detach_permission(allowed),
//         api::SetDetachPermission::PerHost(items) => state.set_detach_permissions(items),
//     }

//     Ok(StatusCode::OK)
// }

/// Detach self
pub async fn detach(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };
    db::hosts::set_provision_state(&mut conn, host, api::ProvisionState::Detached)
        .await
        .internal_server()?;

    Ok(StatusCode::OK)
}
/// Attach self
pub async fn attach(
    State(state): State<YeetState>,
    HttpSig(key): HttpSig,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.internal_server()?;

    let Some(host) = db::hosts::host_by_verify_key(&mut conn, key)
        .await
        .internal_server()?
    else {
        return Err((
            StatusCode::FORBIDDEN,
            "Unknown keyid. You are not a registered host".to_owned(),
        ));
    };
    db::hosts::set_provision_state(&mut conn, host, api::ProvisionState::Provisioned)
        .await
        .internal_server()?;

    Ok(StatusCode::OK)
}
