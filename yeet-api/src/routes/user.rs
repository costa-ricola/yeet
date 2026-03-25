use ed25519_dalek::VerifyingKey;

use serde::{Deserialize, Serialize};

use crate::request;

crate::db_id!(UserID);
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateUser {
    pub key: VerifyingKey,
    pub level: AuthLevel,
    pub username: String,
    pub all_tag: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(feature = "hazard", derive(sqlx::Type))]
pub enum AuthLevel {
    Build,
    Admin,
    Osquery,
}

request! (
    create_user(create_user: CreateUser),
    post("/user/create") -> UserID,
    body: &create_user
);
