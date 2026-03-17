use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, sqlx::Type, Deserialize, Serialize, PartialEq, Eq)]
#[sqlx(transparent)]
#[serde(transparent)]
pub struct HostID(i64);

#[cfg(feature = "hazard")]
impl HostID {
    pub fn new(id: i64) -> Self {
        Self(id)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: HostID,
    pub key: VerifyingKey,
    pub hostname: String,
}
