use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, sqlx::Type, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[sqlx(transparent)]
#[serde(transparent)]
pub struct SecretID(i64);

impl std::fmt::Display for SecretID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "hazard")]
impl SecretID {
    pub fn new(id: i64) -> Self {
        Self(id)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddSecretRequest {
    pub name: String,
    pub secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RenameSecretRequest {
    pub current_name: String,
    pub new_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoveSecretRequest {
    pub secret_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetSecretRequest {
    pub recipient: String,
    pub secret: String,
}
