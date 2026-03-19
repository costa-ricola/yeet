use std::collections::{HashMap, HashSet};

use ed25519_dalek::VerifyingKey;

use jiff::Zoned;
use serde::{Deserialize, Serialize};
use serde_json_any_key::any_key_map;

// use crate::db::secret::{SecretError, SecretStore};

#[derive(Serialize, Deserialize, PartialEq, Eq, Default)]
struct AppState {
    admin_credentials: HashSet<VerifyingKey>,
    build_machines_credentials: HashSet<VerifyingKey>,
    // hostname -> Hosts
    hosts: HashMap<String, api::Host>,
    //  keyid -> Key for httpsig
    keyids: HashMap<String, VerifyingKey>,
    // Maps key to the hostname
    #[serde(with = "any_key_map")]
    host_by_key: HashMap<VerifyingKey, String>,
    // 6 digit number -> unverified pub key
    verification_attempt: HashMap<u32, (api::VerificationAttempt, Zoned)>,
    // Should hosts be allowed to detach by themself in general
    detach_allowed: bool,
    // Secrets encrypted with `server_key`
    // #[serde(default)]
    // secrets: SecretStore,
    // Server key used for response signatures (TODO), certificate pinning (TODO) and for secret decryption
    age_identity: String,
}
