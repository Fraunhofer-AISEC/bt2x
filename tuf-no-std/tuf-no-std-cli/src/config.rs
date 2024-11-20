use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Data structure to parse/store configurations
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// key: role name, value: role configuration
    pub roles: HashMap<String, RoleConfig>,
    /// key: target name, value: target configuration
    pub targets: HashMap<String, TargetConfig>,
    /// directory to store the output
    pub out: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TargetConfig {
    pub name: String,
    pub filepath: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RoleConfig {
    pub threshold: u8,
    pub version: u32,
    pub keys: Vec<KeyConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyConfig {
    pub kind: KeyKind,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Ecdsa,
}
