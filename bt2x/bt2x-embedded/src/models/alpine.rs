/*
 * Rekor
 *
 * Rekor is a cryptographically secure, immutable transparency log for signed software releases.
 *
 * The version of the OpenAPI document: 1.0.0
 * 
 * Generated by: https://openapi-generator.tech
 */

#[cfg(feature = "no_std")]
use alloc::string::String;

#[cfg(feature = "no_std")]
use alloc::collections::BTreeMap as Map;

#[cfg(feature = "std")]
use HashMap as Map;
use crate::models::log_entry_value::{Hash, PublicKey};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlpineObj {
    pub package: AlpinePackage,
    pub public_key: PublicKey,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlpinePackage {
    pub pkginfo: Map<String, String>,
    pub hash: Hash,
    pub content: String,
}




