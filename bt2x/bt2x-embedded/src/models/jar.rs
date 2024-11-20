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


#[cfg(feature = "std")]
use HashMap as Map;
use crate::models::log_entry_value::{Hash, Signature};


#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JarObj {
    pub signature: Signature,
    pub archive: JarArchive,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JarArchive {
    pub hash: Hash,
    pub content: String,
}

