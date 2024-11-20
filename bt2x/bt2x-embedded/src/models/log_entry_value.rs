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
use alloc::vec::Vec;
#[cfg(feature = "no_std")]
use alloc::collections::BTreeMap as Map;

#[cfg(feature = "std")]
use HashMap as Map;

#[cfg(feature = "no_std")]
use alloc::boxed::Box;

use serde_with::serde_as;
use serde_with::hex::Hex;

use serde_with::base64::{Base64, Standard};
use serde_with::formats::{Padded};

use crate::models::alpine::AlpineObj;
use crate::models::cose::CoseObj;
use crate::models::hashedrekord::HashedRekordObj;
use crate::models::helm::HelmObj;
use crate::models::intoto::InTotoObj;
use crate::models::JarObj;
use crate::models::rekord::RekordObj;
use crate::models::rfc3161::Rfc3161Obj;
use crate::models::rpm::RpmObj;
use crate::models::tuf::TufObj;


#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogEntryValue {
    /// This is the SHA256 hash of the DER-encoded public key for the log at the time the entry was included in the log
    #[serde(rename = "LogID")]
    pub log_id: String,
    //String,
    #[serde(rename = "LogIndex")]
    pub log_index: i32,
    #[serde(rename = "Body")]
    pub body: LogEntryBody,
    #[serde(rename = "IntegratedTime")]
    pub integrated_time: i32,
    #[serde(rename = "attestation", skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Box<LogEntryValueAttestation>>,
    #[serde(rename = "verification", skip_serializing_if = "Option::is_none")]
    pub verification: Option<Box<LogEntryValueVerification>>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum LogEntryBody {
    #[serde(rename = "HashedRekordObj")]
    HashedRekord(HashedRekordObj),
    #[serde(rename = "Rfc3161Obj")]
    Rfc3161(Rfc3161Obj),
    #[serde(rename = "AlpineObj")]
    Alpine(AlpineObj),
    #[serde(rename = "CoseObj")]
    Cose(CoseObj),
    #[serde(rename = "HelmObj")]
    Helm(HelmObj),
    #[serde(rename = "InTotoObj")]
    InToto(InTotoObj),
    #[serde(rename = "JarObj")]
    Jar(JarObj),
    #[serde(rename = "RekordObj")]
    Rekord(RekordObj),
    #[serde(rename = "RpmObj")]
    Rpm(RpmObj),
    #[serde(rename = "TufObj")]
    Tuf(TufObj),
}


#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PgpKey {
    pub content: String,
}


#[serde_as]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase", tag = "algorithm", content = "value")]
pub enum Hash {
    Sha256(
        #[serde_as(as = "Hex")]
        [u8; 32]
    ),
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub format: Option<SignatureFormat>,
    #[serde_as(as = "Base64<Standard, Padded>")]
    pub content: Vec<u8>,
    pub public_key: PublicKey,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    #[serde_as(as = "Base64<Standard, Padded>")]
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SignatureFormat {
    Pgp,
    Minisign,
    X509,
    Ssh,
}


impl LogEntryValue {
    pub fn new(log_id: &str, log_index: i32, body: LogEntryBody, integrated_time: i32) -> LogEntryValue {
        LogEntryValue {
            log_id: log_id.into(),
            log_index,
            body,
            integrated_time,
            attestation: Option::<_>::None,
            verification: Option::<_>::None,
        }
    }
}


#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogEntryValueAttestation {
    #[serde(rename = "data", skip_serializing_if = "Option::is_none")]
    pub data: Option<Map<String, String>>,
}

impl LogEntryValueAttestation {
    pub fn new() -> LogEntryValueAttestation {
        LogEntryValueAttestation {
            data: Option::<_>::None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LogEntryValueVerification {
    #[serde(rename = "inclusionProof", skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<Box<crate::models::InclusionProof>>,
    /// Signature over the logID, logIndex, body and integratedTime.
    #[serde(rename = "signedEntryTimestamp", skip_serializing_if = "Option::is_none")]
    pub signed_entry_timestamp: Option<String>,
}

impl LogEntryValueVerification {
    pub fn new() -> LogEntryValueVerification {
        LogEntryValueVerification {
            inclusion_proof: Option::<_>::None,
            signed_entry_timestamp: Option::<_>::None,
        }
    }
}