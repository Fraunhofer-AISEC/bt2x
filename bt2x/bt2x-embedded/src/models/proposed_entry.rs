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
use crate::models::alpine::AlpineObj;
use crate::models::cose::CoseObj;
use crate::models::{HashedRekordObj, HelmObj, InTotoObj, JarObj, RekordObj, Rfc3161Obj, RpmObj, TufObj};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub enum ProposedEntry {
    #[serde(rename = "alpine")]
    Alpine {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Schema for Alpine package objects
        #[serde(rename = "spec")]
        spec: AlpineObj,
    },
    #[serde(rename = "cose")]
    Cose {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// COSE for Rekord objects
        #[serde(rename = "spec")]
        spec: CoseObj,
    },
    #[serde(rename = "hashedrekord")]
    HashedRekord {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Schema for Rekord objects
        #[serde(rename = "spec")]
        spec: HashedRekordObj,
    },
    #[serde(rename = "helm")]
    Helm {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Schema for Helm objects
        #[serde(rename = "spec")]
        spec: HelmObj,
    },
    #[serde(rename = "intoto")]
    InToto {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Intoto for Rekord objects
        #[serde(rename = "spec")]
        spec: InTotoObj,
    },
    #[serde(rename = "jar")]
    Jar {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Schema for JAR objects
        #[serde(rename = "spec")]
        spec: JarObj,
    },
    #[serde(rename = "rekord")]
    Rekord {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Schema for Rekord objects
        #[serde(rename = "spec")]
        spec: RekordObj,
    },
    #[serde(rename = "rfc3161")]
    Rfc3161 {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Schema for RFC 3161 timestamp objects
        #[serde(rename = "spec")]
        spec: Rfc3161Obj,
    },
    #[serde(rename = "rpm")]
    Rpm {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Schema for RPM objects
        #[serde(rename = "spec")]
        spec: RpmObj,
    },
    #[serde(rename = "tuf")]
    Tuf {
        #[serde(rename = "apiVersion")]
        api_version: String,
        /// Schema for TUF metadata objects
        #[serde(rename = "spec")]
        spec: TufObj,
    },
}



