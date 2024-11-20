/*
 * Rekor
 *
 * Rekor is a cryptographically secure, immutable transparency log for signed software releases.
 *
 * The version of the OpenAPI document: 1.0.0
 * 
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CoseAllOf {
    #[serde(rename = "apiVersion")]
    pub api_version: alloc::string::String,
    /// COSE for Rekord objects
    #[serde(rename = "spec")]
    pub spec: serde_json::Value,
}

impl CoseAllOf {
    pub fn new(api_version: &str, spec: serde_json::Value) -> CoseAllOf {
        CoseAllOf {
            api_version: api_version.into(),
            spec,
        }
    }
}

