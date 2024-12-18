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
pub struct TufAllOf {
    #[serde(rename = "apiVersion")]
    pub api_version: alloc::string::String, //String,
    /// Schema for TUF metadata objects
    #[serde(rename = "spec")]
    pub spec: serde_json::Value,
}

impl TufAllOf {
    pub fn new(api_version: &str, spec: serde_json::Value) -> TufAllOf {
        TufAllOf {
            api_version: api_version.into(),
            spec,
        }
    }
}


