use bt2x_common::sigstore_config::SigstoreConfig;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sigstore::cosign::verification_constraint::{
    CertSubjectEmailVerifier, CertSubjectUrlVerifier, VerificationConstraint,
};
use sigstore::registry::OciReference;
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;

/// Data structure to configure this application.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// list of [[References]] to OCI images that will be monitored
    pub references: Vec<References>,
    /// Sigstore configuration, for more details refer to [[bt2x_common::sigstore_config::SigstoreConfig]]
    pub sigstore_config: SigstoreConfig,
    /// URLs of monitors to which gossip is sent
    pub monitors: Vec<Url>,
}

/// function to handle [[serde]] serialization for OCI references
fn serialize_oci_ref<S>(reference: &OciReference, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(reference.whole().as_str())
}

/// function to handle [[serde]] deserialization for OCI references
fn deserialize_oci_ref<'de, D>(deserializer: D) -> Result<OciReference, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;

    OciReference::from_str(&buf).map_err(serde::de::Error::custom)
}

/// data structure to configure images that will be audited/verified
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct References {
    /// tag that is used to identify the image
    #[serde(
        serialize_with = "serialize_oci_ref",
        deserialize_with = "deserialize_oci_ref"
    )]
    pub tag: OciReference,
    /// subject identities that are trusted as signers for this image
    pub subjects: Option<Vec<Subject>>,
    /// optional: annotations are are verified on this image
    pub annotations: Option<HashMap<String, String>>,
}

/// This enum can be used to configure the subject that signed the artifact.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Subject {
    /// the subject is identified by an (E-Mail, OIDC issuer) tuple.
    Email {
        email: String,
        /// The issuer, this is an `Option` for compatibility with the Sigstore library.
        /// However, leaving the issuer unspecified is probably not desirable in case the same E-Mail is registered with multiple issuers.
        issuer: Option<url::Url>,
    },
    /// The subject is identified by a (URL, OIDC issuer) tuple.
    Url { url: url::Url, issuer: url::Url },
}

impl From<Subject> for Box<dyn VerificationConstraint> {
    fn from(value: Subject) -> Self {
        match value {
            Subject::Email { email, issuer } => Box::new(CertSubjectEmailVerifier {
                email,
                issuer: issuer.map(|url| url.to_string()),
            }),
            Subject::Url { url, issuer } => Box::new(CertSubjectUrlVerifier {
                url: url.to_string(),
                issuer: issuer.to_string(),
            }),
        }
    }
}
