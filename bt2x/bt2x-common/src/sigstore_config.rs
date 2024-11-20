//! ## Example YAML Configuration
//!
//! ```
//! use bt2x_common::sigstore_config::SigstoreConfig;
//!
//! let config = r#"
//! key_config:
//!   !tuf
//!   root_path: "/path/to/root.json"
//!   metadata_base: "https://example.org/path"
//!   targets_base: "file://example.org/path/targets"
//!   target_names:
//!     rekor: "rekor.pub"
//!     fulcio: "fulcio.crt"
//!     ctlog: "ctlog.pub"
//!
//! urls:
//!   rekor: http://rekor.example.org
//!   fulcio: http://fulcio.example.org
//!   oidc_issuer: http://fulcio.example.org
//! "#;
//! let config: SigstoreConfig = serde_yaml::from_str(config).expect("failed to parse config");
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

/// Data structure that is used to configure Sigstore with YAML files.
/// ```
/// use bt2x_common::sigstore_config::SigstoreConfig;
///
/// let config = r#"
/// key_config:
///   !tuf
///   root_path: "/path/to/root.json"
///   metadata_base: "https://example.org/path"
///   targets_base: "file://example.org/path/targets"
///   target_names:
///     rekor: "rekor.pub"
///     fulcio: "fulcio.crt"
///     ctlog: "ctlog.pub"
///
/// urls:
///   rekor: http://rekor.example.org
///   fulcio: http://fulcio.example.org
///   oidc_issuer: http://fulcio.example.org
/// "#;
/// let config: SigstoreConfig = serde_yaml::from_str(config).expect("failed to parse config");
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SigstoreConfig {
    pub urls: SigstoreUrls,
    pub key_config: KeyConfig,
}

/// Enum that is used to configure the keys that are used for Sigstore.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyConfig {
    /// specify a TUF repo from which the Sigstore keys are loaded
    Tuf {
        /// path to the INITIAL root file
        root_path: PathBuf,
        /// path/URL from which updates to the TUF metadata is fetched
        metadata_base: Url,
        /// path/URL from which updates to the TUF target files are fetched
        targets_base: Url,
        /// file names of the TUF target files
        target_names: TufTargetNames,
    },
    /// specify the Sigstore keys via file path
    Keys {
        rekor_key: Option<PathBuf>,
        fulcio_cert: Option<PathBuf>,
        ctlog_key: Option<PathBuf>,
    },
}

/// Struct used to specify the URLs of Sigstore servers.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SigstoreUrls {
    pub rekor: Url,
    pub fulcio: Url,
    pub oidc_issuer: Url,
}

fn rekor_target_default() -> String {
    "rekor.pub".to_string()
}

fn fulcio_target_default() -> String {
    "fulcio.crt".to_string()
}

fn ctlog_target_default() -> String {
    "ctfe.pub".to_string()
}

/// Struct used to specify the file names of Sigstore targets in the TUF repo.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TufTargetNames {
    #[serde(default = "rekor_target_default")]
    pub rekor: String,
    #[serde(default = "fulcio_target_default")]
    pub fulcio: String,
    #[serde(default = "ctlog_target_default")]
    pub ctlog: String,
    //#[serde(flatten)]
    //extra_targets: HashMap<String, String>,
}

#[cfg(test)]
mod test {
    use crate::sigstore_config::SigstoreConfig;

    #[test]
    fn test_parse_config() {
        let config = r#"
key_config:
    !tuf
    root_path: "file://example.org/root.json"
    metadata_base: "https://example.org/path"
    targets_base: "file://example.org/path"
    target_names:
      rekor: "rekor.pub"
      fulcio: "fulcio.crt"
      ctlog: "ctlog.pub"

urls:
    rekor: http://rekor.example.org
    fulcio: http://fulcio.example.org
    oidc_issuer: http://fulcio.example.org
"#;
        let _: SigstoreConfig = serde_yaml::from_str(config).expect("failed to parse config");
    }
}
