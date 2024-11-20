mod args;

use anyhow::anyhow;
use bt2x_common::artifact::source::oci::OciSource;
use bt2x_common::error::Bt2XError;
use bt2x_common::rekor::Configuration as RekorConfig;
use bt2x_common::rekor::RekorClient;
use bt2x_common::sigstore_config::{KeyConfig, SigstoreConfig, TufTargetNames};
use bt2x_common::tuf::load_tuf_filesystem;
use bt2x_common::verifier::bt::BinaryTransparencyVerifier;
use bt2x_common::verifier::bt::SigstoreKeys;
use bt2x_common::verifier::Artifact;
use bt2x_common::verifier::Verifier;
use clap::Parser;
use oci_distribution::client as oci_client;
use oci_distribution::secrets::RegistryAuth;
use probe_rs::Permissions;
use probe_rs::Session;
use rustls_pemfile::{read_one, Item};
use sigstore::cosign::bundle::SignedArtifactBundle;
use sigstore::cosign::verification_constraint::CertSubjectEmailVerifier;
use sigstore::cosign::verification_constraint::VerificationConstraintVec;
use sigstore::cosign::CosignCapabilities;
use sigstore::crypto::{CosignVerificationKey, SigningScheme};
use sigstore::registry::{ClientConfig, ClientProtocol, OciReference};
use sigstore::rekor::apis::configuration::Configuration;
use sigstore::trust::ManualTrustRoot;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::{BufReader, Cursor};
use std::panic;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;
use tracing::error;
use tracing::{debug, info, warn};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;
use url::Url;

#[derive(Debug, Error)]
pub enum FlasherError {
    #[error("could not attach to probe {0}")]
    AttachToProbeFailed(#[from] probe_rs::Error),
    #[error("failed to flash {0}")]
    FlashFailed(#[from] probe_rs::flashing::FileDownloadError),
    #[error("failed to open sigstore config file {0}")]
    FailedToOpenSigstoreConfig(std::io::Error),
    #[error("failed to open bundle {0}")]
    FailedToOpenBundle(std::io::Error),
    #[error("failed to open binary {0}")]
    FailedToOpenBinary(std::io::Error),
    #[error("failed to open rekor public key {0}")]
    FailedToOpenRekorPublicKey(std::io::Error),
    #[error("failed to open CT log public key {0}")]
    FailedToOpenCtLogPublicKey(std::io::Error),
    #[error("failed to open fulcio root cert {0}")]
    FailedToOpenFulcioRootCert(std::io::Error),
    #[error("sigstore config file is invalid{0}")]
    InvalidSigstoreConfig(#[from] serde_yaml::Error),
    #[error("sigstore internal error {0}")]
    InternalSigstoreError(#[from] sigstore::errors::SigstoreError),
    #[error("bundle verification failed {0}")]
    VerificationFailed(sigstore::errors::SigstoreError),
    #[error("failed to fetch log entry")]
    FetchLogEntryError,
    #[error("inclusion proof failed")]
    InclusionProofFailed,
    #[error("{0:?}")]
    TufError(Bt2XError),
}

#[tokio::main]
async fn main() -> Result<(), FlasherError> {
    let args = args::Args::parse();
    configure_logging(&args);
    let sigstore_keys = load_tuf_filesystem(
        &args.tuf_root,
        &url::Url::from_file_path(&args.tuf_meta.canonicalize().unwrap()).unwrap(),
        &url::Url::from_file_path(args.tuf_meta.join("/tmp")).unwrap(),
        &TufTargetNames {
            ctlog: String::from("ctlog.pub"),
            rekor: String::from("rekor.pub"),
            fulcio: String::from("fulcio.crt.pem"),
        },
    )
    .await
    .map_err(FlasherError::TufError)?;

    // setup clients and configs for clients
    let rekor_client = RekorClient::new(RekorConfig {
        base_path: args.rekor_url.to_string(),
        ..Default::default()
    });

    let registry_config = ClientConfig {
        protocol: if args.http {
            ClientProtocol::Http
        } else {
            ClientProtocol::Https
        },
        accept_invalid_certificates: false,
        extra_root_certificates: vec![],
        accept_invalid_hostnames: true,
    };
    let mut reader = BufReader::new(Cursor::new(&sigstore_keys.fulcio_cert));
    let Some(Item::X509Certificate(fulcio_cert_der)) =
        read_one(&mut reader).expect("failed to decode PEM")
    else {
        panic!("error converting parsing fulcio cert")
    };
    let mut reader = BufReader::new(Cursor::new(&sigstore_keys.rekor_key));
    let Some(Item::SubjectPublicKeyInfo(rekor_key_der)) =
        read_one(&mut reader).expect("failed to decode PEM")
    else {
        panic!("error converting parsing rekor key")
    };
    let mut reader = BufReader::new(Cursor::new(&sigstore_keys.ctlog_key));
    let Some(Item::SubjectPublicKeyInfo(ctlog_key_der)) =
        read_one(&mut reader).expect("failed to decode PEM")
    else {
        panic!("error converting parsing the CT log key")
    };

    let cosign_client = sigstore::cosign::ClientBuilder::default()
        .with_trust_repository(&ManualTrustRoot {
            ctfe_keys: vec![ctlog_key_der.to_vec()],
            rekor_keys: vec![rekor_key_der.to_vec()],
            fulcio_certs: vec![fulcio_cert_der],
        })
        .expect("failed to add trust repo")
        .with_oci_client_config(registry_config)
        .build()
        .expect("Unexpected failure while building Client");

    let oci_client_config = oci_client::ClientConfig {
        protocol: if args.http {
            oci_client::ClientProtocol::Http
        } else {
            oci_client::ClientProtocol::Https
        },
        ..Default::default()
    };

    // configure verifier
    let mut verifier = BinaryTransparencyVerifier::builder()
        .monitors(vec![Url::parse("http://localhost:3132").unwrap()])
        .rekor_client(rekor_client)
        .cosign_client(cosign_client)
        .keys(
            SigstoreKeys::builder()
                .rekor_pub_key(String::from_utf8(sigstore_keys.rekor_key).unwrap())
                .fulcio_cert(String::from_utf8(sigstore_keys.fulcio_cert).unwrap())
                .ct_log_key(String::from_utf8(sigstore_keys.ctlog_key).unwrap())
                .build(),
        )
        .build();

    // configure source from which images are downloaded
    let mut oci_source = OciSource::new(oci_client_config, RegistryAuth::Anonymous);
    let mut constraints: VerificationConstraintVec = vec![Box::new(CertSubjectEmailVerifier {
        email: args.subject,
        issuer: Some(args.oidc_issuer.to_string()),
    })];

    let binary = match verifier
        .verify(&mut oci_source, &args.image, &constraints)
        .await
    {
        Ok(Artifact::Binary(binary)) => binary,
        Ok(Artifact::BundledBinary { binary, bundle: _ }) => binary,
        Err(err) => panic!("{err:?}"),
    };
    let flasher_directory = PathBuf::from(".flasher");
    let file_path =
        build_path(&flasher_directory, &args.image).expect("failed to build output path");
    std::fs::create_dir_all(flasher_directory).expect("failed to create flasher directory");
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&file_path)
        .expect("failed to open output file");
    f.write_all(&binary)
        .expect("failed to write binary to disk");

    if args.do_not_flash {
        warn!("skipping flashing due to `--do-not-flash` flag");
        return Ok(());
    }
    let mut session = Session::auto_attach(args.target, Permissions::default())?;
    debug!("{session:?}");
    info!("flashing binary");
    let probe_rs::flashing::Format::Bin(mut options) = args.format else {
        panic!("only supports bin formats");
    };
    options.base_address = args.base_address.or(Some(0x10000000));
    probe_rs::flashing::download_file(
        &mut session,
        &file_path,
        probe_rs::flashing::Format::Bin(options),
    )?;
    info!("flashing complete");
    Ok(())
}

fn configure_logging(cli: &args::Args) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            Targets::new()
                .with_target(env!("CARGO_PKG_NAME").replace('-', "_"), &cli.log_level)
                .with_target("bt2x_common", &cli.log_level)
                .with_target("sigstore", tracing_core::Level::INFO),
        )
        .init();
}

/// Builds a file path from the OCI reference at which the output file is stored.
fn build_path(base_path: &Path, reference: &OciReference) -> anyhow::Result<PathBuf> {
    let out_path = PathBuf::from(reference.repository());
    let out_path = format!(
        "{}-{}.{}",
        out_path
            .file_stem()
            .ok_or(anyhow!("could not create file name from reference"))
            .and_then(|s| s
                .to_str()
                .ok_or(anyhow!("could not get unicode string from path")))?,
        reference
            .digest()
            .or(reference.tag())
            .ok_or(anyhow!("OCI reference requires tag or digest"))
            .map(|s| s.trim_start_matches("sha256:"))?,
        out_path
            .extension()
            .unwrap_or("".as_ref())
            .to_str()
            .unwrap()
    );
    let out_path = out_path.trim_start_matches('/').trim_end_matches('.');
    Ok(base_path.join(out_path))
}
