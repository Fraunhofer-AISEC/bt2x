mod cli;
mod config;

use sigstore::registry::{ClientConfig, ClientProtocol, OciReference};
use sigstore::trust::ManualTrustRoot;
use std::collections::HashMap;
use url::Url;

use bt2x_common::rekor::Configuration as RekorConfig;
use bt2x_common::rekor::RekorClient;
use clap::Parser;
use sigstore::cosign::verification_constraint::{AnnotationVerifier, VerificationConstraintVec};
use std::fs;
use std::fs::{read_to_string, OpenOptions};
use std::io::{BufReader, Cursor, Write};
use std::path::{Path, PathBuf};

use oci_distribution::client as oci_client;
use oci_distribution::secrets::RegistryAuth;
use tracing::{debug, error, info};

use tracing_subscriber::filter::Targets;

use crate::config::References;
use anyhow::{anyhow, Result};
use bt2x_common::artifact::source::oci::OciSource;
use bt2x_common::verifier::bt::{BinaryTransparencyVerifier, SigstoreKeys};
use bt2x_common::verifier::Artifact::{Binary, BundledBinary};
use bt2x_common::verifier::{Artifact, Verifier};
use sigstore::cosign::bundle::SignedArtifactBundle;
use tracing_subscriber::prelude::*;

use base64::engine::{general_purpose::STANDARD as BASE64_STANDARD, Engine};
use bt2x_common::sigstore_config::KeyConfig;
use bt2x_common::tuf::load_tuf_filesystem;
use rustls_pemfile::{read_one, Item};

fn configure_logging(cli: &cli::Args) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            Targets::new()
                .with_target(env!("CARGO_PKG_NAME").replace('-', "_"), &cli.log_level)
                .with_target("bt2x_common", &cli.log_level)
                .with_target("sigstore", tracing_core::Level::INFO)
                .with_target("oci_distribution", tracing_core::Level::INFO)
                .with_target("hyper", tracing_core::Level::INFO)
                .with_target("reqwest", tracing_core::Level::INFO),
        )
        .init();
}

#[tokio::main]
pub async fn main() {
    // parse args and read config
    let cli = crate::cli::Args::parse();
    let config = cli
        .config
        .as_ref()
        .map(|path| read_to_string(path).expect("config file not found"))
        .map(|s| serde_yaml::from_str::<config::Config>(&s).expect("invalid config file"))
        .unwrap();
    configure_logging(&cli.clone());

    // either load keys from filesystem or load them from a TUF repo stored in the filesystem
    let (rekor_key, fulcio_cert, ctlog_key) = match config.sigstore_config.key_config {
        KeyConfig::Tuf {
            metadata_base,
            targets_base,
            root_path,
            target_names,
        } => {
            let repo =
                load_tuf_filesystem(&root_path, &metadata_base, &targets_base, &target_names)
                    .await
                    .expect("");
            (repo.rekor_key, repo.fulcio_cert, repo.ctlog_key)
        }
        KeyConfig::Keys {
            rekor_key: Some(rekor_key),
            ctlog_key: Some(ctlog_key),
            fulcio_cert: Some(fulcio_cert),
        } => (
            fs::read(rekor_key).expect("failed to read rekor key"),
            fs::read(fulcio_cert).expect("failed to read fulcio cert"),
            fs::read(ctlog_key).expect("failed to read rekor key"),
        ),
        _ => panic!("rekor key required, update config"),
    };

    // setup clients and configs for clients
    let rekor_client = RekorClient::new(RekorConfig {
        base_path: config.sigstore_config.urls.rekor.to_string(),
        ..Default::default()
    });

    let registry_config = ClientConfig {
        protocol: if cli.http {
            ClientProtocol::Http
        } else {
            ClientProtocol::Https
        },
        accept_invalid_certificates: false,
        extra_root_certificates: vec![],
        accept_invalid_hostnames: true,
    };
    let mut reader = BufReader::new(Cursor::new(fulcio_cert.clone()));
    let Some(Item::X509Certificate(fulcio_cert_der)) =
        read_one(&mut reader).expect("failed to decode PEM")
    else {
        panic!("error converting parsing fulcio cert")
    };
    let mut reader = BufReader::new(Cursor::new(rekor_key.clone()));
    let Some(Item::SubjectPublicKeyInfo(rekor_key_der)) =
        read_one(&mut reader).expect("failed to decode PEM")
    else {
        panic!("error converting parsing rekor key")
    };
    let mut reader = BufReader::new(Cursor::new(ctlog_key.clone()));
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
        protocol: if cli.http {
            oci_client::ClientProtocol::Http
        } else {
            oci_client::ClientProtocol::Https
        },
        ..Default::default()
    };

    // configure verifier
    let mut verifier = BinaryTransparencyVerifier::builder()
        .monitors(config.monitors)
        .rekor_client(rekor_client)
        .cosign_client(cosign_client)
        .keys(
            SigstoreKeys::builder()
                .rekor_pub_key(String::from_utf8(rekor_key.to_vec()).unwrap())
                .fulcio_cert(String::from_utf8(fulcio_cert.to_vec()).unwrap())
                .ct_log_key(String::from_utf8(fulcio_cert.to_vec()).unwrap())
                .build(),
        )
        .build();

    // configure source from which images are downloaded
    let mut oci_source = OciSource::new(oci_client_config, RegistryAuth::Anonymous);
    let references: Vec<(OciReference, VerificationConstraintVec)> = config
        .references
        .into_iter()
        .chain(cli.image.into_iter().map(|r| References {
            tag: r,
            subjects: None,
            annotations: None,
        }))
        .map(|r| {
            let mut constraints = VerificationConstraintVec::new();
            constraints.extend(r.subjects.unwrap_or_default().into_iter().map(|s| s.into()));
            constraints.push(Box::new(AnnotationVerifier {
                annotations: r.annotations.unwrap_or_default(),
            }));
            (r.tag, constraints)
        })
        .collect();
    debug!("{:#?}", references);

    // server loop
    loop {
        debug!("running loop");
        // loop over references
        for (reference, constraints) in references.iter() {
            debug!("checking {}", &reference);
            // verify that each reference is valid under the given constraints
            // on success it writes the image to the file system
            match run_verify(&mut oci_source, reference, constraints, &mut verifier).await {
                // raw binary
                Ok(Binary(artifact)) => {
                    info!("Image successfully verified");
                    let bytes = artifact;
                    fs::create_dir_all(&cli.outdir).expect("failed to create output dir");

                    let out_path = match build_path(cli.outdir.as_path(), reference) {
                        Ok(path) => path,
                        Err(err) => {
                            error!(
                                "could not create path for {reference:?} output because of {err:?}"
                            );
                            continue;
                        }
                    };
                    debug!("Path is {out_path:?}");
                    if !out_path.exists() {
                        debug!("Writing to {out_path:?}");
                        OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .open(out_path)
                            .expect("failed to create output file")
                            .write_all(&bytes)
                            .expect("failed to write output file");
                    }
                }
                Err(err) => {
                    info!("{:?}", err);
                    continue;
                }
                // binary that is bundled with a signature
                Ok(BundledBinary { binary, bundle }) => {
                    info!("Image AND Bundle successfully verified");
                    let bytes = binary;
                    fs::create_dir_all(&cli.outdir).expect("failed to create output dir");

                    let out_path = match build_path(cli.outdir.as_path(), reference) {
                        Ok(path) => path,
                        Err(err) => {
                            error!(
                                "could not create path for {reference:?} output because of {err:?}"
                            );
                            continue;
                        }
                    };
                    debug!("Path is {out_path:?}");
                    debug!("Writing to {out_path:?}");
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&out_path)
                        .expect("failed to create output file")
                        .write_all(&bytes)
                        .expect("failed to write output file");
                    let mut out_path_bundle = out_path.clone();
                    out_path_bundle.set_extension("json");
                    debug!("Bundle path is {out_path_bundle:?}");
                    debug!("Writing to {out_path_bundle:?}");
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(out_path_bundle)
                        .expect("failed to create output file")
                        .write_all(&bundle)
                        .expect("failed to write output file");
                    let mut out_path_bundle = out_path.clone();
                    out_path_bundle.set_extension("canonical.json");
                    debug!("Bundle path is {out_path_bundle:?}");
                    let bundle: SignedArtifactBundle =
                        serde_json::from_slice(bundle.as_slice()).expect("failed to parse bundle");
                    let canonical_json = BASE64_STANDARD
                        .encode(bundle.rekor_bundle.payload.to_canonical_json().unwrap());
                    let encoded_set = BASE64_STANDARD
                        .encode(bundle.rekor_bundle.signed_entry_timestamp.as_slice());
                    let canonical_bundle = HashMap::from([
                        ("SignedEntryTimestamp", &encoded_set),
                        ("Payload", &canonical_json),
                    ]);
                    debug!("Writing to {out_path_bundle:?}");
                    OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(out_path_bundle)
                        .expect("failed to create output file")
                        .write_all(&serde_json::to_vec(&canonical_bundle).unwrap())
                        .expect("failed to write output file");
                }
            }
        }

        if let Some(interval) = cli.interval {
            tokio::time::sleep(interval.into()).await
        } else {
            debug!("Exiting...");
            break;
        }
    }
}

/// Builds a file path from the OCI reference at which the output file is stored.
fn build_path(base_path: &Path, reference: &OciReference) -> Result<PathBuf> {
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

async fn run_verify(
    oci_source: &mut OciSource,
    reference: &OciReference,
    constraints: &VerificationConstraintVec,
    verifier: &mut BinaryTransparencyVerifier,
) -> Result<Artifact<Vec<u8>>> {
    debug!("checking {}", &reference);
    verifier.verify(oci_source, reference, constraints).await
}
