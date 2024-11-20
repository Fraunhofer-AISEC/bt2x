use clap::Parser;
use itertools::Itertools;
use sigstore::registry::OciReference;
use std::env::set_current_dir;
use std::ops::Add;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use tracing::{debug, info};
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

#[derive(Debug, Parser)]
#[clap(author, version /*, trailing_var_arg = true*/)]
struct Args {
    /// tagged OCI reference to which the binary will be published
    #[arg(long, value_name = "OCI IMAGE")]
    tag: OciReference,
    /// Rust binary target that will get published
    #[arg(long, value_name = "BINARY")]
    bin: Vec<String>,
    #[arg(long, value_name = "PACKAGE")]
    package: Vec<String>,
    /// LLVM target (e.g. `thumbv6m-none-eabi` for a Pi Pico).
    #[arg(long, value_name = "LLVM TARGET")]
    target: Option<String>,
    #[arg(long)]
    fulcio_url: Option<url::Url>,
    #[arg(long)]
    fulcio_public_key: Option<PathBuf>,
    #[arg(long)]
    rekor_url: Option<url::Url>,
    #[arg(long)]
    rekor_public_key: Option<PathBuf>,
    #[arg(long)]
    dir: Option<PathBuf>,
    #[arg(long)]
    ct_log_url: Option<url::Url>,
    #[arg(long)]
    ct_log_public_key: Option<PathBuf>,
    #[arg(long)]
    oidc_issuer: Option<url::Url>,
    /// Allow HTTP to be used.
    #[clap(long)]
    http: bool,
    /// disable compiling with `--release flag`
    #[clap(long)]
    debug: bool,
    /// log level of this application, defaults to Info.
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    configure_logging(&args);
    let mut cargo_args = vec![];
    let mut objcopy_args = vec![];
    args.bin
        .iter()
        .for_each(|b| cargo_args.extend(["--bin".to_string(), b.clone()]));
    args.bin
        .iter()
        .for_each(|b| objcopy_args.extend(["--bin".to_string(), b.clone()]));
    args.package
        .iter()
        .for_each(|b| cargo_args.extend(["--package".to_string(), b.clone()]));
    if !args.debug {
        cargo_args.push("--release".to_string());
        objcopy_args.push("--release".to_string());
    }
    if let Some(dir) = args.dir {
        set_current_dir(dir).expect("failed to change directory");
    }
    if let Some(target) = &args.target {
        cargo_args.extend(["--target".to_string(), target.clone()]);
        objcopy_args.extend([
            "--".to_string(),
            "-O".to_string(),
            "binary".to_string(),
            format!("target/{target}/release/{}.bin", &args.bin[0]),
        ]);
    }
    info!("Starting `cargo build {}`", cargo_args.iter().join(" "));

    let output = Command::new("cargo")
        .arg("build")
        .args(cargo_args)
        //.args(args.command)
        .output()
        .expect("Cargo failed");
    let stdout = std::str::from_utf8(output.stdout.as_slice()).unwrap_or("OUTPUT WAS NOT UTF-8");
    let stderr = std::str::from_utf8(output.stderr.as_slice()).unwrap_or("OUTPUT WAS NOT UTF-8");
    info!("Cargo finished.");
    info!("Cargo output:");
    info!("------------------------STDOUT------------------------\n{stdout}");
    info!("------------------------STDERR------------------------\n{stderr}");
    info!("------------------------------------------------------");

    info!("Starting `cargo objcopy {}`", objcopy_args.iter().join(" "));
    let output = Command::new("cargo")
        .arg("objcopy")
        .args(objcopy_args)
        //.args(args.command)
        .output()
        .expect("Cargo failed");
    let stdout = std::str::from_utf8(output.stdout.as_slice()).unwrap_or("OUTPUT WAS NOT UTF-8");
    let stderr = std::str::from_utf8(output.stderr.as_slice()).unwrap_or("OUTPUT WAS NOT UTF-8");
    info!("Cargo finished.");
    info!("Cargo output:");
    info!("------------------------STDOUT------------------------\n{stdout}");
    info!("------------------------STDERR------------------------\n{stderr}");
    info!("------------------------------------------------------");
    debug!("reading input binary");
    let bin_path = if let Some(target) = &args.target {
        PathBuf::from("./target").join(target.as_str())
    } else {
        PathBuf::from("./target")
    }
    .join(if args.debug { "debug" } else { "release" })
    .join(format!("{}.bin", args.bin[0].as_str()));

    let ct_log_public_key_file = args.ct_log_public_key.unwrap();
    let root_file = args.fulcio_public_key.unwrap();
    let rekor_public_key = args.rekor_public_key.unwrap();
    let ct_log_public_key_file = ct_log_public_key_file.to_str().unwrap();
    let root_file = root_file.to_str().unwrap();
    let rekor_public_key = rekor_public_key.to_str().unwrap();

    let mut command = Command::new("cosign");
    command
        .args(["upload", "blob"])
        .args(["-f", bin_path.to_str().unwrap(), &args.tag.whole()]);
    info!("running {command:?}");
    let output_tag = command
        .output()
        .map_err(|err| err.to_string())
        .map(|output| {
            std::str::from_utf8(&output.stdout)
                .map_err(|err| err.to_string())
                .and_then(|s| {
                    OciReference::from_str(s.trim_end_matches('\n')).map_err(|err| err.to_string())
                })
        })
        .and_then(|reference| reference)
        .expect("could not get output tag from cosign output");

    let oidc_issuer = args.oidc_issuer.unwrap().to_string();
    let rekor_url = args.rekor_url.unwrap().to_string();
    let fulcio_url = args.fulcio_url.unwrap().to_string();

    info!("running cosign sign-blob <binary>");

    let mut command = Command::new("cosign");
    command
        .args(["sign-blob", bin_path.to_str().unwrap()])
        .args(["--oidc-issuer", oidc_issuer.as_str()])
        .args(["--rekor-url", rekor_url.as_str()])
        .args(["--fulcio-url", fulcio_url.as_str()])
        .args(["--bundle", "bundle.json"])
        .env("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", ct_log_public_key_file)
        .env("SIGSTORE_ROOT_FILE", root_file)
        .env("SIGSTORE_REKOR_PUBLIC_KEY", rekor_public_key)
        .env("COSIGN_EXPERIMENTAL", "1");
    debug!("Running {command:?}");
    command
        .spawn()
        .expect("`cosign sign-blob` failed")
        .wait()
        .expect("could not wait on cosign child process")
        .code()
        .filter(|&c| c == 0)
        .expect("`cosign sign-blob` failed");

    let bundle_tag = OciReference::with_tag(
        output_tag.registry().to_string(),
        output_tag.repository().to_string(),
        output_tag
            .digest()
            .unwrap()
            .replace(':', "-")
            .add(".bundle"),
    );
    info!("uploading bundle json as blob to {bundle_tag:?}");
    let mut command = Command::new("cosign");
    command
        .args(["upload", "blob"])
        .args(["-f", "bundle.json", &bundle_tag.whole()]);
    debug!("Running {command:?}");
    command
        .spawn()
        .expect("`cosign upload blob` failed")
        .wait()
        .expect("could not wait on cosign child process")
        .code()
        .filter(|&c| c == 0)
        .expect("`cosign upload blob` failed");
    info!("Completed!");

    info!("running cosign sign <tag>");
    let mut command = Command::new("cosign");
    command
        .args(["sign", &output_tag.whole()])
        .args(["--oidc-issuer", oidc_issuer.as_str()])
        .args(["--rekor-url", rekor_url.as_str()])
        .args(["--fulcio-url", fulcio_url.as_str()])
        .env("SIGSTORE_CT_LOG_PUBLIC_KEY_FILE", ct_log_public_key_file)
        .env("SIGSTORE_ROOT_FILE", root_file)
        .env("SIGSTORE_REKOR_PUBLIC_KEY", rekor_public_key)
        .env("COSIGN_EXPERIMENTAL", "1");
    debug!("Running {command:?}");
    command
        .spawn()
        .expect("`cosign sign-blob` failed")
        .wait()
        .expect("could not wait on cosign child process")
        .code()
        .filter(|&c| c == 0)
        .expect("`cosign sign-blob` failed");

    // let data = fs::read(bin_path).expect("failed to read input");
    //
    // let mut oci_client = oci_distribution::client::Client::new(ClientConfig {
    //     protocol: if args.http { Http } else { Https },
    //     ..Default::default()
    // });
    // let image = oci_distribution::Reference::from_str(&args.tag.whole()).expect("this should never fail");
    // let layers = [ImageLayer {
    //     data: data.clone(),
    //     media_type: "application/octet-stream".to_string(),
    //     annotations: None,
    // }];
    // let config = oci_distribution::client::Config {
    //     data: r#"{}"#
    //         .as_bytes().to_vec(),
    //     media_type: "application/vnd.oci.image.config.v1+json".to_string(),
    //     annotations: None,
    // };
    // let mut image_manifest = manifest::OciImageManifest::build(&layers, &config, None);
    // image_manifest.media_type = Some("application/vnd.oci.image.manifest.v1+json".to_string());
    // debug!("Manifest: {image_manifest:#?}");
    //
    // debug!("uploading to OCI registry...");
    // let res = match oci_client.push(
    //     &image,
    //     &layers,
    //     config,
    //     &Anonymous,
    //     Some(image_manifest),
    // ).await {
    //     Ok(res) => { res }
    //     Err(err) => {
    //         error!("failed to push {err:?}");
    //         exit(-1);
    //     }
    // };
    // debug!("Upload completed.");
    //
    // debug!("Creating Fulcio client.");
    // let fulcio_client = sigstore::fulcio::FulcioClient::new(
    //     args.fulcio_url.unwrap(),
    //     Oauth(sigstore::fulcio::oauth::OauthTokenProvider::default()
    //         .with_issuer("http://dex-idp:8888/")),
    // );
    // debug!("Sending certificate request.");
    // let (signer, cert) = match fulcio_client.request_cert(SigningScheme::ECDSA_P256_SHA256_ASN1).await {
    //     Ok((SigStoreSigner::ECDSA_P256_SHA256_ASN1(signer), cert)) => { (signer, cert) }
    //     Err(err) => {
    //         error!("requesting fulcio cert failed {err}");
    //         exit(-1);
    //     }
    //     Ok((signer, cert)) => {
    //         error!("unexpected response {signer:?}");
    //         exit(-1);
    //     }
    // };
    // let sigining_cert = Base64Standard.encode(cert.to_string());
    // let signature = signer.sign(data.as_slice())
    //     .expect("failed to create signature");
    //
    // let digest = Sha256::digest(data.as_slice());
    // let hex_digest = hex::encode(digest.as_slice());
    //
    //
    // let proposed_entry = ProposedEntry::Hashedrekord {
    //     api_version: "0.0.1".to_string(),
    //     spec: Spec {
    //         signature: Signature {
    //             content: Base64Standard.encode(signature.as_slice()),
    //             public_key: PublicKey::new(sigining_cert),
    //         },
    //         data: Data {
    //             hash: Hash { algorithm: AlgorithmKind::sha256, value: hex_digest },
    //         },
    //     },
    // };
    //
    // let entry = create_log_entry(
    //     &RekorConfig {
    //         base_path: args.rekor_url.expect("please add rekor url").to_string(),
    //         user_agent: None,
    //         client: Default::default(),
    //         basic_auth: None,
    //         oauth_access_token: None,
    //         bearer_access_token: None,
    //         api_key: None,
    //     },
    //     proposed_entry,
    // ).await.expect("failed to create entry");
    // let cosign_bundle = CosignBundle::from_signing_material_and_log_entry(
    //     signature.as_slice(),
    //     cert.to_string().as_bytes(),
    //     &entry,
    // ).expect("failed to produce cosign bundle");
    // let bundle_json = serde_json::to_string(&cosign_bundle).expect("failed to produce bundle JSON");
    // write("bundle-cli.json", bundle_json.as_bytes()).expect("failed to write");
    // let compact_bundle = CompactRekorBundle::from(cosign_bundle);
    // let bundle_json = serde_json::to_string(&compact_bundle).expect("failed to produce bundle JSON");
    // write("bundle-cli-compact.json", bundle_json.as_bytes()).expect("failed to write");
    // debug!("{entry:?}");
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Trace,
}

impl From<&LogLevel> for tracing_core::LevelFilter {
    fn from(value: &LogLevel) -> Self {
        match value {
            LogLevel::Debug => tracing_core::Level::DEBUG.into(),
            LogLevel::Info => tracing_core::Level::INFO.into(),
            LogLevel::Warn => tracing_core::Level::WARN.into(),
            LogLevel::Error => tracing_core::Level::ERROR.into(),
            LogLevel::Trace => tracing_core::Level::TRACE.into(),
        }
    }
}

fn configure_logging(args: &Args) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            Targets::new()
                .with_target(env!("CARGO_PKG_NAME").replace('-', "_"), &args.log_level)
                .with_target("sigstore", tracing_core::Level::INFO)
                .with_target("oci_distribution", tracing_core::Level::DEBUG)
                .with_target("hyper", tracing_core::Level::INFO)
                .with_target("reqwest", tracing_core::Level::INFO),
        )
        .init();
}
