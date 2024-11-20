use std::fs;
use std::fs::read_to_string;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use axum::extract::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{extract::State, routing::get, Router};
use futures::{stream, StreamExt};
use sigstore::crypto::CosignVerificationKey;
use sigstore::rekor::apis::configuration::Configuration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use bt2x_common::gossip::*;
use bt2x_common::rekor::RekorClient;
use bt2x_common::sigstore_config::{KeyConfig, SigstoreConfig};
use bt2x_common::tuf::load_tuf_filesystem;

use crate::cli::Args;

pub mod cli;

#[derive(Debug)]
struct AppState {
    pub current_checkpoint: Arc<RwLock<Checkpoint>>,
    pub rekor_key: Arc<CosignVerificationKey>,
    pub rekor_config: Arc<Configuration>,
}

async fn get_err() -> impl IntoResponse {
    (StatusCode::BAD_REQUEST, "Use POST.")
}

async fn listen(
    State(state): State<Arc<AppState>>,
    Json(checkpoint): Json<Checkpoint>,
) -> impl IntoResponse {
    debug!("got request {checkpoint:?}");
    let mut current_checkpoint = state.current_checkpoint.write().await;
    let rekor_client = RekorClient::new((*state.rekor_config).clone());

    if let Err(err) = checkpoint.verify_signature(&state.rekor_key) {
        debug!("{err:?}");
        return (
            StatusCode::OK,
            Json(GossipResponse::Failure(
                MonitorError::FailedSignatureVerification {
                    request_data: checkpoint,
                    pubkey: (),
                },
            )),
        );
    }
    debug!("signature verified successfully");
    match verify_checkpoints(
        (*current_checkpoint).clone(),
        checkpoint.clone(),
        &rekor_client,
    )
    .await
    {
        Ok(new_checkpoint) => {
            debug!("consistency verified successfully");
            *current_checkpoint = new_checkpoint.clone();
            (
                StatusCode::OK,
                Json(GossipResponse::Success(new_checkpoint.clone())),
            )
        }
        Err(err) => {
            warn!("failed to verify consistency: {err:?}");
            (
                StatusCode::OK,
                Json(GossipResponse::Failure(MonitorError::Inconsistent {
                    request_data: checkpoint,
                    other: current_checkpoint.clone(),
                })),
            )
        }
    }
}

pub async fn main_impl(args: Args) -> Result<()> {
    info!("starting monitor ...");
    let sigstore_config: SigstoreConfig = fs::read(&args.sigstore_config)
        .context("failed to open sigstore config file")
        .and_then(|config| {
            serde_yaml::from_slice(&config).context("failed to parse sigstore config")
        })?;
    debug!("using config: {sigstore_config:?}");
    let rekor_key = match sigstore_config.key_config {
        KeyConfig::Tuf {
            metadata_base,
            targets_base,
            root_path,
            target_names,
        } => {
            debug!("loading Sigstore keys from TUF repo via the file system ...");
            load_tuf_filesystem(&root_path, &metadata_base, &targets_base, &target_names)
                .await
                .map_err(|_| anyhow!("failed to load TUF from file system"))?
                .rekor_key
        }
        KeyConfig::Keys {
            rekor_key: Some(rekor_key),
            ..
        } => {
            debug!("loading rekor key at {rekor_key:?}");
            fs::read(rekor_key).context("failed to read rekor key")?
        }
        _ => panic!("rekor key required, update config"),
    };
    let rekor_key = CosignVerificationKey::from_pem(&rekor_key, &Default::default())
        .context("failed to parse rekor key")?;
    let rekor_config = Arc::new(Configuration {
        base_path: sigstore_config.urls.rekor.to_string(),
        ..Default::default()
    });

    let current_checkpoint: Checkpoint = match args.current_checkpoint {
        Some(current_checkpoint) => {
            debug!("loading checkpoint from {current_checkpoint:?} ...");
            read_to_string(current_checkpoint)
                .context("failed to read checkpoint at path: {current_checkpoint:?}")
                .and_then(|data| data.parse().context("failed to parse checkpoint"))
                .context("failed to load current checkpoint")?
        }
        None => {
            debug!("no checkpoint provided, fetching log info using {rekor_config:?} ...");
            loop {
                let res = sigstore::rekor::apis::tlog_api::get_log_info(&rekor_config)
                    .await
                    .context("failed to get log info")
                    .and_then(|log_info| {
                        Checkpoint::from_str(&log_info.signed_tree_head)
                            .context("failed to parse checkpoint from log info")
                    })?;
                if res.tree_size > 0 {
                    break res;
                }
                info!("log provided checkpoint with tree_size == 0, fetching again later");
                sleep(Duration::from_secs(5)).await
            }
        }
    };
    debug!("verifying the initial checkpoint ...");
    current_checkpoint
        .verify_signature(&rekor_key)
        .context("failed to verify signature")?;
    debug!("successfully verified {current_checkpoint:?}");
    let rekor_key = Arc::new(rekor_key);
    let current_checkpoint = Arc::new(RwLock::new(current_checkpoint));

    let listeners = args.monitor.clone();

    let shared_state = Arc::new(AppState {
        rekor_config: rekor_config.clone(),
        rekor_key: rekor_key.clone(),
        current_checkpoint: current_checkpoint.clone(),
    });

    info!("starting speaker");
    let rekor_config_arc = rekor_config.clone();
    let rekor_key_arc = rekor_key.clone();
    let current_checkpoint_arc = current_checkpoint.clone();

    let speaker = tokio::spawn(async move {
        info!("speaker task spawned");
        let interval = tokio::time::interval(args.gossip_interval.into());
        let rekor_client = RekorClient::new((*rekor_config_arc).clone());
        let forever = stream::unfold(interval, |mut interval| async {
            interval.tick().await;
            debug!("speaker is active ...");
            for url in listeners.iter() {
                let mut current_checkpoint = current_checkpoint_arc.write().await;
                let Ok(response_data) = send_checkpoint(url, &current_checkpoint).await else {
                    warn!("sending checkpoint failed");
                    continue;
                };

                let new_checkpoint = match response_data {
                    GossipResponse::Success(new) => new,
                    GossipResponse::Failure(err) => {
                        warn!("got failure response {err:#?}");
                        continue;
                    }
                };
                if let Err(err) = new_checkpoint.verify_signature(&rekor_key_arc) {
                    warn!("could not verify checkpoint {new_checkpoint:?} because of {err:?}");
                    continue;
                }
                match verify_checkpoints(
                    (*current_checkpoint).clone(),
                    new_checkpoint,
                    &rekor_client,
                )
                .await
                {
                    Ok(new) => *current_checkpoint = new,
                    Err(err) => {
                        warn!("could not verify consistency {err:?}");
                        continue;
                    }
                }
            }
            debug!("speaker finished gossiping");
            Some(((), interval))
        });
        forever.for_each(|_| async {}).await;
    });
    info!("starting poller task");
    let poller = tokio::spawn(async move {
        info!("poller task has started");
        let interval = tokio::time::interval(args.log_interval.into());
        let rekor_client = RekorClient::new((*rekor_config).clone());
        let forever = stream::unfold(interval, |mut interval| async {
            interval.tick().await;
            debug!("poller is active ...");
            match fetch_and_verify_signature(&rekor_client, &rekor_key).await {
                Ok(checkpoint) => {
                    let mut current_checkpoint = current_checkpoint.write().await;
                    let new = verify_checkpoints(
                        (*current_checkpoint).clone(),
                        checkpoint,
                        &rekor_client,
                    )
                    .await
                    .expect("poller failed to verify checkpoint, received from the log");
                    info!("using new checkpoint {new:?}");
                    *current_checkpoint = new;
                }
                Err(err) => {
                    warn!("{err:?}")
                }
            }
            Some(((), interval))
        });
        forever.for_each(|_| async {}).await;
    });

    info!("starting listener");
    let listener = tokio::spawn(async move {
        info!("listener task spawned");
        let app = Router::new()
            .route("/listen", get(get_err).post(listen))
            .with_state(shared_state);

        let listener = tokio::net::TcpListener::bind(&format!("0.0.0.0:{}", args.port))
            .await
            .expect("failed to bind to socket");
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    info!("main thread waiting");
    listener.await.context("failed to join listening server")?;
    speaker.await.context("failed to join speaker loop")?;
    poller.await.context("failed to join polling loop")?;

    info!("exiting ...");
    Ok(())
}

pub fn configure_logging(_args: &Args) {
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::prelude::*;
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            Targets::new()
                .with_target(
                    env!("CARGO_PKG_NAME").replace('-', "_"),
                    tracing_core::Level::DEBUG,
                )
                .with_target("sigstore", tracing_core::Level::INFO)
                .with_target("oci_distribution", tracing_core::Level::DEBUG)
                .with_target("hyper", tracing_core::Level::INFO)
                .with_target("reqwest", tracing_core::Level::INFO),
        )
        .init();
}
