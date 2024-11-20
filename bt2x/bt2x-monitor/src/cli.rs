use clap::Parser;
use std::path::PathBuf;
use url::Url;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// path to a Sigstore configuration file, consult [bt2x_common::sigstore_config::SigstoreConfig] for more information.
    #[arg(long)]
    pub sigstore_config: PathBuf,
    #[arg(long)]
    /// actively gossip to the monitor at the specified URL
    pub monitor: Vec<Url>,
    #[arg(long)]
    /// use the checkpoint at this path as the initial checkpoint
    pub current_checkpoint: Option<PathBuf>,
    /// port for the gossiping HTTP server of this monitor
    #[arg(long, default_value_t = 3131)]
    pub port: u16,
    /// interval at which the Rekor log is queried for new checkpoints
    #[arg(long)]
    pub log_interval: humantime::Duration,
    /// interval at which checkpoints are sent to other monitors
    #[arg(long)]
    pub gossip_interval: humantime::Duration,
}
