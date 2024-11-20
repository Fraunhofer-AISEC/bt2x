use clap::Parser;
use sigstore::registry::OciReference;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(author, version /*, trailing_var_arg = true*/)]
pub struct Args {
    #[arg(long)]
    pub image: OciReference,
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub subject: String,
    #[arg(long)]
    pub oidc_issuer: url::Url,
    #[arg(long)]
    pub format: probe_rs::flashing::Format,
    #[arg(long)]
    pub do_not_flash: bool,
    #[arg(long)]
    pub log_level: LogLevel,
    #[arg(long)]
    pub check_inclusion: bool,
    #[arg(long)]
    pub tuf_root: PathBuf,
    #[arg(long)]
    pub tuf_meta: PathBuf,
    #[arg(long)]
    pub(crate) fulcio_url: url::Url,
    #[arg(long)]
    pub(crate) rekor_url: url::Url,
    #[arg(long)]
    pub(crate) http: bool,
    #[arg(long)]
    pub(crate) base_address: Option<u64>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum LogLevel {
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
