use clap::Parser;
use sigstore::registry::OciReference;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    /// OCI image references
    #[arg(long, value_name = "OCI REFERENCE")]
    pub(crate) image: Vec<OciReference>,
    #[arg(long)]
    pub(crate) fulcio_url: Option<url::Url>,
    #[arg(long)]
    pub(crate) rekor_url: Option<url::Url>,
    #[arg(long)]
    pub(crate) ct_log_url: Option<url::Url>,
    /// allow HTTP connections
    #[clap(long)]
    pub(crate) http: bool,
    /// application logging level
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    pub(crate) log_level: LogLevel,
    /// interval at which OCI images are checked
    #[clap(long)]
    pub(crate) interval: Option<humantime::Duration>,
    /// path to the configuration file, consult [crate::config::Config] for more information.
    #[clap(long, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,
    /// directory to which audited files and signatures are written to
    #[clap(long)]
    pub(crate) outdir: PathBuf,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub(crate) enum LogLevel {
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
