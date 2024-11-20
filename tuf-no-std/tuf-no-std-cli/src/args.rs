use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the config file.
    pub config: PathBuf,
}
