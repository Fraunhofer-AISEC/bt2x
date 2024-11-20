use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub repo_path: PathBuf,
    #[arg(long)]
    pub binaries: PathBuf,
    #[arg(long)]
    pub signatures: PathBuf,
}
