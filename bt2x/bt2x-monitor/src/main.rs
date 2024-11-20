use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let args = bt2x_monitor::cli::Args::parse();
    bt2x_monitor::configure_logging(&args);
    bt2x_monitor::main_impl(args).await
}
