use std::process::ExitCode;

use clap::Parser;
use credrelay_client::config::Config;
use librelay::client::log::{self, LogFilter};

#[tokio::main]
async fn main() -> ExitCode {
    let config = Config::parse();
    let filter = match LogFilter::from_env() {
        Ok(filter) => filter,
        Err(e) => {
            eprintln!("credrelay-client: {e}");
            return ExitCode::FAILURE;
        }
    };
    let server_args = config.server_args(&filter);
    log::init(filter);

    match credrelay_client::run(config, server_args).await {
        Ok(status) => {
            tracing::info!(server = %status, "stopped");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "stopped serving");
            ExitCode::FAILURE
        }
    }
}
