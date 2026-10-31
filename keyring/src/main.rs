use std::io::{self, Read};
use std::process::ExitCode;

use clap::Parser;
use credrelay_keyring::backend::{BackendError, Platform};
use credrelay_keyring::cli::{self, Cli, CliError, Command};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    credrelay_keyring::finish("credrelay-keyring", run(Cli::parse()).await)
}

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("can't read the secret from stdin: {0}")]
    ReadSecret(io::Error),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    Cli(#[from] CliError),
}

async fn run(cli: Cli) -> Result<Vec<u8>, MainError> {
    let mut input = Vec::new();
    if matches!(cli.command, Command::Set(_)) {
        io::stdin()
            .read_to_end(&mut input)
            .map_err(MainError::ReadSecret)?;
    }
    let backend = Platform::connect().await?;
    Ok(cli::run(&backend, &cli.command, &input).await?)
}
