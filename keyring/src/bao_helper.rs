//! The token helper OpenBao runs: `token_helper` in `~/.bao` names this binary, and bao calls it
//! with `get`, `store` or `erase` as its only argument. bao takes a path there and no arguments, so
//! this is a binary of its own rather than a subcommand of credrelay-keyring.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use credrelay_keyring::backend::{BackendError, Platform};
use credrelay_keyring::bao::{self, BaoError, Operation};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("credrelay-bao-helper: {e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum HelperError {
    #[error(transparent)]
    Bao(#[from] BaoError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error("can't read the token from stdin: {0}")]
    ReadToken(io::Error),
    #[error("can't write the token to stdout: {0}")]
    WriteToken(io::Error),
}

async fn run() -> Result<(), HelperError> {
    let operation: Operation = std::env::args().nth(1).unwrap_or_default().parse()?;
    let address = bao::address(|name| std::env::var(name).ok())?;
    let mut input = Vec::new();
    if operation == Operation::Store {
        io::stdin()
            .read_to_end(&mut input)
            .map_err(HelperError::ReadToken)?;
    }
    let backend = Platform::connect().await?;
    let output = bao::run(&backend, operation, &address, &input).await?;
    io::stdout()
        .write_all(&output)
        .map_err(HelperError::WriteToken)
}
