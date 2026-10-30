//! The token helper OpenBao runs: `token_helper` in `~/.bao` names this binary, and bao calls it
//! with `get`, `store` or `erase` as its only argument. bao takes a path there and no arguments, so
//! this is a binary of its own rather than a subcommand of credrelay-keyring.

use std::io::{Read, Write};
use std::process::ExitCode;

use credrelay_keyring::backend::Platform;
use credrelay_keyring::bao::{self, BaoError, Operation};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("credrelay-bao-helper: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let operation: Operation = std::env::args()
        .nth(1)
        .unwrap_or_default()
        .parse()
        .map_err(|error: BaoError| error.to_string())?;
    let address =
        bao::address(|name| std::env::var(name).ok()).map_err(|error| error.to_string())?;
    let mut input = Vec::new();
    if operation == Operation::Store {
        std::io::stdin()
            .read_to_end(&mut input)
            .map_err(|error| format!("can't read the token from stdin: {error}"))?;
    }
    let backend = Platform::connect()
        .await
        .map_err(|error| error.to_string())?;
    let output = bao::run(&backend, operation, &address, &input)
        .await
        .map_err(|error| error.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|error| format!("can't write the token to stdout: {error}"))
}
