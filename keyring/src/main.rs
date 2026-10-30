use std::io::{Read, Write};
use std::process::ExitCode;

use clap::Parser;
use credrelay_keyring::backend::Platform;
use credrelay_keyring::cli::{self, Cli, Command};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut input = Vec::new();
    if matches!(cli.command, Command::Set(_))
        && let Err(error) = std::io::stdin().read_to_end(&mut input)
    {
        eprintln!("credrelay-keyring: can't read the secret from stdin: {error}");
        return ExitCode::FAILURE;
    }
    let result = match Platform::connect().await {
        Ok(backend) => cli::run(&backend, &cli.command, &input).await,
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(output) => match std::io::stdout().write_all(&output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("credrelay-keyring: can't write to stdout: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("credrelay-keyring: {error}");
            ExitCode::FAILURE
        }
    }
}
