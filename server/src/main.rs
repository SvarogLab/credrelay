mod config;
mod serve;
mod wincred;

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;

use config::Config;

fn main() -> ExitCode {
    // stdout carries the protocol, so diagnostics go to stderr, which the client forwards.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    Config::parse();

    #[cfg(windows)]
    {
        // The client's end of stdin closing is how this process learns the client is gone:
        // WSL doesn't end a Windows process along with the Linux process that spawned it.
        match serve::serve(
            &wincred::WinCred,
            std::io::stdin().lock(),
            std::io::stdout().lock(),
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                tracing::error!(%error, "stopped answering");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(windows))]
    {
        tracing::error!("the Credential Manager exists only on Windows");
        ExitCode::FAILURE
    }
}
