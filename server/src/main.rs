mod config;
mod serve;
mod wincred;

use std::process::ExitCode;

use clap::Parser;
use credrelay_protocol::Allowlist;

use config::Config;

fn main() -> ExitCode {
    // stdout carries the protocol, so diagnostics go to stderr, which the client forwards.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let config = Config::parse();
    let allowlist = match Allowlist::new(config.allow_prefixes) {
        Ok(allowlist) => allowlist,
        Err(error) => {
            tracing::error!(%error, "refusing to start");
            return ExitCode::FAILURE;
        }
    };

    #[cfg(windows)]
    {
        // The client's end of stdin closing is how this process learns the client is gone:
        // WSL doesn't end a Windows process along with the Linux process that spawned it.
        match serve::serve(
            &wincred::WinCred,
            &allowlist,
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
        let _ = allowlist;
        tracing::error!("the Credential Manager exists only on Windows");
        ExitCode::FAILURE
    }
}
