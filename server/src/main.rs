mod config;
mod serve;

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;

use config::Config;

fn main() -> ExitCode {
    let config = Config::parse();
    let filter = match tracing_subscriber::EnvFilter::try_new(&config.log_filter) {
        Ok(filter) => filter,
        Err(error) => {
            eprintln!("credrelay-server: invalid --log-filter: {error}");
            return ExitCode::FAILURE;
        }
    };
    // stdout carries the protocol, so diagnostics go to stderr, which the client forwards. There
    // the client or the journal stamps each line, so the server adds a time only on a terminal.
    let on_terminal = std::io::stderr().is_terminal();
    let logs = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(on_terminal)
        .with_env_filter(filter);
    if on_terminal {
        logs.init();
    } else {
        logs.without_time().init();
    }

    #[cfg(windows)]
    {
        // The client's end of stdin closing is how this process learns the client is gone:
        // WSL doesn't end a Windows process along with the Linux process that spawned it.
        match serve::serve(
            &credrelay_wincred::WinCred,
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
