mod config;
mod serve;
mod store;

use std::process::ExitCode;

use clap::Parser;

use config::Config;

#[tokio::main]
async fn main() -> ExitCode {
    let config = Config::parse();
    // stdout carries the mux, so diagnostics go to stderr, which the client forwards.
    librelay::server::log::init(&config.log);

    #[cfg(windows)]
    {
        run().await
    }
    #[cfg(not(windows))]
    {
        tracing::error!("the Credential Manager exists only on Windows");
        ExitCode::FAILURE
    }
}

/// Answers each stream the client opens until the mux ends. Its end is how this process learns
/// the client is gone: WSL doesn't end a Windows process along with the Linux process that
/// started it.
#[cfg(windows)]
async fn run() -> ExitCode {
    use std::sync::Arc;

    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let store = Arc::new(store::CredentialManager);
    let stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    let (mut acceptor, driver) = librelay::server::mux::server(stdio);
    tokio::spawn(async move {
        while let Some(stream) = acceptor.accept().await {
            let store = store.clone();
            tokio::spawn(async move {
                if let Err(error) = serve::serve_stream(store, stream.compat()).await {
                    tracing::warn!(%error, "a request went unanswered");
                }
            });
        }
    });
    match driver.await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::info!(%error, "the client is gone");
            ExitCode::SUCCESS
        }
    }
}
