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

/// Answers each stream the client opens until the client is gone, whether it closed the
/// connection or died: WSL doesn't end a Windows process along with the Linux process that started
/// it. Exits right away then, so a Credential Manager call still blocked can't keep it alive.
#[cfg(windows)]
async fn run() -> ExitCode {
    use std::sync::Arc;

    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let store = Arc::new(store::CredentialManager);
    let stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    let outcome = librelay::server::mux::serve(stdio, move |stream| {
        let store = store.clone();
        async move {
            if let Err(e) = serve::serve_stream(store, stream.compat()).await {
                tracing::warn!(error = %e, "a request went unanswered");
            }
        }
    })
    .await;
    if let Err(e) = &outcome {
        tracing::error!(error = %e, "the connection to the client failed");
    }
    std::process::exit(if outcome.is_ok() { 0 } else { 1 })
}
