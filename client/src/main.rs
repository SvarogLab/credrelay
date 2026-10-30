use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use credrelay_client::config::Config;
use credrelay_client::dbus;
use credrelay_client::keyring::Keyring;
use credrelay_client::prefixes::Prefixes;
use credrelay_client::rpc::Rpc;
use credrelay_client::schemes;
use credrelay_client::spawn::Server;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let config = Config::parse();
    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Serves until the server exits or the link to it breaks. There is no restarting it here: either
/// way every later request would fail, so this process exits and its supervisor starts both afresh.
async fn run(config: Config) -> Result<(), String> {
    let go_keyring =
        Prefixes::new(config.go_keyring_prefixes).map_err(|error| error.to_string())?;
    let mut server = Server::spawn(config.server_exe)
        .await
        .map_err(|error| error.to_string())?;

    // The server's diagnostics end up wherever this process's do.
    let mut server_stderr = server.stderr;
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut server_stderr, &mut tokio::io::stderr()).await;
    });

    let rpc = Rpc::new(
        server.stdout,
        server.stdin,
        Duration::from_secs(config.request_timeout_secs),
    );
    let keyring = Keyring::new(rpc.clone(), schemes::all(go_keyring));
    let builder = zbus::connection::Builder::session();
    let _connection = dbus::serve(builder, keyring)
        .await
        .map_err(|error| format!("can't serve {}: {error}", dbus::BUS_NAME))?;
    tracing::info!("serving {}", dbus::BUS_NAME);

    let status = server
        .child
        .wait()
        .await
        .map_err(|error| error.to_string())?;
    Err(format!("credrelay-server exited: {status}"))
}
