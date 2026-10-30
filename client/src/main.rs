mod config;
mod dbus;
mod keyring;
mod prefixes;
mod rpc;
mod schemes;
mod session;
mod spawn;

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::Parser;

use config::Config;
use keyring::Keyring;
use prefixes::Prefixes;
use rpc::Rpc;
use spawn::Server;

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

/// Serves until the server exits. There is no restarting it here: losing it means every later
/// request would fail, so this process exits too and its supervisor starts both afresh.
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

    let keyring = Keyring::new(
        Rpc::new(server.stdout, server.stdin),
        schemes::all(go_keyring),
    );
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
