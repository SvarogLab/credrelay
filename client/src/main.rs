use std::io;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use credrelay_client::config::Config;
use credrelay_client::dbus;
use credrelay_client::keyring::Keyring;
use credrelay_client::rpc::{Rpc, RpcError};
use credrelay_client::schemes;
use librelay::client::lifecycle::{self, Died};
use librelay::client::log::{self, LogFilter};
use librelay::client::mux;
use librelay::client::spawn::{Server, SpawnError};
use tokio_util::compat::FuturesAsyncReadCompatExt;

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error(transparent)]
    Spawn(#[from] SpawnError),
    #[error("credrelay-server isn't answering: {0}")]
    NotAnswering(RpcError),
    #[error("can't serve org.freedesktop.secrets: {0}")]
    Serve(zbus::Error),
    #[error("credrelay-server exited: {0}")]
    ServerExited(std::process::ExitStatus),
    #[error("can't wait for credrelay-server: {0}")]
    Wait(io::Error),
    #[error("the connection to credrelay-server ended")]
    LinkEnded,
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = Config::parse();
    let filter = match LogFilter::from_env() {
        Ok(filter) => filter,
        Err(e) => {
            eprintln!("credrelay-client: {e}");
            return ExitCode::FAILURE;
        }
    };
    let server_args = config.server_args(&filter);
    log::init(filter);

    match run(config, server_args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "stopped serving");
            ExitCode::FAILURE
        }
    }
}

/// Serves until the server exits or the connection to it ends. There is no restarting it here:
/// either way every later request would fail, so this process exits and its supervisor starts both
/// afresh.
async fn run(config: Config, server_args: Vec<String>) -> Result<(), RunError> {
    let mut server = Server::spawn(config.server_exe.clone(), server_args).await?;
    tokio::spawn(log::forward_server_stderr(
        server.stderr,
        tokio::io::stderr(),
    ));

    let (mux, driver) = mux::client(tokio::io::join(server.stdout, server.stdin));
    let mut driver = tokio::spawn(driver);
    let rpc = Rpc::new(
        move || {
            let mux = mux.clone();
            async move {
                let stream = mux.open_stream().await.map_err(io::Error::other)?;
                Ok(stream.compat())
            }
        },
        Duration::from_secs(config.request_timeout_secs),
    );
    // One answered request before taking the bus name: a client that starts serving with a server
    // that can't answer would fail every application that calls it.
    rpc.list(schemes::NATIVE_PREFIX)
        .await
        .map_err(RunError::NotAnswering)?;

    let keyring = Keyring::new(rpc, schemes::all(config.go_keyring_prefixes()));
    let builder = zbus::connection::Builder::session();
    let _connection = dbus::serve(builder, keyring)
        .await
        .map_err(RunError::Serve)?;
    tracing::info!("serving {}", dbus::BUS_NAME);

    match lifecycle::died(&mut server.child, &mut driver).await {
        Died::Exited(status) => {
            driver.abort();
            Err(status.map_or_else(RunError::Wait, RunError::ServerExited))
        }
        Died::TransportEnded => Err(RunError::LinkEnded),
    }
}
