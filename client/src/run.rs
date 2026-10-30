//! The client's whole life: start the server, serve the Secret Service, and stop.

use std::io;
use std::process::ExitStatus;
use std::time::Duration;

use librelay::client::lifecycle::{self, Died};
use librelay::client::relay::{self, CloseError, StartError};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::config::Config;
use crate::dbus;
use crate::keyring::Keyring;
use crate::rpc::{Rpc, RpcError};
use crate::schemes;

/// How long the server gets to exit on its own once the client has closed the connection.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Start(#[from] StartError),
    #[error("credrelay-server isn't answering: {0}")]
    NotAnswering(RpcError),
    #[error("can't serve org.freedesktop.secrets: {0}")]
    Serve(zbus::Error),
    #[error("can't listen for a signal to stop: {0}")]
    Signal(io::Error),
    #[error(transparent)]
    Died(Died),
    #[error("credrelay-server didn't stop: {0}")]
    Close(#[from] CloseError),
}

/// Serves until told to stop, or until the server exits or the connection to it ends.
///
/// There is no restarting the server here: every later request would fail, so this process exits and its
/// supervisor starts both afresh.
pub async fn run(config: Config, server_args: Vec<String>) -> Result<ExitStatus, RunError> {
    let (handle, mut link) = relay::start(config.server_exe.clone(), server_args, None).await?;
    let opener = handle.clone();
    let rpc = Rpc::new(
        move || {
            let mux = opener.clone();
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
    let serving = dbus::serve(zbus::connection::Builder::session(), keyring)
        .await
        .map_err(RunError::Serve)?;
    tracing::info!("serving {}", dbus::BUS_NAME);

    tokio::select! {
        died = link.died() => return Err(RunError::Died(died)),
        signal = lifecycle::shutdown_signal() => signal.map_err(RunError::Signal)?,
    }
    tracing::info!("stopping");
    serving.stop().await;
    Ok(link.close(handle, CLOSE_TIMEOUT).await?)
}
