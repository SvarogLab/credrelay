//! A keyring backed by memory instead of credrelay-server, for tests here and in other crates.

use std::sync::Arc;
use std::time::Duration;

use std::process::Stdio;

use credrelay_protocol::{MemoryStore, answer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::keyring::Keyring;
use crate::rpc::Rpc;
use crate::schemes::Prefixes;
use crate::schemes::{self, Attributes};

/// An `Rpc` whose every stream is answered in-process from one [`MemoryStore`], with the server's
/// own request handler.
pub fn in_memory() -> Rpc {
    let store = Arc::new(MemoryStore::default());
    Rpc::new(
        move || {
            let store = store.clone();
            async move {
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut server = BufReader::new(server);
                    let mut line = String::new();
                    if server.read_line(&mut line).await.is_ok()
                        && let Ok(answer) = answer(&*store, &line)
                    {
                        let _ = server.get_mut().write_all(answer.as_bytes()).await;
                    }
                });
                Ok(client)
            }
        },
        Duration::from_secs(10),
    )
}

/// A keyring in memory whose go-keyring scheme claims the services under `go_keyring_prefixes`.
pub fn keyring_with(go_keyring_prefixes: &[&str]) -> Keyring {
    let prefixes = go_keyring_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
    Keyring::new(
        in_memory(),
        schemes::all(Prefixes::new(prefixes).expect("non-empty prefixes")),
    )
}

/// A keyring in memory with gh and glab on go-keyring.
pub fn keyring() -> Keyring {
    keyring_with(&["gh:", "glab:"])
}

/// A private `dbus-daemon` with a session bus configuration, gone when dropped.
pub struct Bus {
    _daemon: Child,
    address: String,
}

impl Bus {
    pub async fn start() -> Self {
        let mut daemon = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("dbus-daemon must be installed to run these tests");
        let mut address = String::new();
        BufReader::new(daemon.stdout.take().expect("stdout is piped"))
            .read_line(&mut address)
            .await
            .expect("dbus-daemon prints its address");
        Self {
            _daemon: daemon,
            address: address.trim().to_owned(),
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address())
            .build()
            .await
            .expect("dbus-daemon accepts a connection")
    }
}

pub fn attributes(pairs: &[(&str, &str)]) -> Attributes {
    pairs
        .iter()
        .map(|&(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}
