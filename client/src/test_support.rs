//! A keyring backed by memory instead of credrelay-server, for tests here and in other crates.

use std::sync::Arc;
use std::time::Duration;

use credrelay_protocol::{MemoryStore, answer};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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
    let prefixes = go_keyring_prefixes.iter().map(|p| p.to_string()).collect();
    Keyring::new(
        in_memory(),
        schemes::all(Prefixes::new(prefixes).expect("non-empty prefixes")),
    )
}

/// A keyring in memory with gh and glab on go-keyring.
pub fn keyring() -> Keyring {
    keyring_with(&["gh:", "glab:"])
}

pub fn attributes(pairs: &[(&str, &str)]) -> Attributes {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}
