//! A keyring backed by memory instead of credrelay-server, for tests here and in other crates.

use credrelay_protocol::{MemoryStore, decode_line, encode_line, handle};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::keyring::Keyring;
use crate::prefixes::Prefixes;
use crate::rpc::Rpc;
use crate::schemes::{self, Attributes};

/// An `Rpc` whose far end answers in-process from a [`MemoryStore`], with the server's own request
/// handler.
pub fn in_memory() -> Rpc {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (client_reader, client_writer) = tokio::io::split(client);
    tokio::spawn(async move {
        let store = MemoryStore::default();
        let (server_reader, mut server_writer) = tokio::io::split(server);
        let mut lines = BufReader::new(server_reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let response = handle(&store, decode_line(&line).unwrap());
            let encoded = encode_line(&response);
            if server_writer.write_all(encoded.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    Rpc::new(client_reader, client_writer)
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
