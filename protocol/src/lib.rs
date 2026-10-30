//! What `credrelay-client` and `credrelay-server` say to each other over the server's stdio: one
//! JSON [`Request`] per line in, one JSON [`Response`] per line out, strictly in turn.
//!
//! JSON lines rather than a binary framing so the server can be driven by hand for testing.

mod handler;
#[cfg(any(test, feature = "memory"))]
mod memory;

use serde::{Deserialize, Serialize};

pub use handler::handle;
#[cfg(any(test, feature = "memory"))]
pub use memory::MemoryStore;

/// A generic credential, as the Credential Manager lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub target: String,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Read {
        target: String,
    },
    Write {
        target: String,
        username: String,
        secret: Vec<u8>,
    },
    Delete {
        target: String,
    },
    /// Every credential whose target starts with `prefix`.
    List {
        prefix: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Secret(Vec<u8>),
    Done,
    Credentials(Vec<Credential>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    #[error("no such credential")]
    NotFound,
    #[error("credential store failed: {0}")]
    Store(String),
}

pub type Response = Result<Reply, Failure>;

/// The credential store as the server sees it: the Credential Manager in production.
pub trait CredentialStore {
    fn read(&self, target: &str) -> Result<Vec<u8>, Failure>;
    fn write(&self, target: &str, username: &str, secret: &[u8]) -> Result<(), Failure>;
    fn delete(&self, target: &str) -> Result<(), Failure>;
    fn list(&self, prefix: &str) -> Result<Vec<Credential>, Failure>;
}

/// Serializes one message as a single line, newline included.
pub fn encode_line<T: Serialize>(message: &T) -> String {
    let mut line = serde_json::to_string(message).expect("protocol messages always serialize");
    line.push('\n');
    line
}

pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips_through_one_line() {
        let request = Request::Write {
            target: "gh:github.com:".into(),
            username: String::new(),
            secret: b"token\nwith newline".to_vec(),
        };
        let line = encode_line(&request);
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with('\n'));
        assert_eq!(decode_line::<Request>(&line).unwrap(), request);
    }

    #[test]
    fn a_request_is_writable_by_hand() {
        let request: Request = decode_line(r#"{"op":"read","target":"gh:github.com:"}"#).unwrap();
        assert_eq!(
            request,
            Request::Read {
                target: "gh:github.com:".into()
            }
        );
    }

    #[test]
    fn a_failure_round_trips() {
        let response: Response = Err(Failure::Store("access denied".into()));
        assert_eq!(
            decode_line::<Response>(&encode_line(&response)).unwrap(),
            response
        );
    }
}
