//! An OpenBao (and Vault) token helper: `get`, `store` and `erase` the token of the server in
//! `BAO_ADDR`, kept as service `bao:<address>` with no username.
//!
//! bao runs the helper with the operation as its only argument, sets `BAO_ADDR` and `VAULT_ADDR`
//! to the address in use, sends a token to `store` on stdin, and takes `get`'s stdout as the token
//! verbatim, so nothing may follow it, not even a newline.

use crate::backend::{Backend, BackendError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Get,
    Store,
    Erase,
}

#[derive(Debug, thiserror::Error)]
pub enum BaoError {
    #[error("unknown operation {0:?}: expected get, store or erase")]
    UnknownOperation(String),
    #[error("neither BAO_ADDR nor VAULT_ADDR names the server")]
    NoAddress,
    #[error(transparent)]
    Backend(#[from] BackendError),
}

impl std::str::FromStr for Operation {
    type Err = BaoError;

    fn from_str(operation: &str) -> Result<Self, Self::Err> {
        match operation {
            "get" => Ok(Self::Get),
            "store" => Ok(Self::Store),
            "erase" => Ok(Self::Erase),
            other => Err(BaoError::UnknownOperation(other.to_owned())),
        }
    }
}

/// The server address bao passes in its environment, read through `var`.
pub fn address(var: impl Fn(&str) -> Option<String>) -> Result<String, BaoError> {
    ["BAO_ADDR", "VAULT_ADDR"]
        .into_iter()
        .filter_map(var)
        .find(|address| !address.is_empty())
        .ok_or(BaoError::NoAddress)
}

pub fn service(address: &str) -> String {
    format!("bao:{address}")
}

/// Runs `operation` for the server at `address`, returning what to write to stdout.
pub async fn run(
    backend: &impl Backend,
    operation: Operation,
    address: &str,
    input: &[u8],
) -> Result<Vec<u8>, BaoError> {
    let service = service(address);
    match operation {
        Operation::Get => Ok(backend.get(&service, "").await?.unwrap_or_default()),
        Operation::Store => {
            let token = input.trim_ascii_end();
            backend.set(&service, "", token).await?;
            Ok(Vec::new())
        }
        Operation::Erase => {
            backend.delete(&service, "").await?;
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::Memory;

    const ADDRESS: &str = "https://bao.example.com:8200";

    #[tokio::test]
    async fn a_stored_token_comes_back_exactly() {
        let backend = Memory::default();
        assert!(
            run(&backend, Operation::Store, ADDRESS, b"s.t0ken")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            run(&backend, Operation::Get, ADDRESS, b"").await.unwrap(),
            b"s.t0ken"
        );
        assert_eq!(
            backend
                .get("bao:https://bao.example.com:8200", "")
                .await
                .unwrap(),
            Some(b"s.t0ken".to_vec())
        );
    }

    #[tokio::test]
    async fn a_newline_typed_after_a_token_is_not_part_of_it() {
        let backend = Memory::default();
        run(&backend, Operation::Store, ADDRESS, b"s.t0ken\r\n")
            .await
            .unwrap();
        assert_eq!(
            run(&backend, Operation::Get, ADDRESS, b"").await.unwrap(),
            b"s.t0ken"
        );
    }

    #[tokio::test]
    async fn no_token_reads_as_empty_and_erases_without_error() {
        let backend = Memory::default();
        assert!(
            run(&backend, Operation::Get, ADDRESS, b"")
                .await
                .unwrap()
                .is_empty()
        );
        run(&backend, Operation::Erase, ADDRESS, b"").await.unwrap();
    }

    #[tokio::test]
    async fn erase_forgets_the_token_of_that_server_only() {
        let backend = Memory::default();
        let other = "https://other.example.com:8200";
        run(&backend, Operation::Store, ADDRESS, b"one")
            .await
            .unwrap();
        run(&backend, Operation::Store, other, b"two")
            .await
            .unwrap();
        run(&backend, Operation::Erase, ADDRESS, b"").await.unwrap();
        assert!(
            run(&backend, Operation::Get, ADDRESS, b"")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            run(&backend, Operation::Get, other, b"").await.unwrap(),
            b"two"
        );
    }

    #[test]
    fn bao_addr_wins_over_vault_addr_and_one_of_them_is_needed() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.to_string())
            }
        };
        assert_eq!(
            address(env(&[
                ("BAO_ADDR", "https://a"),
                ("VAULT_ADDR", "https://b")
            ]))
            .unwrap(),
            "https://a"
        );
        assert_eq!(
            address(env(&[("VAULT_ADDR", "https://b")])).unwrap(),
            "https://b"
        );
        assert_eq!(
            address(env(&[("BAO_ADDR", ""), ("VAULT_ADDR", "https://b")])).unwrap(),
            "https://b"
        );
        assert!(matches!(address(env(&[])), Err(BaoError::NoAddress)));
    }

    #[test]
    fn only_the_three_operations_parse() {
        assert_eq!("get".parse::<Operation>().unwrap(), Operation::Get);
        assert_eq!("store".parse::<Operation>().unwrap(), Operation::Store);
        assert_eq!("erase".parse::<Operation>().unwrap(), Operation::Erase);
        assert!(matches!(
            "list".parse::<Operation>(),
            Err(BaoError::UnknownOperation(_))
        ));
    }
}
