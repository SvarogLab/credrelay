//! The Credential Manager behind the protocol's store, its errors turned into the protocol's.
#![cfg(windows)]

use credrelay_protocol::{Credential, CredentialStore, Failure};
use credrelay_wincred::{WinCred, WinCredError};

pub struct CredentialManager;

fn failure(error: WinCredError) -> Failure {
    match error {
        WinCredError::NotFound => Failure::NotFound,
        other => Failure::Store(other.to_string()),
    }
}

impl CredentialStore for CredentialManager {
    fn read(&self, target: &str) -> Result<Vec<u8>, Failure> {
        WinCred.read(target).map_err(failure)
    }

    fn write(&self, target: &str, username: &str, secret: &[u8]) -> Result<(), Failure> {
        WinCred.write(target, username, secret).map_err(failure)
    }

    fn delete(&self, target: &str) -> Result<(), Failure> {
        WinCred.delete(target).map_err(failure)
    }

    fn list(&self, prefix: &str) -> Result<Vec<Credential>, Failure> {
        let listed = WinCred.list(prefix).map_err(failure)?;
        Ok(listed
            .into_iter()
            .map(|listed| Credential {
                target: listed.target,
                username: listed.username,
            })
            .collect())
    }
}
