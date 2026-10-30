#![cfg(windows)]

use credrelay_wincred::{WinCred, WinCredError, go_keyring_target};

use super::{Backend, BackendError};

/// The Credential Manager, written directly under go-keyring's names: `service:username`.
pub struct CredentialManager;

impl CredentialManager {
    pub async fn connect() -> Result<Self, BackendError> {
        Ok(Self)
    }
}

impl Backend for CredentialManager {
    async fn get(&self, service: &str, username: &str) -> Result<Option<Vec<u8>>, BackendError> {
        match WinCred.read(&go_keyring_target(service, username)) {
            Ok(secret) => Ok(Some(secret)),
            Err(WinCredError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn set(&self, service: &str, username: &str, secret: &[u8]) -> Result<(), BackendError> {
        Ok(WinCred.write(&go_keyring_target(service, username), username, secret)?)
    }

    async fn delete(&self, service: &str, username: &str) -> Result<bool, BackendError> {
        match WinCred.delete(&go_keyring_target(service, username)) {
            Ok(()) => Ok(true),
            Err(WinCredError::NotFound) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

/// These run against the real Credential Manager of whoever runs them, under a service of their
/// own, and delete what they write.
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_secret_is_stored_under_go_keyrings_name_and_deleted() {
        let service = format!("credrelay-test-{}", std::process::id());
        let backend = CredentialManager::connect().await.unwrap();
        backend.set(&service, "octo", b"t0ken").await.unwrap();
        let raw = WinCred.read(&format!("{service}:octo"));
        assert_eq!(
            backend.get(&service, "octo").await.unwrap(),
            Some(b"t0ken".to_vec())
        );
        assert!(backend.delete(&service, "octo").await.unwrap());
        assert_eq!(raw.unwrap(), b"t0ken");
        assert_eq!(backend.get(&service, "octo").await.unwrap(), None);
        assert!(!backend.delete(&service, "octo").await.unwrap());
    }
}
