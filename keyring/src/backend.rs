//! Where secrets are kept: the Secret Service on Linux, the Credential Manager on Windows.

#[cfg(windows)]
mod credential_manager;
#[cfg(test)]
pub mod memory;
#[cfg(unix)]
mod secret_service;

#[cfg(windows)]
pub use credential_manager::CredentialManager as Platform;
#[cfg(unix)]
pub use secret_service::SecretService as Platform;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BackendError(pub String);

/// One secret per `(service, username)`, as go-keyring keeps them.
#[expect(
    async_fn_in_trait,
    reason = "every caller runs on a current-thread runtime, so the futures needn't be Send"
)]
pub trait Backend {
    async fn get(&self, service: &str, username: &str) -> Result<Option<Vec<u8>>, BackendError>;

    /// Stores `secret`, replacing what was there.
    async fn set(&self, service: &str, username: &str, secret: &[u8]) -> Result<(), BackendError>;

    /// Deletes the secret, returning whether there was one.
    async fn delete(&self, service: &str, username: &str) -> Result<bool, BackendError>;
}
