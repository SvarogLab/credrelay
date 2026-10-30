//! Windows credentials as go-keyring keeps them: how it names them, on every platform, and the
//! Credential Manager itself, on Windows.

mod store;

#[cfg(windows)]
pub use store::{Listed, MAX_SECRET_LEN, WinCred, WinCredError};

/// The generic credential go-keyring keeps a secret in: `service:username`. Both the Linux
/// service's go-keyring scheme and the Windows keyring utility name credentials with this, so
/// each side reads what the other stored.
pub fn go_keyring_target(service: &str, username: &str) -> String {
    format!("{service}:{username}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_is_the_service_and_username_joined_by_a_colon() {
        assert_eq!(
            go_keyring_target("gh:github.com", "octo"),
            "gh:github.com:octo"
        );
        assert_eq!(go_keyring_target("gh:github.com", ""), "gh:github.com:");
    }
}
