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

#[cfg(test)]
mod tests {
    use credrelay_protocol::{Reply, Request, handle};

    use super::*;

    /// Deletes the credential when dropped, so a failed assertion leaves nothing behind.
    struct Written(String);

    impl Drop for Written {
        fn drop(&mut self) {
            let _ = WinCred.delete(&self.0);
        }
    }

    /// Through the same handler the server answers streams with, against the real Credential
    /// Manager, under a name no one else uses.
    #[test]
    fn every_request_reaches_the_credential_manager() {
        let prefix = format!("credrelay-test:{}:server:", std::process::id());
        let target = format!("{prefix}octo");
        let _written = Written(target.clone());
        let request = |request| handle(&CredentialManager, request);

        assert_eq!(
            request(Request::Write {
                target: target.clone(),
                username: "octo".into(),
                secret: b"t0ken".to_vec(),
            }),
            Ok(Reply::Done)
        );
        assert_eq!(
            request(Request::Read {
                target: target.clone()
            }),
            Ok(Reply::Secret(b"t0ken".to_vec()))
        );
        assert_eq!(
            request(Request::List { prefix }),
            Ok(Reply::Credentials(vec![Credential {
                target: target.clone(),
                username: "octo".into(),
            }]))
        );
        assert_eq!(
            request(Request::Delete {
                target: target.clone()
            }),
            Ok(Reply::Done)
        );
        assert_eq!(
            request(Request::Read {
                target: target.clone()
            }),
            Err(Failure::NotFound)
        );
        assert_eq!(request(Request::Delete { target }), Err(Failure::NotFound));
    }
}
