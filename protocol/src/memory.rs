use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use crate::{Credential, CredentialStore, Failure};

/// A [`CredentialStore`] that forgets everything when dropped, for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    credentials: Mutex<Credentials>,
}

type Credentials = BTreeMap<String, (String, Vec<u8>)>;

impl MemoryStore {
    fn credentials(&self) -> MutexGuard<'_, Credentials> {
        self.credentials
            .lock()
            .expect("no code holding the credentials panics")
    }
}

impl CredentialStore for MemoryStore {
    fn read(&self, target: &str) -> Result<Vec<u8>, Failure> {
        self.credentials()
            .get(target)
            .map(|(_, secret)| secret.clone())
            .ok_or(Failure::NotFound)
    }

    fn write(&self, target: &str, username: &str, secret: &[u8]) -> Result<(), Failure> {
        self.credentials()
            .insert(target.to_owned(), (username.to_owned(), secret.to_vec()));
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<(), Failure> {
        let removed = self.credentials().remove(target);
        removed.map(drop).ok_or(Failure::NotFound)
    }

    fn list(&self, prefix: &str) -> Result<Vec<Credential>, Failure> {
        Ok(self
            .credentials()
            .iter()
            .filter(|(target, _)| target.starts_with(prefix))
            .map(|(target, (username, _))| Credential {
                target: target.clone(),
                username: username.clone(),
            })
            .collect())
    }
}
