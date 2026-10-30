use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::{Credential, CredentialStore, Failure};

/// A [`CredentialStore`] that forgets everything when dropped, for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    credentials: Mutex<BTreeMap<String, (String, Vec<u8>)>>,
}

impl CredentialStore for MemoryStore {
    fn read(&self, target: &str) -> Result<Vec<u8>, Failure> {
        let credentials = self.credentials.lock().unwrap();
        let (_, secret) = credentials.get(target).ok_or(Failure::NotFound)?;
        Ok(secret.clone())
    }

    fn write(&self, target: &str, username: &str, secret: &[u8]) -> Result<(), Failure> {
        self.credentials
            .lock()
            .unwrap()
            .insert(target.to_owned(), (username.to_owned(), secret.to_vec()));
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<(), Failure> {
        let removed = self.credentials.lock().unwrap().remove(target);
        removed.map(drop).ok_or(Failure::NotFound)
    }

    fn list(&self, prefix: &str) -> Result<Vec<Credential>, Failure> {
        let credentials = self.credentials.lock().unwrap();
        Ok(credentials
            .iter()
            .filter(|(target, _)| target.starts_with(prefix))
            .map(|(target, (username, _))| Credential {
                target: target.clone(),
                username: username.clone(),
            })
            .collect())
    }
}
