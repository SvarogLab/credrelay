use std::collections::HashMap;
use std::sync::Mutex;

use super::{Backend, BackendError};

#[derive(Default)]
pub struct Memory {
    secrets: Mutex<HashMap<(String, String), Vec<u8>>>,
}

impl Backend for Memory {
    async fn get(&self, service: &str, username: &str) -> Result<Option<Vec<u8>>, BackendError> {
        let key = (service.to_owned(), username.to_owned());
        Ok(self.secrets.lock().unwrap().get(&key).cloned())
    }

    async fn set(&self, service: &str, username: &str, secret: &[u8]) -> Result<(), BackendError> {
        let key = (service.to_owned(), username.to_owned());
        self.secrets.lock().unwrap().insert(key, secret.to_vec());
        Ok(())
    }

    async fn delete(&self, service: &str, username: &str) -> Result<bool, BackendError> {
        let key = (service.to_owned(), username.to_owned());
        Ok(self.secrets.lock().unwrap().remove(&key).is_some())
    }
}
