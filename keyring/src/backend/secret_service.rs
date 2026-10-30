use std::collections::HashMap;

use oo7::dbus::{Collection, Service};

use super::{Backend, BackendError};

/// The Secret Service on the session bus: whichever one runs there, credrelay or another.
pub struct SecretService {
    collection: Collection,
}

impl SecretService {
    /// Connects to the default collection, unlocking it if the service keeps it locked.
    pub async fn connect() -> Result<Self, BackendError> {
        let service = Service::new().await.map_err(failed)?;
        let collection = service.default_collection().await.map_err(failed)?;
        if collection.is_locked().await.map_err(failed)? {
            collection.unlock(None).await.map_err(failed)?;
        }
        Ok(Self { collection })
    }
}

fn attributes<'a>(service: &'a str, username: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([("service", service), ("username", username)])
}

fn failed(error: oo7::dbus::Error) -> BackendError {
    BackendError(error.to_string())
}

impl Backend for SecretService {
    async fn get(&self, service: &str, username: &str) -> Result<Option<Vec<u8>>, BackendError> {
        let found = self
            .collection
            .search_items(&attributes(service, username))
            .await
            .map_err(failed)?;
        let Some(item) = found.first() else {
            return Ok(None);
        };
        if item.is_locked().await.map_err(failed)? {
            item.unlock(None).await.map_err(failed)?;
        }
        let secret = item.secret().await.map_err(failed)?;
        Ok(Some(secret.as_bytes().to_vec()))
    }

    async fn set(&self, service: &str, username: &str, secret: &[u8]) -> Result<(), BackendError> {
        // go-keyring's label, so an item reads the same whichever of them stored it.
        let label = format!("Password for '{username}' on '{service}'");
        self.collection
            .create_item(
                &label,
                &attributes(service, username),
                oo7::Secret::blob(secret),
                true,
                None,
            )
            .await
            .map_err(failed)?;
        Ok(())
    }

    async fn delete(&self, service: &str, username: &str) -> Result<bool, BackendError> {
        let found = self
            .collection
            .search_items(&attributes(service, username))
            .await
            .map_err(failed)?;
        for item in &found {
            item.delete(None).await.map_err(failed)?;
        }
        Ok(!found.is_empty())
    }
}
