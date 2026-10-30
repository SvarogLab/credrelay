//! The `org.freedesktop.secrets` service: one collection, `login`, also reachable as the `default`
//! alias, whose items live in the Windows Credential Manager.
//!
//! Nothing here is ever locked and nothing asks for a prompt: every prompt path returned is `/`.

mod collection;
mod item;
mod service;
mod session;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use zbus::object_server::ObjectServer;
use zbus::{OwnedObjectPath, Type};

use crate::encoding::{Encoding, EncodingError};
use crate::keyring::{Item, Keyring, KeyringError};
use crate::schemes::Attributes;

pub const BUS_NAME: &str = "org.freedesktop.secrets";
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
pub const LOGIN_PATH: &str = "/org/freedesktop/secrets/collection/login";
pub const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const SESSION_PATH: &str = "/org/freedesktop/secrets/session";

/// The prompt path that says no prompt is needed.
const NO_PROMPT: &str = "/";

/// Serves `keyring` on the bus `builder` connects to, under the well-known name, which it fails
/// to take if another Secret Service already holds it.
pub async fn serve(
    builder: zbus::connection::Builder<'_>,
    keyring: Keyring,
) -> zbus::Result<zbus::Connection> {
    let state = Arc::new(State {
        keyring,
        sessions: Mutex::default(),
        next_session: AtomicU64::new(0),
    });
    builder
        .serve_at(SERVICE_PATH, service::Service::new(state.clone()))
        .serve_at(LOGIN_PATH, collection::Collection::new(state.clone()))
        .serve_at(DEFAULT_ALIAS_PATH, collection::Collection::new(state))
        // zbus would otherwise take the name from an instance already serving, and let the next
        // one take it from this.
        .replace_existing_names(false)
        .allow_name_replacements(false)
        .name(BUS_NAME)
        .build()
        .await
}

/// What every exported object shares.
struct State {
    keyring: Keyring,
    sessions: Mutex<HashMap<OwnedObjectPath, Arc<Encoding>>>,
    next_session: AtomicU64,
}

impl State {
    fn encoding(&self, session: &OwnedObjectPath) -> Result<Arc<Encoding>, Error> {
        self.sessions
            .lock()
            .unwrap()
            .get(session)
            .cloned()
            .ok_or_else(|| Error::NoSession(session.to_string()))
    }

    fn new_session_path(&self) -> OwnedObjectPath {
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        OwnedObjectPath::try_from(format!("{SESSION_PATH}/{id}")).expect("a valid object path")
    }

    /// Searches, and exports every item found so the caller can use the paths it gets.
    async fn search(
        self: &Arc<Self>,
        server: &ObjectServer,
        attributes: &Attributes,
    ) -> Result<Vec<OwnedObjectPath>, Error> {
        let mut paths = Vec::new();
        for found in self.keyring.search(attributes).await? {
            paths.push(self.export(server, found).await?);
        }
        Ok(paths)
    }

    async fn export(
        self: &Arc<Self>,
        server: &ObjectServer,
        found: Item,
    ) -> Result<OwnedObjectPath, Error> {
        let path = item::path(&found.target);
        // An item already exported under this path is the same credential, so the existing
        // object serves as well as the new one would.
        server
            .at(
                &path,
                item::ItemObject::new(self.clone(), found, path.clone()),
            )
            .await?;
        Ok(path)
    }

    /// Encodes `secret` for the session it is being sent in.
    fn secret_for(&self, session: &OwnedObjectPath, secret: &[u8]) -> Result<Secret, Error> {
        let (parameters, value) = self.encoding(session)?.encode(secret)?;
        Ok(Secret {
            session: session.clone(),
            parameters,
            value,
            content_type: "text/plain".into(),
        })
    }

    fn secret_from(&self, secret: &Secret) -> Result<Vec<u8>, Error> {
        Ok(self
            .encoding(&secret.session)?
            .decode(&secret.parameters, &secret.value)?)
    }
}

/// A secret as it crosses the bus, `(oayays)`.
#[derive(Debug, Serialize, Deserialize, Type)]
struct Secret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop")]
enum Error {
    #[zbus(error)]
    ZBus(zbus::Error),
    #[zbus(name = "Secret.Error.NoSession")]
    NoSession(String),
    #[zbus(name = "Secret.Error.NoSuchObject")]
    NoSuchObject(String),
    #[zbus(name = "DBus.Error.NotSupported")]
    NotSupported(String),
    #[zbus(name = "DBus.Error.AccessDenied")]
    AccessDenied(String),
    #[zbus(name = "DBus.Error.InvalidArgs")]
    InvalidArgs(String),
    #[zbus(name = "DBus.Error.Failed")]
    Failed(String),
}

impl From<KeyringError> for Error {
    fn from(error: KeyringError) -> Self {
        let message = error.to_string();
        match error {
            KeyringError::Unsupported => Self::NotSupported(message),
            KeyringError::NotAllowed(_) => Self::AccessDenied(message),
            KeyringError::NotFound => Self::NoSuchObject(message),
            KeyringError::Failed(_) => Self::Failed(message),
        }
    }
}

impl From<EncodingError> for Error {
    fn from(error: EncodingError) -> Self {
        let message = error.to_string();
        match error {
            EncodingError::Unsupported(_) => Self::NotSupported(message),
            EncodingError::Malformed(_) => Self::InvalidArgs(message),
            EncodingError::Random(_) => Self::Failed(message),
        }
    }
}

#[cfg(test)]
mod tests;
