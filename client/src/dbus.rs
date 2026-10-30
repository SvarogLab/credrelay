//! The `org.freedesktop.secrets` service: one collection, `login`, also reachable as the `default`
//! alias, whose items live in the Windows Credential Manager.
//!
//! Nothing here is ever locked and nothing asks for a prompt: every prompt path returned is `/`.

mod collection;
mod item;
mod service;
mod session;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use futures::StreamExt;

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
) -> zbus::Result<Serving> {
    let state = Arc::new(State {
        keyring,
        sessions: Mutex::default(),
        next_session: AtomicU64::new(0),
        exported: Mutex::default(),
    });
    let connection = builder
        .serve_at(SERVICE_PATH, service::Service::new(state.clone()))
        .serve_at(LOGIN_PATH, collection::Collection::new(state.clone()))
        .serve_at(
            DEFAULT_ALIAS_PATH,
            collection::Collection::new(state.clone()),
        )
        .build()
        .await?;
    let departures = zbus::fdo::DBusProxy::new(&connection)
        .await?
        .receive_name_owner_changed()
        .await?;
    let watcher = tokio::spawn(close_sessions_of_departed(
        departures,
        state.clone(),
        connection.clone(),
    ));
    // `Items` lists only exported items, so what the store already holds is exported before any
    // client can ask.
    if let Err(error) = state
        .search(connection.object_server(), &Attributes::new())
        .await
    {
        tracing::warn!(%error, "can't export the items already stored");
    }
    // Neither replacing an instance already serving nor letting the next one replace this.
    connection
        .request_name_with_flags(BUS_NAME, zbus::fdo::RequestNameFlags::DO_NOT_QUEUE)
        .await?;
    Ok(Serving {
        connection,
        watcher,
    })
}

/// The service on the bus, until [`Serving::stop`].
pub struct Serving {
    connection: zbus::Connection,
    watcher: tokio::task::JoinHandle<()>,
}

impl Serving {
    /// Gives up the bus name, so no new calls arrive, and returns once the calls in flight are
    /// answered. Everything the service held, the link to the server included, is released then.
    pub async fn stop(self) {
        let _ = self.connection.release_name(BUS_NAME).await;
        // The watcher holds a copy of the connection, which shutting down waits for.
        self.watcher.abort();
        let _ = self.watcher.await;
        self.connection.graceful_shutdown().await;
    }
}

/// Closes the sessions of every client that leaves the bus: a client needn't close its sessions,
/// and one that doesn't would otherwise leave them open for as long as the service runs.
async fn close_sessions_of_departed(
    mut departures: zbus::fdo::NameOwnerChangedStream,
    state: Arc<State>,
    connection: zbus::Connection,
) {
    while let Some(change) = departures.next().await {
        let Ok(args) = change.args() else { continue };
        if args.new_owner().is_some() || !args.name().starts_with(':') {
            continue;
        }
        let departed = args.name().to_string();
        let closed: Vec<OwnedObjectPath> = {
            let mut sessions = state.sessions();
            let closed = sessions
                .iter()
                .filter(|(_, session)| session.owner == departed)
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>();
            for path in &closed {
                sessions.remove(path);
            }
            closed
        };
        for path in closed {
            unexport::<session::SessionObject>(&connection, path);
        }
    }
}

/// A session: how secrets cross the bus in it, and the client that opened it.
struct Session {
    encoding: Arc<Encoding>,
    owner: String,
}

/// What every exported object shares.
struct State {
    keyring: Keyring,
    sessions: Mutex<HashMap<OwnedObjectPath, Session>>,
    next_session: AtomicU64,
    /// The paths of the items exported, which a property getter can't learn from the object
    /// server: the getter already holds the object tree's lock.
    exported: Mutex<HashSet<OwnedObjectPath>>,
}

impl State {
    fn sessions(&self) -> MutexGuard<'_, HashMap<OwnedObjectPath, Session>> {
        self.sessions
            .lock()
            .expect("no code holding the sessions panics")
    }

    fn exported(&self) -> MutexGuard<'_, HashSet<OwnedObjectPath>> {
        self.exported
            .lock()
            .expect("no code holding the exported items panics")
    }

    fn encoding(&self, session: &OwnedObjectPath) -> Result<Arc<Encoding>, Error> {
        self.sessions()
            .get(session)
            .map(|session| session.encoding.clone())
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
        self.exported().insert(path.clone());
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

/// Removes the object at `path` once the method running on it has returned, since the object
/// server can't drop an interface while one of its methods still holds it.
fn unexport<I: zbus::object_server::Interface>(
    connection: &zbus::Connection,
    path: OwnedObjectPath,
) {
    let connection = connection.clone();
    tokio::spawn(async move {
        let _ = connection.object_server().remove::<I, _>(&path).await;
    });
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
            EncodingError::PublicKeyOutOfRange
            | EncodingError::IvLength(_)
            | EncodingError::Undecryptable(_) => Self::InvalidArgs(message),
            EncodingError::Random(_) => Self::Failed(message),
        }
    }
}

#[cfg(test)]
mod tests;
