use std::fmt::Write;
use std::sync::Arc;

use zbus::object_server::ObjectServer;
use zbus::{Connection, OwnedObjectPath, interface};

use super::{Error, LOGIN_PATH, NO_PROMPT, Secret, State, unexport};
use crate::keyring::Item;
use crate::schemes::Attributes;

pub struct ItemObject {
    state: Arc<State>,
    item: Item,
    path: OwnedObjectPath,
}

impl ItemObject {
    pub(super) fn new(state: Arc<State>, item: Item, path: OwnedObjectPath) -> Self {
        Self { state, item, path }
    }
}

/// The path of the item stored in `target`. An object path allows only `[A-Za-z0-9_]` in an
/// element, so every other byte, and `_` itself, is written as `_` and two hex digits, which keeps
/// distinct targets on distinct paths.
pub fn path(target: &str) -> OwnedObjectPath {
    let mut path = format!("{LOGIN_PATH}/");
    for byte in target.bytes() {
        if byte.is_ascii_alphanumeric() {
            path.push(char::from(byte));
        } else {
            write!(path, "_{byte:02x}").expect("writing to a String can't fail");
        }
    }
    OwnedObjectPath::try_from(path).expect("only path-safe characters are written")
}

/// The item exported at `path`, if any.
pub(super) async fn exported(server: &ObjectServer, path: &OwnedObjectPath) -> Result<Item, Error> {
    let object = server
        .interface::<_, ItemObject>(path)
        .await
        .map_err(|_| Error::NoSuchObject(path.to_string()))?;
    Ok(object.get().await.item.clone())
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemObject {
    async fn delete(
        &self,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<OwnedObjectPath, Error> {
        self.state.keyring.delete(&self.item).await?;
        unexport::<Self>(connection, self.path.clone());
        Ok(OwnedObjectPath::try_from(NO_PROMPT)?)
    }

    /// Returned in a one-element tuple, as zbus otherwise sends a struct's fields as separate
    /// arguments, where the specification has a single `(oayays)`.
    async fn get_secret(&self, session: OwnedObjectPath) -> Result<(Secret,), Error> {
        let secret = self.state.keyring.read(&self.item).await?;
        Ok((self.state.secret_for(&session, &secret)?,))
    }

    async fn set_secret(&self, secret: Secret) -> Result<(), Error> {
        let secret = self.state.secret_from(&secret)?;
        self.state
            .keyring
            .store(&self.item.attributes, &secret)
            .await?;
        Ok(())
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn attributes(&self) -> Attributes {
        self.item.attributes.clone()
    }

    /// Labels aren't kept, so an item is labelled by where it is stored.
    #[zbus(property)]
    fn label(&self) -> String {
        self.item.target.clone()
    }

    #[zbus(property)]
    fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    fn modified(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_targets_get_distinct_valid_paths() {
        let targets = ["gh:github.com:", "gh:github.com:octo", "gh_3a", "gh:"];
        let paths: std::collections::BTreeSet<_> = targets
            .iter()
            .map(|target| path(target).to_string())
            .collect();
        assert_eq!(paths.len(), targets.len());
        assert_eq!(
            path("gh:github.com:").as_str(),
            "/org/freedesktop/secrets/collection/login/gh_3agithub_2ecom_3a"
        );
    }
}
