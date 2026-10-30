use std::collections::HashMap;
use std::sync::Arc;

use zbus::object_server::ObjectServer;
use zbus::{Connection, OwnedObjectPath, OwnedVariant, interface};

use super::{Error, NO_PROMPT, Secret, State, item};
use crate::schemes::Attributes;

const ATTRIBUTES_PROPERTY: &str = "org.freedesktop.Secret.Item.Attributes";

pub struct Collection {
    state: Arc<State>,
}

impl Collection {
    pub(super) fn new(state: Arc<State>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    async fn delete(&self) -> Result<OwnedObjectPath, Error> {
        Err(Error::NotSupported(
            "the login collection can't be deleted".into(),
        ))
    }

    async fn search_items(
        &self,
        attributes: Attributes,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<Vec<OwnedObjectPath>, Error> {
        self.state.search(server, &attributes).await
    }

    /// Stores the secret under the attributes given, replacing an item with exactly those
    /// attributes whether or not `replace` asks for it: a credential holds one secret per target,
    /// so two items with the same attributes have nowhere to live side by side.
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedVariant>,
        secret: Secret,
        _replace: bool,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), Error> {
        let attributes = match properties.get(ATTRIBUTES_PROPERTY) {
            Some(value) => Attributes::try_from(value.try_clone()?)
                .map_err(|error| Error::InvalidArgs(error.to_string()))?,
            None => Attributes::new(),
        };
        let secret = self.state.secret_from(&secret)?;
        let stored = self.state.keyring.store(&attributes, &secret).await?;
        let path = self.state.export(server, stored).await?;
        Ok((path, OwnedObjectPath::try_from(NO_PROMPT)?))
    }

    /// zbus holds the object tree's read lock while a property getter runs, and exporting an
    /// object takes its write lock, so the items found are exported once the getter has returned.
    #[zbus(property)]
    async fn items(
        &self,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<Vec<OwnedObjectPath>, zbus::fdo::Error> {
        let found = self
            .state
            .keyring
            .search(&Attributes::new())
            .await
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        let paths = found
            .iter()
            .map(|found| item::path(&found.target))
            .collect();
        let state = self.state.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            for found in found {
                let _ = state.export(connection.object_server(), found).await;
            }
        });
        Ok(paths)
    }

    #[zbus(property)]
    fn label(&self) -> String {
        "Login".into()
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        false
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
