use std::collections::HashMap;
use std::sync::Arc;

use zbus::message::Header;
use zbus::object_server::ObjectServer;
use zbus::{OwnedObjectPath, OwnedVariant, Variant, interface};

use super::session::SessionObject;
use super::{Error, LOGIN_PATH, NO_PROMPT, Secret, Session, State, item};
use crate::encoding::{self, Encoding};
use crate::schemes::Attributes;

pub struct Service {
    state: Arc<State>,
}

impl Service {
    pub(super) fn new(state: Arc<State>) -> Self {
        Self { state }
    }
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(
        &self,
        algorithm: &str,
        input: OwnedVariant,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(OwnedVariant, OwnedObjectPath), Error> {
        let owner = header
            .sender()
            .map(|sender| sender.to_string())
            .ok_or_else(|| Error::InvalidArgs("a session needs a sender to belong to".into()))?;
        let input = match algorithm {
            encoding::PLAIN => Vec::new(),
            _ => {
                Vec::<u8>::try_from(input).map_err(|error| Error::InvalidArgs(error.to_string()))?
            }
        };
        let (encoding, output) = Encoding::negotiate(algorithm, &input)?;
        let output = match encoding {
            Encoding::Plain => OwnedVariant::try_from(Variant::from("")),
            Encoding::Aes(_) => OwnedVariant::try_from(Variant::from(output)),
        }?;
        let path = self.state.new_session_path();
        self.state.sessions().insert(
            path.clone(),
            Session {
                encoding: Arc::new(encoding),
                owner,
            },
        );
        server
            .at(&path, SessionObject::new(self.state.clone(), path.clone()))
            .await?;
        Ok((output, path))
    }

    async fn create_collection(
        &self,
        _properties: HashMap<String, OwnedVariant>,
        _alias: &str,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), Error> {
        Err(Error::NotSupported(
            "credrelay serves the login collection only".into(),
        ))
    }

    async fn search_items(
        &self,
        attributes: Attributes,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), Error> {
        Ok((self.state.search(server, &attributes).await?, Vec::new()))
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        (objects, no_prompt())
    }

    async fn lock(
        &self,
        _objects: Vec<OwnedObjectPath>,
    ) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        (Vec::new(), no_prompt())
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<HashMap<OwnedObjectPath, Secret>, Error> {
        let mut secrets = HashMap::new();
        for path in items {
            let found = item::exported(server, &path).await?;
            let secret = self.state.keyring.read(&found).await?;
            secrets.insert(path, self.state.secret_for(&session, &secret)?);
        }
        Ok(secrets)
    }

    async fn read_alias(&self, name: &str) -> OwnedObjectPath {
        match name {
            "default" | "login" => {
                OwnedObjectPath::try_from(LOGIN_PATH).expect("a valid object path")
            }
            _ => no_prompt(),
        }
    }

    async fn set_alias(&self, _name: &str, _collection: OwnedObjectPath) -> Result<(), Error> {
        Err(Error::NotSupported("aliases are fixed".into()))
    }

    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![OwnedObjectPath::try_from(LOGIN_PATH).expect("a valid object path")]
    }
}

/// `/`, which the specification uses both for "no prompt" and for "no such alias".
fn no_prompt() -> OwnedObjectPath {
    OwnedObjectPath::try_from(NO_PROMPT).expect("a valid object path")
}
