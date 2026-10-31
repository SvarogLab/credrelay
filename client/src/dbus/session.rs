use std::sync::Arc;

use zbus::{Connection, OwnedObjectPath, interface};

use super::{State, unexport};

pub struct SessionObject {
    state: Arc<State>,
    path: OwnedObjectPath,
}

impl SessionObject {
    pub(super) fn new(state: Arc<State>, path: OwnedObjectPath) -> Self {
        Self { state, path }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionObject {
    fn close(&self, #[zbus(connection)] connection: &Connection) {
        self.state.sessions().remove(&self.path);
        unexport::<Self>(connection, self.path.clone());
    }
}
