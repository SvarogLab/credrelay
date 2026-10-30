use std::sync::Arc;

use zbus::{Connection, OwnedObjectPath, interface};

use super::State;

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
    async fn close(&self, #[zbus(connection)] connection: &Connection) {
        self.state.sessions.lock().unwrap().remove(&self.path);
        // Removed once this method has returned, as an item is; see `item::unexport`.
        let connection = connection.clone();
        let path = self.path.clone();
        tokio::spawn(async move {
            let _ = connection
                .object_server()
                .remove::<SessionObject, _>(&path)
                .await;
        });
    }
}
