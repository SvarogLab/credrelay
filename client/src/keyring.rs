//! Items as the Secret Service sees them, kept as credentials on the Windows side.

use std::collections::BTreeMap;

use crate::rpc::{Rpc, RpcError};
use crate::schemes::{Attributes, Scheme};

/// An item: the credential it lives in, and the attributes it answers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub target: String,
    pub attributes: Attributes,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error("no scheme stores an item with these attributes")]
    Unsupported,
    #[error("credential {0:?} belongs to no scheme")]
    NotAllowed(String),
    #[error("no such item")]
    NotFound,
    #[error(transparent)]
    Failed(RpcError),
}

impl From<RpcError> for KeyringError {
    fn from(error: RpcError) -> Self {
        match error {
            RpcError::NotFound => Self::NotFound,
            other => Self::Failed(other),
        }
    }
}

pub struct Keyring {
    rpc: Rpc,
    schemes: Vec<Box<dyn Scheme>>,
}

impl Keyring {
    pub fn new(rpc: Rpc, schemes: Vec<Box<dyn Scheme>>) -> Self {
        Self { rpc, schemes }
    }

    /// Every item whose attributes include all of `attributes`.
    pub async fn search(&self, attributes: &Attributes) -> Result<Vec<Item>, KeyringError> {
        let mut found = BTreeMap::new();
        for scheme in &self.schemes {
            for prefix in prefixes_to_list(scheme.as_ref(), attributes) {
                for credential in self.rpc.list(&prefix).await? {
                    let Some(item_attributes) = scheme.attributes(&credential) else {
                        continue;
                    };
                    let matches = attributes
                        .iter()
                        .all(|(key, value)| item_attributes.get(key) == Some(value));
                    if matches {
                        found.entry(credential.target).or_insert(item_attributes);
                    }
                }
            }
        }
        Ok(found
            .into_iter()
            .map(|(target, attributes)| Item { target, attributes })
            .collect())
    }

    /// Stores `secret` in the item with exactly `attributes`, replacing what it held.
    pub async fn store(
        &self,
        attributes: &Attributes,
        secret: &[u8],
    ) -> Result<Item, KeyringError> {
        let credential = self
            .schemes
            .iter()
            .find_map(|scheme| scheme.credential(attributes))
            .ok_or(KeyringError::Unsupported)?;
        self.check(&credential.target)?;
        self.rpc
            .write(&credential.target, &credential.username, secret)
            .await?;
        Ok(Item {
            target: credential.target,
            attributes: attributes.clone(),
        })
    }

    pub async fn read(&self, item: &Item) -> Result<Vec<u8>, KeyringError> {
        self.check(&item.target)?;
        Ok(self.rpc.read(&item.target).await?)
    }

    pub async fn delete(&self, item: &Item) -> Result<(), KeyringError> {
        self.check(&item.target)?;
        Ok(self.rpc.delete(&item.target).await?)
    }

    fn check(&self, target: &str) -> Result<(), KeyringError> {
        if self
            .schemes
            .iter()
            .any(|scheme| scheme.prefixes().covers(target))
        {
            Ok(())
        } else {
            Err(KeyringError::NotAllowed(target.to_owned()))
        }
    }
}

/// What to list to find a scheme's items matching a search: the scheme's own search prefix if it
/// lies inside the scheme's prefixes, the scheme's prefixes inside it otherwise.
fn prefixes_to_list(scheme: &dyn Scheme, attributes: &Attributes) -> Vec<String> {
    let own = scheme.prefixes();
    match scheme.search_prefix(attributes) {
        Some(prefix) if own.covers(&prefix) => vec![prefix],
        Some(prefix) => own
            .as_slice()
            .iter()
            .filter(|own| own.starts_with(&prefix))
            .cloned()
            .collect(),
        None => own.as_slice().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{attributes, keyring};

    fn gh(username: &str) -> Attributes {
        attributes(&[("service", "gh:github.com"), ("username", username)])
    }

    #[tokio::test]
    async fn a_stored_item_is_found_by_its_attributes_and_reads_back() {
        let keyring = keyring();
        let stored = keyring.store(&gh("octo"), b"t0ken").await.unwrap();
        assert_eq!(stored.target, "gh:github.com:octo");
        assert_eq!(
            keyring.search(&gh("octo")).await.unwrap(),
            vec![stored.clone()]
        );
        assert_eq!(keyring.read(&stored).await.unwrap(), b"t0ken");
    }

    #[tokio::test]
    async fn storing_again_replaces_the_secret() {
        let keyring = keyring();
        keyring.store(&gh("octo"), b"old").await.unwrap();
        let stored = keyring.store(&gh("octo"), b"new").await.unwrap();
        assert_eq!(keyring.read(&stored).await.unwrap(), b"new");
        assert_eq!(keyring.search(&gh("octo")).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_search_matches_items_with_more_attributes_than_it_names() {
        let keyring = keyring();
        keyring.store(&gh(""), b"a").await.unwrap();
        keyring.store(&gh("octo"), b"b").await.unwrap();
        keyring
            .store(
                &attributes(&[("service", "gh:example.com"), ("username", "")]),
                b"c",
            )
            .await
            .unwrap();

        let by_service = keyring
            .search(&attributes(&[("service", "gh:github.com")]))
            .await
            .unwrap();
        let mut targets: Vec<_> = by_service.iter().map(|item| item.target.as_str()).collect();
        targets.sort();
        assert_eq!(targets, ["gh:github.com:", "gh:github.com:octo"]);

        assert_eq!(keyring.search(&Attributes::new()).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_search_by_a_service_prefix_matches_nothing() {
        let keyring = keyring();
        keyring.store(&gh(""), b"a").await.unwrap();
        let found = keyring
            .search(&attributes(&[("service", "gh")]))
            .await
            .unwrap();
        assert!(found.is_empty(), "{found:?}");
    }

    #[tokio::test]
    async fn a_missing_item_is_found_nowhere() {
        let keyring = keyring();
        assert!(keyring.search(&gh("octo")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_deleted_item_is_gone() {
        let keyring = keyring();
        let stored = keyring.store(&gh("octo"), b"t0ken").await.unwrap();
        keyring.delete(&stored).await.unwrap();
        assert!(keyring.search(&gh("octo")).await.unwrap().is_empty());
        assert!(matches!(
            keyring.delete(&stored).await,
            Err(KeyringError::NotFound)
        ));
    }

    #[tokio::test]
    async fn an_item_no_application_scheme_claims_is_kept_under_credrelays_own_names() {
        let keyring = keyring();
        let other = attributes(&[("service", "git"), ("username", "https://github.com")]);
        let stored = keyring.store(&other, b"t0ken").await.unwrap();
        assert!(stored.target.starts_with("credrelay:"), "{stored:?}");
        assert_eq!(keyring.search(&other).await.unwrap(), vec![stored.clone()]);
        assert_eq!(keyring.read(&stored).await.unwrap(), b"t0ken");

        let by_url = attributes(&[("url", "https://index.crates.io/")]);
        keyring.store(&by_url, b"other").await.unwrap();
        assert_eq!(keyring.search(&Attributes::new()).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_credential_no_scheme_owns_is_never_touched() {
        let keyring = keyring();
        let item = Item {
            target: "git:https://github.com".into(),
            attributes: attributes(&[("service", "git"), ("username", "https://github.com")]),
        };
        assert!(matches!(
            keyring.read(&item).await,
            Err(KeyringError::NotAllowed(_))
        ));
        assert!(matches!(
            keyring.delete(&item).await,
            Err(KeyringError::NotAllowed(_))
        ));
    }
}
