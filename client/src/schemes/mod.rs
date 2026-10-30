//! How the attributes of a Secret Service item map onto a Windows credential. Each scheme other
//! than the last is the convention one credential library follows on both systems, so the Windows
//! build of an application finds what its Linux build stored, and the other way round; the last,
//! [`Native`], keeps whatever none of them claims.

mod go_keyring;
mod native;

use std::collections::BTreeMap;

use credrelay_protocol::Credential;

pub use go_keyring::GoKeyring;
pub use native::Native;

use crate::prefixes::Prefixes;

pub type Attributes = BTreeMap<String, String>;

pub trait Scheme: Send + Sync {
    /// The target prefixes this scheme stores under, and the only ones it may touch.
    fn prefixes(&self) -> &Prefixes;

    /// The credential an item with exactly these attributes is stored as, if this scheme claims
    /// it. The target is always under [`Scheme::prefixes`].
    fn credential(&self, attributes: &Attributes) -> Option<Credential>;

    /// A target prefix every credential matching a search for `attributes` starts with, to list
    /// instead of all of [`Scheme::prefixes`].
    fn search_prefix(&self, attributes: &Attributes) -> Option<String>;

    /// The attributes of a listed credential, if this scheme could have stored it.
    fn attributes(&self, credential: &Credential) -> Option<Attributes>;
}

/// Every scheme in the order they are tried, with go-keyring claiming the services under
/// `go_keyring_prefixes`.
pub fn all(go_keyring_prefixes: Prefixes) -> Vec<Box<dyn Scheme>> {
    vec![
        Box::new(GoKeyring::new(go_keyring_prefixes)),
        Box::new(Native::new()),
    ]
}
