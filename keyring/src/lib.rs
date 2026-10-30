//! go-keyring's convention from the command line, on Linux and on Windows alike: an item
//! `{service, username}` in the Secret Service, or the generic credential `service:username` in the
//! Credential Manager. A secret one side stores, the other reads.

pub mod backend;
pub mod bao;
pub mod cli;
pub mod kube;
