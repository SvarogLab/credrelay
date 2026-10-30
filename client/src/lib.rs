//! The WSL side of credrelay: the Secret Service, and the link to credrelay-server it keeps items
//! through. A library as well as the binary so other crates can test against the real service.

pub mod config;
pub mod dbus;
pub mod keyring;
pub mod prefixes;
pub mod rpc;
pub mod schemes;
mod session;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
