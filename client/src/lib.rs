//! The WSL side of credrelay: the Secret Service, and the link to credrelay-server it keeps items
//! through. A library as well as the binary so other crates can test against the real service.

pub mod config;
pub mod dbus;
mod encoding;
mod keyring;
mod rpc;
mod run;
mod schemes;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use keyring::Keyring;
pub use run::{RunError, run};

/// What the fuzz targets in `fuzz/` drive, which nothing else outside the crate needs.
#[cfg(fuzzing)]
pub mod fuzzing {
    pub use crate::encoding::{DH_AES, Encoding, EncodingError};
    pub use crate::schemes::{Attributes, NATIVE_PREFIX, Native, Scheme};
}
