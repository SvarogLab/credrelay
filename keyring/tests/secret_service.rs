//! The Linux backend against credrelay's Secret Service on a private bus.
#![cfg(unix)]

use credrelay_client::{dbus, test_support};
use credrelay_keyring::backend::{Backend, Platform};

/// One test, since the backend finds the bus through `DBUS_SESSION_BUS_ADDRESS`, which belongs to
/// the whole process.
#[tokio::test]
async fn go_keyring_items_round_trip_through_the_secret_service() {
    let bus = test_support::Bus::start().await;
    let address = bus.address();
    let _service = dbus::serve(
        zbus::connection::Builder::address(address),
        test_support::keyring_with(&["age:"]),
    )
    .await
    .unwrap();
    // SAFETY: this test is the only one in its process, and nothing else reads the environment
    // while it changes.
    unsafe { std::env::set_var("DBUS_SESSION_BUS_ADDRESS", address) };

    let backend = Platform::connect().await.unwrap();
    assert_eq!(backend.get("age:default", "").await.unwrap(), None);
    backend
        .set("age:default", "", b"AGE-SECRET-KEY-1")
        .await
        .unwrap();
    backend
        .set("age:default", "", b"AGE-SECRET-KEY-2")
        .await
        .unwrap();
    assert_eq!(
        backend.get("age:default", "").await.unwrap(),
        Some(b"AGE-SECRET-KEY-2".to_vec())
    );
    assert!(backend.delete("age:default", "").await.unwrap());
    assert_eq!(backend.get("age:default", "").await.unwrap(), None);
    assert!(!backend.delete("age:default", "").await.unwrap());
}
