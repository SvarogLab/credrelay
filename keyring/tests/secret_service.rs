//! The Linux backend against credrelay's Secret Service on a private bus.
#![cfg(unix)]

use std::process::Stdio;

use credrelay_client::{dbus, test_support};
use credrelay_keyring::backend::{Backend, Platform};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// One test, since the backend finds the bus through `DBUS_SESSION_BUS_ADDRESS`, which belongs to
/// the whole process.
#[tokio::test]
async fn go_keyring_items_round_trip_through_the_secret_service() {
    let mut daemon = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("dbus-daemon must be installed to run this test");
    let mut address = String::new();
    BufReader::new(daemon.stdout.take().unwrap())
        .read_line(&mut address)
        .await
        .unwrap();
    let address = address.trim();
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
