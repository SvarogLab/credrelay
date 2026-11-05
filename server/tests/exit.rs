//! The built server's exit status, which is all the client learns of how its connection ended.

use std::io::Write;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const SERVER: &str = env!("CARGO_BIN_EXE_credrelay-server");
/// A server that never exits fails the test instead of hanging it.
const WITHIN: Duration = Duration::from_secs(10);

fn exit_after_sending(input: &[u8]) -> ExitStatus {
    let mut server = Command::new(SERVER)
        .args(["--log-filter", "off"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    server.stdin.take().unwrap().write_all(input).unwrap();
    let deadline = Instant::now() + WITHIN;
    loop {
        if let Some(status) = server.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = server.kill();
            panic!("the server didn't exit within {WITHIN:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The client reports a server that exits otherwise as having failed.
#[cfg(windows)]
#[test]
fn a_client_that_closes_the_connection_leaves_the_server_exiting_successfully() {
    let status = exit_after_sending(b"");
    assert!(status.success(), "{status:?}");
}

#[cfg(windows)]
#[test]
fn a_connection_that_breaks_ends_the_server_with_a_failure() {
    let status = exit_after_sending(b"not a yamux frame\n");
    assert_eq!(status.code(), Some(1), "{status:?}");
}

/// Started anywhere but Windows, where there is no Credential Manager, it says so and fails.
#[cfg(not(windows))]
#[test]
fn off_windows_the_server_fails_at_once() {
    let status = exit_after_sending(b"");
    assert!(!status.success(), "{status:?}");
}
