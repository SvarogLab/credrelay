//! The built binaries against credrelay's Secret Service on a private bus, run the way gh, kubectl
//! and bao run them: arguments and environment in, the secret on stdin or stdout, the outcome in
//! the exit status.
#![cfg(unix)]

use std::process::{Output, Stdio};

use credrelay_client::{dbus, test_support};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const KEYRING: &str = env!("CARGO_BIN_EXE_credrelay-keyring");
const BAO_HELPER: &str = env!("CARGO_BIN_EXE_credrelay-bao-helper");

/// A private bus with credrelay serving on it, until dropped.
struct Service {
    bus: test_support::Bus,
    _serving: dbus::Serving,
}

impl Service {
    async fn start() -> Self {
        let bus = test_support::Bus::start().await;
        let serving = dbus::serve(
            zbus::connection::Builder::address(bus.address()),
            test_support::keyring_with(&["age:", "bao:"]),
        )
        .await
        .unwrap();
        Self {
            bus,
            _serving: serving,
        }
    }

    /// Nothing of the test's own environment reaches the program but the bus address: a log
    /// filter or a bus variable of whoever runs the tests would change what it does.
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
        stdin: &[u8],
    ) -> Output {
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .env("DBUS_SESSION_BUS_ADDRESS", self.bus.address())
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(stdin).await.unwrap();
        drop(input);
        child.wait_with_output().await.unwrap()
    }

    async fn keyring(&self, args: &[&str], stdin: &[u8]) -> Output {
        self.run(KEYRING, args, &[], stdin).await
    }

    async fn bao(&self, operation: &str, address: &str, stdin: &[u8]) -> Output {
        self.run(BAO_HELPER, &[operation], &[("BAO_ADDR", address)], stdin)
            .await
    }
}

fn succeeded_with(output: &Output, stdout: &[u8]) {
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, stdout, "{output:?}");
}

fn failed_with(output: &Output, stderr_start: &str) {
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with(stderr_start), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn each_service_keeps_its_own_secret_exactly_as_stored() {
    let service = Service::start().await;
    succeeded_with(
        &service.keyring(&["set", "age:default"], b"KEY-1\n").await,
        b"",
    );
    succeeded_with(&service.keyring(&["set", "age:other"], b"KEY-2").await, b"");
    succeeded_with(&service.keyring(&["set", "age:other"], b"KEY-3").await, b"");

    succeeded_with(
        &service.keyring(&["get", "age:default"], b"").await,
        b"KEY-1\n",
    );
    succeeded_with(&service.keyring(&["get", "age:other"], b"").await, b"KEY-3");

    succeeded_with(&service.keyring(&["delete", "age:default"], b"").await, b"");
    failed_with(
        &service.keyring(&["get", "age:default"], b"").await,
        "credrelay-keyring: no secret",
    );
    failed_with(
        &service.keyring(&["delete", "age:default"], b"").await,
        "credrelay-keyring: no secret",
    );
    succeeded_with(&service.keyring(&["get", "age:other"], b"").await, b"KEY-3");
}

#[tokio::test(flavor = "multi_thread")]
async fn bao_gets_the_token_it_stored_for_that_server_only() {
    let service = Service::start().await;
    let server = "https://bao.example.com:8200";
    let other = "https://bao.example.net:8200";
    succeeded_with(&service.bao("store", server, b"s.token\n").await, b"");
    succeeded_with(&service.bao("get", server, b"").await, b"s.token");
    succeeded_with(&service.bao("get", other, b"").await, b"");

    succeeded_with(&service.bao("erase", server, b"").await, b"");
    succeeded_with(&service.bao("get", server, b"").await, b"");
    failed_with(
        &service.bao("renew", server, b"").await,
        "credrelay-bao-helper: unknown operation",
    );
}
