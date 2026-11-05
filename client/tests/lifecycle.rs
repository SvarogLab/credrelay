//! Runs the built client the way its systemd unit does, on a private bus, against a stand-in
//! server: this test binary itself, which the client starts as its server and which then answers
//! from memory over the same connection credrelay-server uses. Without libtest's harness, so that
//! `main` can tell the two roles apart.

use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use credrelay_protocol::{MemoryStore, answer};
use futures::{FutureExt, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio_util::compat::FuturesAsyncReadCompatExt;

const CLIENT: &str = env!("CARGO_BIN_EXE_credrelay-client");
const BUS_NAME: &str = "org.freedesktop.secrets";
/// Set in the client's environment, and so in its server's: how the stand-in server behaves.
const STAND_IN: &str = "CREDRELAY_TEST_STAND_IN";
const WITHIN: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() {
    match std::env::var(STAND_IN).as_deref() {
        Ok("answer") => serve_from_memory().await,
        Ok("exit") => {}
        _ => {
            run(
                "serves_until_told_to_stop_then_gives_up_the_name",
                serves_until_told_to_stop_then_gives_up_the_name,
            )
            .await;
            run(
                "a_server_that_cant_answer_keeps_it_off_the_bus",
                a_server_that_cant_answer_keeps_it_off_the_bus,
            )
            .await;
        }
    }
}

async fn run(name: &str, test: impl AsyncFnOnce()) {
    println!("test {name} ...");
    test().await;
    println!("test {name} ... ok");
}

async fn serve_from_memory() {
    let store = Arc::new(MemoryStore::default());
    let stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    let _ = librelay::server::mux::serve(stdio, move |stream| {
        let store = store.clone();
        async move {
            let mut stream = BufReader::new(stream.compat());
            let mut line = String::new();
            if stream.read_line(&mut line).await.is_ok()
                && let Ok(answer) = answer(&*store, &line)
            {
                let _ = stream.get_mut().write_all(answer.as_bytes()).await;
                let _ = stream.get_mut().shutdown().await;
            }
        }
    })
    .await;
}

/// The client is ready once it holds the name, and a stop signal makes it give the name up, stop
/// its server and exit successfully.
async fn serves_until_told_to_stop_then_gives_up_the_name() {
    let bus = Bus::start().await;
    let mut client = bus.client("answer");
    let watcher = bus.connect().await;
    bus.wait_for_owner(&watcher, true).await;

    signal(&client, "TERM").await;
    let status = exit_within(&mut client).await;
    assert!(status.success(), "{status:?}");
    bus.wait_for_owner(&watcher, false).await;
}

/// A client whose server can't answer would fail every application that called it, so it exits
/// without ever taking the name, not even for a moment.
async fn a_server_that_cant_answer_keeps_it_off_the_bus() {
    let bus = Bus::start().await;
    let watcher = bus.connect().await;
    let mut owners = zbus::fdo::DBusProxy::new(&watcher)
        .await
        .unwrap()
        .receive_name_owner_changed_with_args(&[(0, BUS_NAME)])
        .await
        .unwrap();
    let mut client = bus.client("exit");
    let status = exit_within(&mut client).await;
    assert!(!status.success(), "{status:?}");
    // The bus sends a signal before the reply to any later call, so once this reply is in, every
    // change of owner the client caused has arrived.
    assert!(!has_owner(&watcher).await);
    assert!(
        owners.next().now_or_never().is_none(),
        "{BUS_NAME} changed owner"
    );
}

struct Bus {
    _daemon: Child,
    address: String,
}

impl Bus {
    async fn start() -> Self {
        let mut daemon = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("dbus-daemon must be installed to run these tests");
        let mut address = String::new();
        BufReader::new(daemon.stdout.take().unwrap())
            .read_line(&mut address)
            .await
            .unwrap();
        Self {
            _daemon: daemon,
            address: address.trim().to_owned(),
        }
    }

    fn client(&self, stand_in: &str) -> Child {
        // Nothing of the test's own environment, such as a log filter or a systemd notify socket.
        Command::new(CLIENT)
            .arg("--server-exe")
            .arg(std::env::current_exe().unwrap())
            .env_clear()
            .env("DBUS_SESSION_BUS_ADDRESS", &self.address)
            .env(STAND_IN, stand_in)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    async fn connect(&self) -> zbus::Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .build()
            .await
            .unwrap()
    }

    async fn wait_for_owner(&self, connection: &zbus::Connection, owned: bool) {
        tokio::time::timeout(WITHIN, async {
            while has_owner(connection).await != owned {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{BUS_NAME} owned should be {owned} within {WITHIN:?}"));
    }
}

async fn has_owner(connection: &zbus::Connection) -> bool {
    let bus = zbus::fdo::DBusProxy::new(connection).await.unwrap();
    bus.name_has_owner(BUS_NAME.try_into().unwrap())
        .await
        .unwrap()
}

async fn signal(child: &Child, name: &str) {
    let sent = Command::new("kill")
        .arg(format!("-{name}"))
        .arg(child.id().unwrap().to_string())
        .status()
        .await
        .unwrap();
    assert!(sent.success());
}

async fn exit_within(child: &mut Child) -> ExitStatus {
    tokio::time::timeout(WITHIN, child.wait())
        .await
        .unwrap_or_else(|_| panic!("the client didn't exit within {WITHIN:?}"))
        .unwrap()
}
