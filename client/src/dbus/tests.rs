//! The service on a private bus of its own, driven the way its clients drive it.

use std::collections::HashMap;
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use zbus::{Connection, OwnedObjectPath, OwnedVariant, Variant};

use super::*;
use crate::keyring::tests::keyring;

/// A secret as clients read it: one `(oayays)` argument, not four.
type WireSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const SESSION: &str = "org.freedesktop.Secret.Session";

/// A `dbus-daemon` with a session bus configuration, gone when dropped.
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

    async fn connect(&self) -> Connection {
        zbus::connection::Builder::address(self.address.as_str())
            .build()
            .await
            .unwrap()
    }
}

/// A served keyring and a client connection to it.
struct Fixture {
    bus: Bus,
    _service: Connection,
    client: Connection,
}

impl Fixture {
    async fn start() -> Self {
        let bus = Bus::start().await;
        let service = serve(
            zbus::connection::Builder::address(bus.address.as_str()),
            keyring(),
        )
        .await
        .unwrap();
        let client = bus.connect().await;
        Self {
            bus,
            _service: service,
            client,
        }
    }

    async fn call<B, R>(
        &self,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
    ) -> zbus::Result<R>
    where
        B: serde::Serialize + zbus::Type,
        R: for<'d> serde::Deserialize<'d> + zbus::Type,
    {
        // A handler that panics never replies, which would hang the test rather than fail it.
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.client
                .call_method(Some(BUS_NAME), path, Some(interface), method, body),
        )
        .await
        .unwrap_or_else(|_| panic!("{interface}.{method} on {path} never replied"))?;
        reply.body().deserialize()
    }

    /// The signature of a reply as `busctl` prints it. zbus can't be asked: it reports the same
    /// signature for a struct as for the struct's fields sent as separate arguments, while the
    /// clients built on other D-Bus libraries tell them apart.
    async fn reply_signature(
        &self,
        path: &str,
        interface: &str,
        method: &str,
        args: &[&str],
    ) -> String {
        let output = Command::new("busctl")
            .arg(format!("--address={}", self.bus.address))
            .args(["call", BUS_NAME, path, interface, method])
            .args(args)
            .output()
            .await
            .expect("busctl must be installed to run these tests");
        assert!(output.status.success(), "{output:?}");
        let printed = String::from_utf8(output.stdout).unwrap();
        printed
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    async fn property<R>(&self, path: &str, interface: &str, name: &str) -> R
    where
        R: TryFrom<OwnedVariant>,
        R::Error: std::fmt::Debug,
    {
        let value: OwnedVariant = self
            .call(
                path,
                "org.freedesktop.DBus.Properties",
                "Get",
                &(interface, name),
            )
            .await
            .unwrap();
        R::try_from(value).unwrap()
    }

    async fn open_plain_session(&self) -> OwnedObjectPath {
        let (_, session): (OwnedVariant, OwnedObjectPath) = self
            .call(
                SERVICE_PATH,
                SERVICE,
                "OpenSession",
                &("plain", Variant::from("")),
            )
            .await
            .unwrap();
        session
    }

    async fn unlock(&self, path: &str) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        let objects = vec![OwnedObjectPath::try_from(path).unwrap()];
        self.call(SERVICE_PATH, SERVICE, "Unlock", &(objects,))
            .await
            .unwrap()
    }

    /// `go-keyring`'s `Set`.
    async fn set(
        &self,
        service: &str,
        user: &str,
        password: &str,
    ) -> zbus::Result<OwnedObjectPath> {
        let session = self.open_plain_session().await;
        let collections: Vec<OwnedObjectPath> =
            self.property(SERVICE_PATH, SERVICE, "Collections").await;
        assert!(collections.iter().any(|path| path.as_str() == LOGIN_PATH));
        assert_eq!(self.unlock(LOGIN_PATH).await.0[0].as_str(), LOGIN_PATH);

        let attributes = HashMap::from([("username", user), ("service", service)]);
        let label = format!("Password for '{user}' on '{service}'");
        let properties = HashMap::from([
            (
                "org.freedesktop.Secret.Item.Label",
                Variant::from(label.as_str()),
            ),
            (
                "org.freedesktop.Secret.Item.Attributes",
                Variant::from(attributes),
            ),
        ]);
        let secret = (
            session.clone(),
            Vec::<u8>::new(),
            password.as_bytes().to_vec(),
            "text/plain; charset=utf8",
        );
        let created: zbus::Result<(OwnedObjectPath, OwnedObjectPath)> = self
            .call(
                LOGIN_PATH,
                COLLECTION,
                "CreateItem",
                &(properties, secret, true),
            )
            .await;
        let _: () = self
            .call(session.as_str(), SESSION, "Close", &())
            .await
            .unwrap();
        let (item, prompt) = created?;
        assert_eq!(prompt.as_str(), "/");
        Ok(item)
    }

    async fn search(&self, attributes: &[(&str, &str)]) -> Vec<OwnedObjectPath> {
        let attributes: HashMap<&str, &str> = attributes.iter().copied().collect();
        self.call(LOGIN_PATH, COLLECTION, "SearchItems", &(attributes,))
            .await
            .unwrap()
    }

    /// `go-keyring`'s `Get`.
    async fn get(&self, service: &str, user: &str) -> Option<String> {
        let found = self
            .search(&[("username", user), ("service", service)])
            .await;
        let item = found.first()?;
        let session = self.open_plain_session().await;
        let (unlocked, _) = self.unlock(item.as_str()).await;
        assert_eq!(unlocked, std::slice::from_ref(item));
        let ((_, _, value, _),): (WireSecret,) = self
            .call(item.as_str(), ITEM, "GetSecret", &(&session,))
            .await
            .unwrap();
        let _: () = self
            .call(session.as_str(), SESSION, "Close", &())
            .await
            .unwrap();
        Some(String::from_utf8(value).unwrap())
    }

    async fn delete(&self, item: &OwnedObjectPath) {
        let prompt: OwnedObjectPath = self.call(item.as_str(), ITEM, "Delete", &()).await.unwrap();
        assert_eq!(prompt.as_str(), "/");
    }
}

#[tokio::test]
async fn go_keyring_reads_back_what_it_set() {
    let fixture = Fixture::start().await;
    fixture.set("gh:github.com", "octo", "t0ken").await.unwrap();
    assert_eq!(
        fixture.get("gh:github.com", "octo").await.as_deref(),
        Some("t0ken")
    );
    assert_eq!(fixture.get("gh:github.com", "other").await, None);
}

/// godbus, under go-keyring, stores `GetSecret`'s reply into one struct and fails on four values.
#[tokio::test]
async fn get_secret_replies_with_one_secret_struct() {
    let fixture = Fixture::start().await;
    let item = fixture.set("gh:github.com", "", "t0ken").await.unwrap();
    let session = fixture.open_plain_session().await;
    assert_eq!(
        fixture
            .reply_signature(item.as_str(), ITEM, "GetSecret", &["o", session.as_str()])
            .await,
        "(oayays)"
    );
}

#[tokio::test]
async fn go_keyring_set_replaces_the_secret() {
    let fixture = Fixture::start().await;
    fixture.set("gh:github.com", "", "old").await.unwrap();
    fixture.set("gh:github.com", "", "new").await.unwrap();
    assert_eq!(
        fixture.get("gh:github.com", "").await.as_deref(),
        Some("new")
    );
}

/// glab's check for a working keyring: set a sentinel, then delete it.
#[tokio::test]
async fn go_keyring_deletes_what_it_set() {
    let fixture = Fixture::start().await;
    let service = "glab:__keyring_probe__:1:1";
    fixture.set(service, "", "1").await.unwrap();
    let found = fixture
        .search(&[("username", ""), ("service", service)])
        .await;
    assert_eq!(found.len(), 1);
    fixture.delete(&found[0]).await;
    assert_eq!(fixture.get(service, "").await, None);
}

#[tokio::test]
async fn go_keyring_delete_all_finds_every_user_of_a_service() {
    let fixture = Fixture::start().await;
    fixture.set("gh:github.com", "", "a").await.unwrap();
    fixture.set("gh:github.com", "octo", "b").await.unwrap();
    fixture.set("gh:example.com", "", "c").await.unwrap();
    let found = fixture.search(&[("service", "gh:github.com")]).await;
    assert_eq!(found.len(), 2);
    for item in &found {
        fixture.delete(item).await;
    }
    assert_eq!(
        fixture.get("gh:example.com", "").await.as_deref(),
        Some("c")
    );
}

/// Attributes no application scheme claims, as libsecret stores them, round-trip under
/// credrelay's own names; a go-keyring service outside the listed ones lands there too.
#[tokio::test]
async fn any_other_attributes_round_trip() {
    let fixture = Fixture::start().await;
    fixture
        .set("git", "https://github.com", "t0ken")
        .await
        .unwrap();
    assert_eq!(
        fixture.get("git", "https://github.com").await.as_deref(),
        Some("t0ken")
    );

    let session = fixture.open_plain_session().await;
    let attributes = HashMap::from([
        ("xdg:schema", "org.freedesktop.Secret.Generic"),
        ("server", "example.com"),
    ]);
    let properties = HashMap::from([(
        "org.freedesktop.Secret.Item.Attributes",
        Variant::from(attributes),
    )]);
    let secret = (
        session.clone(),
        Vec::<u8>::new(),
        b"pass".to_vec(),
        "text/plain",
    );
    let (item, _): (OwnedObjectPath, OwnedObjectPath) = fixture
        .call(
            DEFAULT_ALIAS_PATH,
            COLLECTION,
            "CreateItem",
            &(properties, secret, true),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture.search(&[("server", "example.com")]).await,
        vec![item.clone()]
    );
    let ((_, _, value, _),): (WireSecret,) = fixture
        .call(item.as_str(), ITEM, "GetSecret", &(&session,))
        .await
        .unwrap();
    assert_eq!(value, b"pass");
}

#[tokio::test]
async fn the_default_alias_is_the_login_collection() {
    let fixture = Fixture::start().await;
    let alias: OwnedObjectPath = fixture
        .call(SERVICE_PATH, SERVICE, "ReadAlias", &("default",))
        .await
        .unwrap();
    assert_eq!(alias.as_str(), LOGIN_PATH);
    fixture.set("gh:github.com", "", "t0ken").await.unwrap();
    let attributes = HashMap::from([("service", "gh:github.com")]);
    let found: Vec<OwnedObjectPath> = fixture
        .call(
            DEFAULT_ALIAS_PATH,
            COLLECTION,
            "SearchItems",
            &(attributes,),
        )
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
}

#[tokio::test]
async fn an_item_shows_its_attributes() {
    let fixture = Fixture::start().await;
    let item = fixture.set("gh:github.com", "octo", "t0ken").await.unwrap();
    let attributes: HashMap<String, String> =
        fixture.property(item.as_str(), ITEM, "Attributes").await;
    assert_eq!(
        attributes,
        HashMap::from([
            ("service".to_owned(), "gh:github.com".to_owned()),
            ("username".to_owned(), "octo".to_owned()),
        ])
    );
    let locked: bool = fixture.property(item.as_str(), ITEM, "Locked").await;
    assert!(!locked);
}

/// What libsecret and the Rust `keyring` stores do: a DH session, and the secret encrypted under
/// the key both sides derive.
#[tokio::test]
async fn a_dh_session_sends_and_receives_encrypted_secrets() {
    use oo7::{Key, crypto};

    let fixture = Fixture::start().await;
    let item = fixture.set("gh:github.com", "", "t0ken").await.unwrap();

    let private = Key::generate_private_key().unwrap();
    let public = Key::generate_public_key(&private).unwrap();
    let (output, session): (OwnedVariant, OwnedObjectPath) = fixture
        .call(
            SERVICE_PATH,
            SERVICE,
            "OpenSession",
            &(
                crate::session::DH_AES,
                Variant::from(public.as_ref().to_vec()),
            ),
        )
        .await
        .unwrap();
    let service_public = Vec::<u8>::try_from(output).unwrap();
    let key = Key::generate_aes_key(&private, &Key::new(service_public)).unwrap();

    let secrets: HashMap<OwnedObjectPath, (OwnedObjectPath, Vec<u8>, Vec<u8>, String)> = fixture
        .call(
            SERVICE_PATH,
            SERVICE,
            "GetSecrets",
            &(vec![item.clone()], &session),
        )
        .await
        .unwrap();
    let (_, iv, value, _) = &secrets[&item];
    assert_eq!(&*crypto::decrypt(value, &key, iv).unwrap(), b"t0ken");

    let iv = crypto::generate_iv().unwrap();
    let value = crypto::encrypt(b"rotated", &key, &iv).unwrap();
    let _: () = fixture
        .call(
            item.as_str(),
            ITEM,
            "SetSecret",
            &((&session, iv, value, "text/plain"),),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture.get("gh:github.com", "").await.as_deref(),
        Some("rotated")
    );
}

#[tokio::test]
async fn a_secret_for_a_closed_session_is_refused() {
    let fixture = Fixture::start().await;
    let item = fixture.set("gh:github.com", "", "t0ken").await.unwrap();
    let session = fixture.open_plain_session().await;
    let _: () = fixture
        .call(session.as_str(), SESSION, "Close", &())
        .await
        .unwrap();
    let error = fixture
        .call::<_, (WireSecret,)>(item.as_str(), ITEM, "GetSecret", &(&session,))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, zbus::Error::MethodError(name, _, _) if name.as_str() == "org.freedesktop.Secret.Error.NoSession"),
        "{error:?}"
    );
}
