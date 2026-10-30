# credrelay

`credrelay` serves the freedesktop [Secret Service](https://specifications.freedesktop.org/secret-service/)
(`org.freedesktop.secrets`) on the WSL session bus and keeps every secret in the Windows Credential
Manager. It takes the place of gnome-keyring or KeePassXC on a Linux desktop: Linux applications
store their secrets through it as they would anywhere else.

Where an application ships for both systems and stores its secrets through a known library, the
Linux build finds what the Windows build stored, and the other way round. Today that covers the
applications built on [`zalando/go-keyring`](https://github.com/zalando/go-keyring), `gh` and `glab`
among them: log in on one side, and the other side is logged in too.

Without a Secret Service, WSL has nowhere safe to keep a token: `gh` and `glab` fall back to
plaintext files (`~/.config/gh/hosts.yml`, `~/.config/glab-cli/config.yml`) and need a login of
their own, apart from the Windows one.

## Architecture

- **`credrelay-client`** (WSL/Linux) owns `org.freedesktop.secrets` on the session bus. At startup it
  starts **`credrelay-server.exe`** exactly once and sends it every credential request over that
  process's stdin/stdout. Starting one Windows process per request would run into a WSL interop bug
  under load ([microsoft/WSL #7371](https://github.com/microsoft/WSL/issues/7371)). If the server
  exits, the client exits too rather than restarting it; systemd restarts the client.
- **`credrelay-server.exe`** (Windows, cross-compiled; WSL runs it natively) reads, writes, deletes
  and lists generic credentials with `CredReadW`, `CredWriteW`, `CredDeleteW` and `CredEnumerateW`.
  It knows nothing about the Secret Service.
- **`credrelay-protocol`** is what the two say to each other: one JSON request per line, one JSON
  response per line, strictly in turn, so the server can be driven by hand:

  ```sh
  echo '{"op":"list","prefix":"gh:"}' | credrelay-server.exe
  ```

### Schemes

A Secret Service item is a set of attributes and a secret; a Windows credential is a target name, a
user name and a blob. A *scheme* is the mapping between the two that one credential library uses,
one module each under `client/src/schemes/`. An item goes to the first scheme that claims it:

| Scheme | Claims | Windows credential |
| --- | --- | --- |
| go-keyring | attributes exactly `{service, username}`, with `service` under a `--go-keyring-prefix` | target `service:username`, user `username`, the secret's bytes as they are |
| credrelay | everything else | target `credrelay:` followed by the attributes, sorted, `key,value` pairs joined by `;`, keys and values percent-encoded |

Attributes alone don't say which library stored an item: the Rust `keyring` crate, for one, stores
the same `{service, username}` under a different Windows name. The service does, since each
application names its own (`gh:github.com`, `glab:gitlab.com:token`), so the go-keyring scheme takes
only the services it is told belong to go-keyring applications. Every other item is kept under
`credrelay:` names, which only Linux applications read; no Windows application has a counterpart to
look for.

That also keeps an application from overwriting another one's credential by accident: an item whose
attributes happen to spell out someone else's target name lands under `credrelay:` instead.

The `credrelay:` encoding leaves no `=` or `:` after the prefix because the Credential Manager leaves
a target out of listings when `service=` or `target=` follows its first colon (a test in
`server/src/wincred.rs` holds this).

### What the service implements

- One collection, `/org/freedesktop/secrets/collection/login`, also reachable as the `default` alias
  (`ReadAlias`, `/org/freedesktop/secrets/aliases/default`).
- Sessions `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`. libsecret and the Rust `keyring` crate
  ask for the latter, and the Rust crate has no fallback.
- `SearchItems`, `CreateItem`, `GetSecret`, `GetSecrets`, `SetSecret`, `Delete`, and item properties
  `Attributes`, `Label`, `Locked`.
- Nothing is ever locked, and no call returns a prompt: `Unlock` returns what it was given.
- A credential holds one secret per target, so `CreateItem` replaces an item with exactly the same
  attributes whether or not `replace` is set.
- Not kept: labels (an item's `Label` is its target name), creation and modification times (`0`).
- Not supported: `CreateCollection`, `SetAlias`, and deleting the collection.

## Configuration

`credrelay-client` needs no flags in the common case:

```text
credrelay-client
  --server-exe <PATH>           default: "credrelay-server.exe", searched for on PATH
  --go-keyring-prefix <PREFIX>  default: gh: and glab:; repeat it to list others, which replaces the default
```

`credrelay-server.exe` takes no flags: `credrelay-client` starts it, and decides which credentials
are touched.

Log verbosity follows `RUST_LOG` (default `info`). The client logs to stderr, which systemd sends to
the journal, and forwards the server's stderr there too:

```sh
journalctl --user -u credrelay
```

## Installing

```sh
./install.sh
```

builds both binaries, installs them into `/usr/local/bin`, and installs a systemd user unit
(`$XDG_CONFIG_HOME/systemd/user/credrelay.service`) and a D-Bus activation file
(`$XDG_DATA_HOME/dbus-1/services/org.freedesktop.secrets.service`). The first application that asks
for the Secret Service starts the client. It needs systemd running in WSL (`systemd=true` under
`[boot]` in `/etc/wsl.conf`).

Only one process can own `org.freedesktop.secrets`. If another Secret Service, gnome-keyring for one,
runs on the same session bus, stop and disable it first; `systemctl --user status credrelay` shows
the failure otherwise.

### Prebuilt binaries

Each [release](https://github.com/SvarogLab/credrelay/releases) carries the client for Linux
(`credrelay-client-linux-amd64`, `credrelay-client-linux-arm64`, static musl builds) and the server
for Windows (`credrelay-server-windows-amd64.exe`, `credrelay-server-windows-arm64.exe`), with their
checksums in `SHA256SUMS`. Install them as `credrelay-client` and `credrelay-server.exe` on `PATH`,
then copy `contrib/credrelay.service` and `contrib/org.freedesktop.secrets.service` where
`install.sh` puts them, replacing `@BINDIR@` with the directory holding `credrelay-client`.

### Moving gh and glab onto the keyring

An existing plaintext login stays where it is: an application reads the keyring only for what it
stored there. With credrelay running:

- `gh auth status` says where each token lives. A plaintext token moves with `gh auth login`, which
  stores into the keyring when one is available. If the Windows `gh` is already logged in to the same
  account, removing `oauth_token` from `~/.config/gh/hosts.yml` instead makes the Linux `gh` pick up
  the Windows token.
- `glab auth login` tries a test write to the keyring and, when it succeeds, stores the token there;
  logging in again moves a plaintext login.

Both sides now share one credential, so **logging out on either side logs out both**.

`glab` refreshes an OAuth token under a lock in its own config directory, which is separate on each
side: a refresh on both sides at the same moment can race, and one side then logs in again.

## Building

The server is cross-compiled for Windows with [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin);
WSL runs the `.exe` natively when it targets the host's own architecture:

```sh
rustup target add aarch64-pc-windows-msvc
cargo install cargo-xwin

cargo build -p credrelay-client
cargo xwin build -p credrelay-server --target aarch64-pc-windows-msvc
```

(`x86_64-pc-windows-msvc` on an x86-64 host.)

## Testing

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The client's tests start a private `dbus-daemon` per test and read some replies back with `busctl`,
so both need to be installed. They run the service against an in-memory store and drive it the way
`go-keyring` does.

The server's Credential Manager code builds only for Windows. Its tests run there, against the real
Credential Manager of whoever runs them, under target names starting with `credrelay-test`, and
delete what they write:

```sh
eval "$(cargo xwin env --target aarch64-pc-windows-msvc)"
unset CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_RUNNER
cargo test -p credrelay-server --target aarch64-pc-windows-msvc
cargo clippy -p credrelay-server --all-targets --target aarch64-pc-windows-msvc
```

`cargo xwin test` would set `CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_RUNNER=wine`; WSL runs the test
binary itself, so the runner is unset and plain `cargo test` used instead.

### Releasing

Run the **Release PR** workflow from the Actions tab. It opens `chore: release vX.Y.Z` with the
version git-cliff computes from the commits since the last tag and a regenerated `CHANGELOG.md`;
merging it tags the commit and publishes the release.

## Security notes

- Any process running as the same user in WSL can read every secret credrelay serves, as on any
  Linux desktop with an unlocked keyring. It can also start Windows processes and read the
  Credential Manager directly; credrelay adds no way in that wasn't there.
- The scheme prefixes keep applications from overwriting each other's credentials by accident; they
  are not an access control.
- Credentials are written with local-machine persistence, as go-keyring writes them: they stay on
  this machine and don't roam with the Windows profile.
- A `plain` session sends secrets over the session bus unencrypted, as the specification allows; a
  client that asks for the DH session gets them encrypted.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
