# credrelay

`credrelay` serves the freedesktop [Secret Service](https://specifications.freedesktop.org/secret-service/)
(`org.freedesktop.secrets`) on the WSL session bus and keeps every secret in the Windows Credential
Manager. It takes the place of gnome-keyring or KeePassXC on a Linux desktop: Linux applications
store their secrets through it as they would anywhere else.

Where an application ships for both systems and stores its secrets through a known library, the
Linux build finds what the Windows build stored, and the other way round. Today that covers the
applications built on [`zalando/go-keyring`](https://github.com/zalando/go-keyring), `gh` and `glab`
among them: log in on one side, and the other side is logged in too. For tools that keep their
secrets in files instead, `credrelay-keyring` stores them the same way on both sides: an age key
for sops, a kubectl client certificate, an OpenBao token.

Without a Secret Service, WSL has nowhere safe to keep a token: `gh` and `glab` fall back to
plaintext files (`~/.config/gh/hosts.yml`, `~/.config/glab-cli/config.yml`) and need a login of
their own, apart from the Windows one.

## Architecture

- **`credrelay-client`** (WSL/Linux) owns `org.freedesktop.secrets` on the session bus. At startup it
  starts **`credrelay-server.exe`** exactly once and multiplexes every credential request over that
  process's stdin/stdout with [`yamux`](https://docs.rs/yamux), one stream per request, so requests
  run side by side and a slow one holds up no other. Starting one Windows process per request would
  run into a WSL interop bug under load ([microsoft/WSL #7371](https://github.com/microsoft/WSL/issues/7371)).
  Before taking the bus name the client asks the server one question, so a server that can't answer
  never serves. If the server exits or the connection to it ends, the client exits too rather than
  restarting it; systemd restarts the client. The spawning, the multiplexing, the logging and this
  lifecycle come from [`librelay`](https://github.com/SvarogLab/librelay), shared with
  [`sockrelay`](https://github.com/SvarogLab/sockrelay).
- **`credrelay-server.exe`** (Windows, cross-compiled; WSL runs it natively) reads, writes, deletes
  and lists generic credentials with `CredReadW`, `CredWriteW`, `CredDeleteW` and `CredEnumerateW`.
  It knows nothing about the Secret Service.
- **`credrelay-protocol`** is what the two say on each stream: one JSON request line from the client,
  one JSON answer line back, for example `{"op":"list","prefix":"gh:"}` and
  `{"Ok":{"credentials":[…]}}`.

- **`credrelay-keyring`** and **`credrelay-bao-helper`** (Linux and Windows) read and write one
  secret under go-keyring's names: through the Secret Service on Linux, in the Credential Manager
  directly on Windows. See [Running](#running) for what they serve.

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
`wincred/src/store.rs` holds this). It also percent-encodes capital letters, because the Credential
Manager compares targets regardless of case: attributes that differ only in case would otherwise
share one credential.

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

### `credrelay-client`

Every flag has a default, and the client runs with none under systemd:

```text
credrelay-client
  --server-exe <PATH>             default: "credrelay-server.exe", searched for on PATH
  --go-keyring-prefix <PREFIX>    default: gh: glab: age: bao: kubectl:; repeat it to list others,
                                  which replaces the default
  --request-timeout-secs <N>      default: 10
```

`--request-timeout-secs` bounds how long the server may take to answer one request. A request that
isn't answered in time fails on its own; the others, each on its own stream, carry on.

### `credrelay-server`

Not meant to be run by hand: the client starts it and passes every flag, and every flag is required.

```text
credrelay-server.exe
  --log-filter <FILTER>           RUST_LOG syntax, e.g. info
```

The filter is a flag rather than `RUST_LOG` because environment variables set in WSL don't reach a
Windows process started from it.

### `credrelay-keyring` and `credrelay-bao-helper`

```text
credrelay-keyring get <SERVICE> [--username <NAME>]              the secret, to stdout, as stored
credrelay-keyring set <SERVICE> [--username <NAME>]              stdin, as read, replacing any secret
credrelay-keyring delete <SERVICE> [--username <NAME>]
credrelay-keyring kube-credential <SERVICE> [--username <NAME>]  a kubectl ExecCredential

credrelay-bao-helper get|store|erase                             an OpenBao token helper
```

The username defaults to empty. A missing secret makes `get` and `delete` exit non-zero. A Windows
credential holds at most 2560 bytes of secret, on either side, so a larger one is refused with an
error saying so.
`credrelay-bao-helper` is a binary of its own because OpenBao runs its token helper by path, with
the operation as the only argument; it keys the token by the server address bao passes in
`BAO_ADDR` (or `VAULT_ADDR`), as service `bao:<address>`.

## Running

### Running under systemd

```sh
./install.sh
```

builds and installs:

- `credrelay-client` and `credrelay-server.exe` into `/usr/local/bin`;
- `credrelay-keyring` and `credrelay-bao-helper` with `cargo install`;
- their Windows builds with the Windows `cargo install`, into the Windows cargo bin directory. This
  needs Rust installed on the Windows side;
- a systemd user unit (`$XDG_CONFIG_HOME/systemd/user/credrelay.service`) and a D-Bus activation
  file (`$XDG_DATA_HOME/dbus-1/services/org.freedesktop.secrets.service`).

The first application that asks for the Secret Service starts the client. It needs systemd running
in WSL (`systemd=true` under `[boot]` in `/etc/wsl.conf`). Re-running `install.sh` restarts a running
client, so it picks up the new build; the client and the server are always installed together.

Only one process can own `org.freedesktop.secrets`. If another Secret Service, gnome-keyring for one,
runs on the same session bus, stop and disable it first; `systemctl --user status credrelay` shows
the failure otherwise.

### Moving gh and glab onto the keyring

An existing plaintext login stays where it is: an application reads the keyring only for what it
stored there. With credrelay running, and the Windows build already logged in to the same account,
the Linux build takes over the Windows login with no new login at all:

- `gh`: delete every `oauth_token` line from `~/.config/gh/hosts.yml`, leaving `user` and the
  account under `users` (as `<account>: {}`). `gh` then reads the active account's token from the
  keyring; `gh auth status` reports it as `(keyring)`.
- `glab`: in `~/.config/glab-cli/config.yml`, under the host, set `use_keyring: "true"`, empty
  `token` and `oauth2_refresh_token`, and copy `oauth2_expiry_date` from the Windows build's config
  (`%USERPROFILE%\.config\glab-cli\config.yml`), which holds the expiry of the token now in the
  keyring. `glab auth status` then reports `Token found in operating system keyring`.

  `use_keyring` matters beyond reading: with it `"false"`, every token `glab` writes, a refresh
  included, also deletes the keyring copy, which is now the Windows login.

Logging in again on the Linux side (`gh auth login`, `glab auth login`) works too, and replaces the
token the Windows build uses.

Both sides now share one credential, so **logging out on either side logs out both**.

`glab` refreshes an OAuth token under a lock in its own config directory, which is separate on each
side: a refresh on both sides at the same moment can race, and one side then logs in again.

### sops with age

Store the key file once, from either side, then point sops at the keyring on both:

```sh
credrelay-keyring set age:default < ~/.config/sops/age/keys.txt
export SOPS_AGE_KEY_CMD="credrelay-keyring get age:default"
```

On Windows, set `SOPS_AGE_KEY_CMD` to the same value as a user environment variable. sops runs the
command itself, without a shell, and reads the keys from its output; the key file can then go.

### kubectl

The exec plugin hands kubectl a kubeconfig user entry kept in the keyring. Store the entry as
kubeconfig holds it, then point the user at the plugin and drop the inline data:

```sh
kubectl config view --raw -o jsonpath='{.users[?(@.name=="<user>")].user}' \
  | credrelay-keyring set kubectl:<user>
kubectl config set-credentials <user> --exec-api-version=client.authentication.k8s.io/v1 \
  --exec-command=credrelay-keyring --exec-arg=kube-credential --exec-arg=kubectl:<user> \
  --exec-interactive-mode=Never
kubectl config unset users.<user>.client-certificate-data
kubectl config unset users.<user>.client-key-data
```

The entry must fit in 2560 bytes: one with an EC client key does, while a 2048-bit RSA key with its
certificate, base64-encoded, may not. Run the last three commands with the Windows `kubectl` as
well, against its kubeconfig. Entries with
a `token` work the same way (`kubectl config unset users.<user>.token`).

### OpenBao

`credrelay-bao-helper` keeps the token in the keyring, keyed by server address. Name it as the
token helper in `~/.bao` on Linux and `%USERPROFILE%\.bao` on Windows, by its full path:

```hcl
token_helper = "<path to credrelay-bao-helper>"
```

Both sides must reach the server under the same address (`BAO_ADDR` or `VAULT_ADDR`), since that is
the key. bao asks the helper only when `BAO_TOKEN` and `VAULT_TOKEN` are unset. `bao login` stores
the token through it; `bao token renew` renews the same token, so both sides keep using it.

### When gh or glab hangs

Every call that needs a token reads it from the keyring, so a stopped or stuck credrelay shows up as
`gh` or `glab` hanging with no output, `glab` saying it failed to read from the operating system
keyring, or `gh` saying it isn't logged in. An HTTP 401, 403 or 405 from the forge is about rights or
state there, not credrelay. These answer at once when credrelay is well:

```sh
systemctl --user is-active credrelay
timeout 5 busctl --user call org.freedesktop.secrets /org/freedesktop/secrets \
  org.freedesktop.DBus.Properties Get ss org.freedesktop.Secret.Service Collections
journalctl --user -u credrelay -n 30 --no-pager
```

While investigating, don't run `gh auth logout` or `glab auth logout`: they delete the shared
credential, which logs the Windows side out too.

## Logging

The client logs to stderr, which systemd sends to the journal; colors only on a terminal. Verbosity
follows `RUST_LOG`, `info` when it is unset or empty; a value that doesn't parse stops the client
before it starts the server, with the error on stderr. The client passes the same filter to the
server as `--log-filter` and writes each line of the server's stderr to its own behind a `server:`
prefix followed by a space, unchanged otherwise. Off a terminal the server writes no timestamps of
its own; the journal stamps every line.

```sh
journalctl --user -u credrelay
```

## Building

The server is cross-compiled for Windows with [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin);
WSL runs the `.exe` natively when it targets the host's own architecture:

```sh
rustup target add aarch64-pc-windows-msvc
cargo install cargo-xwin

cargo build -p credrelay-client -p credrelay-keyring
cargo xwin build -p credrelay-server -p credrelay-keyring --target aarch64-pc-windows-msvc
```

(`x86_64-pc-windows-msvc` on an x86-64 host.)

### Prebuilt binaries

Each [release](https://github.com/SvarogLab/credrelay/releases) carries, for `amd64` and `arm64`,
`credrelay-client`, `credrelay-keyring` and `credrelay-bao-helper` for Linux (static musl builds,
named `<binary>-linux-<arch>`) and `credrelay-server`, `credrelay-keyring` and `credrelay-bao-helper`
for Windows (`<binary>-windows-<arch>.exe`), with their checksums in `SHA256SUMS`. Install them on
`PATH` under their own names, then copy `contrib/credrelay.service` and
`contrib/org.freedesktop.secrets.service` where `install.sh` puts them, replacing `@BINDIR@` with the
directory holding `credrelay-client`.

### Releasing

Run the **Release PR** workflow from the Actions tab. It opens `chore: release vX.Y.Z` with the
version git-cliff computes from the commits since the last tag and a regenerated `CHANGELOG.md`;
merging it tags the commit and publishes the release.

## Testing

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The client's tests, and `credrelay-keyring`'s Linux test, start a private `dbus-daemon` and read
some replies back with `busctl`, so both need to be installed. They run the service against an
in-memory store and drive it the way `go-keyring` and oo7 do.

The Credential Manager code builds only for Windows. Its tests, in `credrelay-wincred` and
`credrelay-keyring`, run there against the real Credential Manager of whoever runs them, under
names starting with `credrelay-test`, and delete what they write:

```sh
eval "$(cargo xwin env --target aarch64-pc-windows-msvc)"
unset CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_RUNNER
cargo test -p credrelay-wincred -p credrelay-server -p credrelay-keyring --target aarch64-pc-windows-msvc
cargo clippy -p credrelay-wincred -p credrelay-server -p credrelay-keyring --all-targets \
  --target aarch64-pc-windows-msvc
```

`cargo xwin test` would set `CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_RUNNER=wine`; WSL runs the test
binary itself, so the runner is unset and plain `cargo test` used instead.

## Security notes

- Any process running as the same user in WSL can read every secret credrelay serves, as on any
  Linux desktop with an unlocked keyring. It can also start Windows processes and read the
  Credential Manager directly; credrelay adds no way in that wasn't there.
- The scheme prefixes keep applications from overwriting each other's credentials by accident; they
  are not an access control.
- Credentials are written with local-machine persistence, as go-keyring writes them: they stay on
  this machine and don't roam with the Windows profile.
- A `plain` session sends secrets over the session bus unencrypted, as the specification allows; a
  client that asks for the DH session gets them encrypted. `credrelay-keyring` asks for DH.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
