#!/bin/sh
# Builds credrelay and installs it: credrelay-client and credrelay-server.exe into /usr/local/bin,
# credrelay-keyring and credrelay-bao-helper with cargo install, their Windows builds into
# %LOCALAPPDATA%\Programs\credrelay, and the systemd user unit and the D-Bus activation file that
# start the client the first time an application asks for the Secret Service. Restarts a running client, starts nothing else,
# and doesn't touch any application's stored login. Safe to re-run any time to rebuild and reinstall.
set -eu

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="/usr/local/bin"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DBUS_SERVICE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/dbus-1/services"
# Windows applications run the Windows helpers, so they go where Windows keeps per-user programs,
# not behind a \\wsl.localhost path that exists only while WSL runs.
WIN_LOCALAPPDATA="$(cmd.exe /c 'echo %LOCALAPPDATA%' 2>/dev/null | tr -d '\r')"
WIN_BIN_DIR="$(wslpath "$WIN_LOCALAPPDATA")/Programs/credrelay"

# WSL runs the .exe natively only when it is built for the host's own architecture.
case "$(uname -m)" in
    aarch64 | arm64) WIN_TARGET="aarch64-pc-windows-msvc" ;;
    x86_64 | amd64) WIN_TARGET="x86_64-pc-windows-msvc" ;;
    *)
        echo "credrelay install.sh: unrecognized host architecture '$(uname -m)' — don't know which *-pc-windows-msvc target matches it" >&2
        exit 1
        ;;
esac
echo "==> Host architecture $(uname -m) -> Windows target $WIN_TARGET"

rustup target add "$WIN_TARGET"

echo "==> Building credrelay-client (release)"
(cd "$REPO_DIR" && cargo build --release -p credrelay-client)

echo "==> Building credrelay-server and the Windows helpers (release, $WIN_TARGET)"
(cd "$REPO_DIR" && cargo xwin build --release -p credrelay-server -p credrelay-keyring --target "$WIN_TARGET")

echo "==> Installing credrelay-client and credrelay-server.exe into $BIN_DIR (sudo)"
sudo install -m 755 "$REPO_DIR/target/release/credrelay-client" "$BIN_DIR/credrelay-client"
sudo install -m 755 "$REPO_DIR/target/$WIN_TARGET/release/credrelay-server.exe" "$BIN_DIR/credrelay-server.exe"

echo "==> Installing credrelay-keyring and credrelay-bao-helper (cargo install)"
cargo install --path "$REPO_DIR/keyring"

printf '%s\n' "==> Installing the Windows helpers into $WIN_LOCALAPPDATA\\Programs\\credrelay"
mkdir -p "$WIN_BIN_DIR"
for bin in credrelay-keyring credrelay-bao-helper; do
    install -m 755 "$REPO_DIR/target/$WIN_TARGET/release/$bin.exe" "$WIN_BIN_DIR/$bin.exe"
done

echo "==> Installing the systemd user unit and the D-Bus activation file"
mkdir -p "$UNIT_DIR" "$DBUS_SERVICE_DIR"
sed "s|@BINDIR@|$BIN_DIR|g" "$REPO_DIR/contrib/credrelay.service" > "$UNIT_DIR/credrelay.service"
sed "s|@BINDIR@|$BIN_DIR|g" "$REPO_DIR/contrib/org.freedesktop.secrets.service" \
    > "$DBUS_SERVICE_DIR/org.freedesktop.secrets.service"
systemctl --user daemon-reload
# A running instance keeps the binary it started with until it restarts; a stopped one stays stopped.
systemctl --user try-restart credrelay.service

cat <<EOF

==> Installed:
    $BIN_DIR/credrelay-client
    $BIN_DIR/credrelay-server.exe
    ${CARGO_HOME:-$HOME/.cargo}/bin/credrelay-keyring
    ${CARGO_HOME:-$HOME/.cargo}/bin/credrelay-bao-helper
    $WIN_LOCALAPPDATA\\Programs\\credrelay\\credrelay-keyring.exe
    $WIN_LOCALAPPDATA\\Programs\\credrelay\\credrelay-bao-helper.exe
    $UNIT_DIR/credrelay.service
    $DBUS_SERVICE_DIR/org.freedesktop.secrets.service

credrelay starts the first time an application asks for the Secret Service. To start it now and
see that it holds the name:

    systemctl --user start credrelay
    systemctl --user status credrelay

If it fails because org.freedesktop.secrets is taken, another Secret Service (gnome-keyring, for
one) is running on this session bus; stop and disable it first.

See the README for moving gh and glab onto the keyring, and for setting up sops with age, kubectl
and OpenBao through credrelay-keyring on both sides.
EOF
