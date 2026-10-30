#!/bin/sh
# Builds both credrelay binaries, installs them into /usr/local/bin, and installs the systemd user
# unit and the D-Bus activation file that start the client the first time an application asks for
# the Secret Service. Starts nothing itself, and doesn't touch any application's stored login.
# Safe to re-run any time to rebuild and reinstall.
set -eu

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="/usr/local/bin"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DBUS_SERVICE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/dbus-1/services"

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

echo "==> Building credrelay-server (release, $WIN_TARGET)"
(cd "$REPO_DIR" && cargo xwin build --release -p credrelay-server --target "$WIN_TARGET")

echo "==> Installing binaries into $BIN_DIR (sudo)"
sudo install -m 755 "$REPO_DIR/target/release/credrelay-client" "$BIN_DIR/credrelay-client"
sudo install -m 755 "$REPO_DIR/target/$WIN_TARGET/release/credrelay-server.exe" "$BIN_DIR/credrelay-server.exe"

echo "==> Installing the systemd user unit and the D-Bus activation file"
mkdir -p "$UNIT_DIR" "$DBUS_SERVICE_DIR"
sed "s|@BINDIR@|$BIN_DIR|g" "$REPO_DIR/contrib/credrelay.service" > "$UNIT_DIR/credrelay.service"
sed "s|@BINDIR@|$BIN_DIR|g" "$REPO_DIR/contrib/org.freedesktop.secrets.service" \
    > "$DBUS_SERVICE_DIR/org.freedesktop.secrets.service"
systemctl --user daemon-reload

cat <<EOF

==> Installed:
    $BIN_DIR/credrelay-client
    $BIN_DIR/credrelay-server.exe
    $UNIT_DIR/credrelay.service
    $DBUS_SERVICE_DIR/org.freedesktop.secrets.service

credrelay starts the first time an application asks for the Secret Service. To start it now and
see that it holds the name:

    systemctl --user start credrelay
    systemctl --user status credrelay

If it fails because org.freedesktop.secrets is taken, another Secret Service (gnome-keyring, for
one) is running on this session bus; stop and disable it first.

See the README's "Moving gh and glab onto the keyring" for switching an existing plaintext login.
EOF
