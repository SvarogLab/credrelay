#!/bin/sh
# Builds credrelay and installs it: credrelay-client and credrelay-server.exe into /usr/local/bin;
# credrelay-keyring and credrelay-bao-helper with cargo install, and their Windows builds with the
# Windows cargo install; and the systemd user unit and the D-Bus activation file that start the
# client the first time an application asks for the Secret Service. Restarts a running client,
# starts nothing else, and doesn't touch any application's stored login. Safe to re-run any time to
# rebuild and reinstall.
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

echo "==> Installing credrelay-client and credrelay-server.exe into $BIN_DIR (sudo)"
sudo install -m 755 "$REPO_DIR/target/release/credrelay-client" "$BIN_DIR/credrelay-client"
sudo install -m 755 "$REPO_DIR/target/$WIN_TARGET/release/credrelay-server.exe" "$BIN_DIR/credrelay-server.exe"

echo "==> Installing credrelay-keyring and credrelay-bao-helper (cargo install)"
cargo install --path "$REPO_DIR/keyring"

# Windows applications run the Windows helpers, so the Windows toolchain installs them into its own
# cargo bin directory. It reads the sources through \\wsl.localhost but builds under %TEMP%, since
# building on that share is slow. cmd.exe can't start in a WSL directory, hence the cd.
echo "==> Installing the Windows credrelay-keyring and credrelay-bao-helper (Windows cargo install)"
if ! cmd.exe /c "where cargo" > /dev/null 2>&1; then
    echo "credrelay install.sh: no cargo on the Windows side; install Rust for Windows first" >&2
    exit 1
fi
(
    cd "$(wslpath "$(cmd.exe /c 'echo %SystemRoot%' 2>/dev/null | tr -d '\r')")"
    cmd.exe /c "set CARGO_TARGET_DIR=%TEMP%\\credrelay-target&& cargo install --path $(wslpath -w "$REPO_DIR/keyring")"
)

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
    %USERPROFILE%\\.cargo\\bin\\credrelay-keyring.exe (or the Windows CARGO_HOME)
    %USERPROFILE%\\.cargo\\bin\\credrelay-bao-helper.exe
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
