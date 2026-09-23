#!/bin/sh
# Compila pwdv in release e lo installa per l'utente corrente.
# Destinazione predefinita: ~/.local. Per cambiarla: PREFIX=/percorso ./install.sh
set -eu

PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"
APPDIR="$PREFIX/share/applications"
ICONDIR="$PREFIX/share/icons/hicolor/scalable/apps"
SRC="$(cd "$(dirname "$0")" && pwd)"

cargo build --release --manifest-path "$SRC/Cargo.toml" -p pwdv-cli -p pwdv-gui

install -Dm755 "$SRC/target/release/pwdv" "$BINDIR/pwdv"
install -Dm755 "$SRC/target/release/pwdv-gui" "$BINDIR/pwdv-gui"
install -Dm644 "$SRC/packaging/linux/pwdv.svg" "$ICONDIR/pwdv.svg"
mkdir -p "$APPDIR"
# Percorso assoluto in Exec: i launcher non sempre hanno ~/.local/bin nel PATH.
sed "s|@BINDIR@|$BINDIR|g" "$SRC/packaging/linux/pwdv.desktop.in" > "$APPDIR/pwdv.desktop"
chmod 644 "$APPDIR/pwdv.desktop"

# Aggiornamento della cache: facoltativo, i launcher recenti rileggono da soli.
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPDIR" 2>/dev/null || true
fi

echo "Installato in $PREFIX"
case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *) echo "Nota: $BINDIR non è nel PATH; aggiungilo per usare 'pwdv' da terminale." ;;
esac
