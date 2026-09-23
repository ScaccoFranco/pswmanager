#!/bin/sh
# Rimuove i file installati da install.sh. Non tocca i vault né i loro .bak.
set -eu

PREFIX="${PREFIX:-$HOME/.local}"

rm -f "$PREFIX/bin/pwdv" \
      "$PREFIX/bin/pwdv-gui" \
      "$PREFIX/share/applications/pwdv.desktop" \
      "$PREFIX/share/icons/hicolor/scalable/apps/pwdv.svg"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
fi

echo "Rimosso da $PREFIX"
