#!/usr/bin/env bash
# Installs Joern (https://joern.io) using its official installer script.
#
# Usage:
#   ./scripts/setup_joern.sh [install-dir]
#
# After install, either add the install dir to PATH, or point cpgvd at it
# via the JOERN_HOME environment variable (see .env.example).

set -euo pipefail

INSTALL_DIR="${1:-$HOME/bin/joern}"

echo "Installing Joern into: ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

command -v curl >/dev/null 2>&1 || { echo "curl is required." >&2; exit 1; }
command -v java >/dev/null 2>&1 || { echo "A JDK (11+) is required on PATH." >&2; exit 1; }

TMP_SCRIPT="$(mktemp)"
curl -fsSL https://github.com/joernio/joern/releases/latest/download/joern-install.sh -o "${TMP_SCRIPT}"
chmod +x "${TMP_SCRIPT}"

"${TMP_SCRIPT}" --interactive=false --install-dir="${INSTALL_DIR}"
rm -f "${TMP_SCRIPT}"

# Joern's installer sometimes unpacks into a joern-cli/ subdirectory of
# INSTALL_DIR rather than putting binaries at its top level (this varies
# by installer version) -- find where joern-parse actually landed instead
# of assuming a fixed layout.
BIN_DIR="$(dirname "$(find "${INSTALL_DIR}" -maxdepth 3 -name 'joern-parse' -print -quit)")"

if [ -z "${BIN_DIR}" ]; then
  echo "Warning: could not locate joern-parse under ${INSTALL_DIR} after install." >&2
  echo "Check the installer output above for errors." >&2
  BIN_DIR="${INSTALL_DIR}"
fi

echo
echo "Done. Add this to your shell profile:"
echo "  export JOERN_HOME=\"${BIN_DIR}\""
echo "  export PATH=\"\$JOERN_HOME:\$PATH\""
echo
echo "Verify with: \"${BIN_DIR}/joern-parse\" --help"
