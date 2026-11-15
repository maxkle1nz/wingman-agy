#!/bin/sh
# Installs the agy bridge CLI symlink. Idempotent.
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$HOME/.local/bin"
ln -sf "$REPO/agy" "$HOME/.local/bin/agy"
chmod +x "$REPO/agy"
echo "CLI     : ~/.local/bin/agy -> $REPO/agy"

echo "to teach your agents (Claude Code, Codex, Antigravity): run \`agy setup --apply\` in a terminal"
echo "done. try: agy status"
