#!/bin/sh
# Local Codex CLI installation. No daemon, credentials, guard, or network access.
set -eu

REPO="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CLI="$HOME/.local/bin/agy"

check_destination() {
    destination=$1
    source=$2
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        if [ ! -L "$destination" ] || [ "$(readlink "$destination")" != "$source" ]; then
            printf 'Refusing to replace existing path: %s\n' "$destination" >&2
            exit 1
        fi
    fi
}

check_destination "$CLI" "$REPO/agy"
mkdir -p "$HOME/.local/bin"
[ -L "$CLI" ] || ln -s "$REPO/agy" "$CLI"
printf 'CLI: %s\n' "$CLI"
printf 'to teach your agents (Claude Code, Codex, Antigravity): run `agy setup --apply` in a terminal\n'
printf 'No daemon, guard, credentials, or PATH configuration was changed.\n'
