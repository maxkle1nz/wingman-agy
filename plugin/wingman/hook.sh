#!/bin/sh
# Always-answer wrapper for the wingman Antigravity plugin hooks.
# Never falls back to /usr/bin/python3 (which triggers a CLT install dialog on macOS).

event="${1:-}"

neutral() {
  if [ "$event" = "PreToolUse" ]; then
    printf '{"decision":"ask"}\n'
  else
    printf '{}\n'
  fi
  exit 0
}

wingman_dir="${WINGMAN_DIR:-$HOME/.agy/wingman}"
py_file="$wingman_dir/python"

[ -f "$py_file" ] && [ -r "$py_file" ] || neutral
IFS= read -r py < "$py_file" || true
py="${py%$(printf '\r')}"
[ -n "$py" ] && [ -f "$py" ] && [ -x "$py" ] || neutral

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if out=$("$py" -I "$script_dir/hook.py" "$event" 2>/dev/null); then
  out_clean=$(printf '%s' "$out" | tr -d ' \t\r\n')
  case "$out_clean" in
    \{*\}) ;;
    *) neutral ;;
  esac
  if [ -n "$out_clean" ]; then
    printf '%s\n' "$out"
    exit 0
  fi
fi

neutral
