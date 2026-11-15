#!/bin/bash
# Read-only smoke test against the LIVE Antigravity installation.
# Never calls `agy new` / `agy send` (those spend quota and drive autonomous agents).
set -uo pipefail

AGY="${AGY_BIN:-$(dirname "$0")/../agy}"
pass=0; fail=0

check() { # check <name> <expected_exit> <grep_pattern> -- cmd...
  local name="$1" want_exit="$2" pattern="$3"; shift 3; shift # consume --
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -ne "$want_exit" ]; then
    echo "FAIL  $name (exit $rc, wanted $want_exit)"; echo "$out" | sed 's/^/      /' | head -6
    fail=$((fail+1)); return
  fi
  # No grep -q: it exits at the first match, and under pipefail the SIGPIPE that echo then
  # gets on a large output turns a match into a failure.
  if [ -n "$pattern" ] && ! printf '%s\n' "$out" | grep -iE -e "$pattern" >/dev/null; then
    echo "FAIL  $name (missing /$pattern/)"; echo "$out" | sed 's/^/      /' | head -6
    fail=$((fail+1)); return
  fi
  echo "ok    $name"; pass=$((pass+1))
}

echo "== agy-bridge smoke (read-only) =="

# 1. status: discovery finds daemon + proves the gRPC port; token never printed
check "status finds daemon + proven port"  0 "daemon *: up"            -- "$AGY" status
check "status never prints the token"      0 "present"                 -- "$AGY" status
out="$("$AGY" status 2>&1)"
if printf '%s\n' "$out" | grep -E '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' >/dev/null; then
  echo "FAIL  token leak check (uuid-shaped string in status output)"; fail=$((fail+1))
else
  echo "ok    token leak check"; pass=$((pass+1))
fi

# 1b. leak check across ALL read commands against the REAL token (conversation ids
#     are legitimately uuid-shaped, so here we grep for the exact live token).
TOKEN="$(ps -p "$(pgrep -f 'language_server.*--standalone' | head -1)" -o command= 2>/dev/null \
        | sed -n 's/.*--csrf_token \([^ ]*\).*/\1/p')"
if [ -n "$TOKEN" ]; then
  CID0="$(ls "$HOME/.gemini/antigravity/conversations/"*.db 2>/dev/null | head -1 | xargs -I{} basename {} .db)"
  all_out="$({ "$AGY" status; "$AGY" ls; "$AGY" quota; "$AGY" quota --raw; \
               "$AGY" models; "$AGY" ledger; "$AGY" grants status; "$AGY" gc; \
               [ -n "$CID0" ] && "$AGY" show "$CID0"; [ -n "$CID0" ] && "$AGY" tail "$CID0" -n 20; } 2>&1)"
  if printf '%s\n' "$all_out" | grep -F -e "$TOKEN" >/dev/null; then
    echo "FAIL  live-token leak across status/ls/quota/models/ledger/grants/gc/show/tail"; fail=$((fail+1))
  else
    echo "ok    live-token leak check (status/ls/quota/models/ledger/grants/gc/show/tail)"; pass=$((pass+1))
  fi
else
  echo "skip  live-token leak check (daemon not found by smoke)"
fi

# 1c. the API lane carries a SECOND secret (the Gemini key): status must report
#     presence only, and the key must never appear in any output. Never echo $KEY.
KEY="$(security find-generic-password -s gemini-api-key -a "${AGY_API_KEY_ACCOUNT:-$(id -un)}" -w 2>/dev/null)"
if [ -n "$KEY" ]; then
  api_out="$({ "$AGY" status; "$AGY" models --api --filter nothing-matches-this; } 2>&1)"
  if printf '%s\n' "$api_out" | grep -F -e "$KEY" >/dev/null; then
    echo "FAIL  gemini key leak (key value in status/models --api output)"; fail=$((fail+1))
  elif ! printf '%s\n' "$api_out" | grep -F "gemini api  : key present" >/dev/null; then
    echo "FAIL  gemini key presence line missing from status"; fail=$((fail+1))
  else
    echo "ok    gemini key leak check (present, never printed)"; pass=$((pass+1))
  fi
  if grep -rqF -e "$KEY" "$(dirname "$0")/.." --exclude-dir=.git 2>/dev/null; then
    echo "FAIL  gemini key leak (key value committed in the repo)"; fail=$((fail+1))
  else
    echo "ok    gemini key absent from the repo tree"; pass=$((pass+1))
  fi
else
  echo "skip  gemini key checks (no key in the Keychain)"
fi

# 1d. the API lane must refuse to spend money without an explicit gesture
check "video refuses without --yes"        1 "money"                   -- "$AGY" video "should not run"

# 1e. --file must reject a bad path BEFORE uploading anything (no key, no bytes, no cost)
check "ask --file rejects a missing path"  1 "file not found"          -- "$AGY" ask --file /nope/nope "x"

# 2. ls: lists at least one conversation, tolerates legacy .pb
check "ls lists conversations"             0 "db|pb"                   -- "$AGY" ls

# 2b. quota & catalog & ledger/grants/gc: read-only checks of daemon RPCs and local state
check "quota reads the plan buckets"       0 "plan quota"              -- "$AGY" quota
check "quota renders a reset window"       0 "resets|EXHAUSTED"        -- "$AGY" quota
check "models reads the live catalog"      0 "--model ID"              -- "$AGY" models
check "ledger lists or reports empty"      0 "REQUESTED|ledger is empty" -- "$AGY" ledger
check "grants status is readable"          0 "present"                 -- "$AGY" grants status
check "gc dry-run runs read-only"          0 "dry run:|eligible for gc" -- "$AGY" gc
check "doctor diagnoses read-only"         0 "summary: .* FAIL"        -- "$AGY" doctor

# 3. show: real metadata for the first .db conversation
CID="$(ls "$HOME/.gemini/antigravity/conversations/"*.db 2>/dev/null | head -1 | xargs -I{} basename {} .db)"
if [ -n "$CID" ]; then
  check "show returns real metadata"       0 "metadata"                -- "$AGY" show "$CID"
  # 4. tail: at least one transcript line renders
  check "tail renders transcript"          0 "."                       -- "$AGY" tail "$CID" -n 5
else
  echo "skip  show/tail (no .db conversations)"
fi

# 5. negative: wrong port+token must fail FAST with a clear error, not hang
start=$(date +%s)
AGY_BRIDGE_PORT=1 AGY_BRIDGE_TOKEN=bogus "$AGY" show "${CID:-deadbeef}" >/dev/null 2>&1
rc=$?; elapsed=$(( $(date +%s) - start ))
if [ "$rc" -ne 0 ] && [ "$elapsed" -le 25 ]; then
  echo "ok    negative: wrong port fails fast (exit $rc in ${elapsed}s)"; pass=$((pass+1))
else
  echo "FAIL  negative: wrong port (exit $rc in ${elapsed}s — must be nonzero and fast)"; fail=$((fail+1))
fi

# 6. gates: new/send refuse without --yes (and therefore never reach the daemon)
check "new refuses without --yes"          1 "quota"                   -- "$AGY" new "should not run"
check "send refuses without --yes"         1 "quota"                   -- "$AGY" send someid "should not run"

echo "== $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
