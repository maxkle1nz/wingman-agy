#!/usr/bin/env python3
"""Antigravity lifecycle hook for agy's wingman plugin (stdlib only, Python 3.9+).

Every execution path MUST print exactly one JSON object on stdout and exit 0:
returning {} from PreToolUse is treated as deny, and a silent crash blocks
every conversation on the host.
"""

import fcntl
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

DENY_REASON = "wingman: agents may not modify agy's ledger or Antigravity's configuration"
CMD_DENY_REASON = (
    "wingman: agents may not run agy setup --apply, agy setup --undo, "
    "agy grants enable, or agy ledger adopt"
)
BLOCKED_COMMAND_PHRASES = (
    "agy setup --apply",
    "agy setup --undo",
    "agy grants enable",
    "agy ledger adopt",
)
CONTINUE_REASON = (
    "The previous model call failed with a transport error (for example a stream idle "
    "timeout). Continue the task from where you stopped; do not start over."
)
TRANSPORT_ERR_RE = re.compile(
    r"stream idle timeout|timed out|timeout|unavailable|connection (?:reset|refused|closed|error|aborted)|reset by peer|broken pipe|\bEOF\b|\b50[234]\b"
    # Go socket errors, as the app reports them: "read tcp a:p->b:p: read: can't assign requested address".
    r"|\b(?:read|write|dial) (?:tcp|udp)\b|can't assign requested address|network is unreachable|no route to host|tls handshake",
    re.IGNORECASE,
)
TARGET_SUBSTRS = ("path", "file", "dir", "cwd")


def _neutral(event):
    if event == "PreToolUse":
        return {"decision": "ask"}
    return {}


def _wingman_dir():
    return Path(os.environ.get("WINGMAN_DIR") or "~/.agy/wingman").expanduser()


def _ledger_path():
    return Path(os.environ.get("AGY_LEDGER") or "~/.agy/ledger.jsonl").expanduser()


def _lookup_ledger(cid):
    """Return (in_scope, max_invocations) for cid by reading the ledger under shared flock."""
    p = _ledger_path()
    if not p.is_file():
        return False, None
    seen = False
    deleted = False
    max_invocations = None
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            # Bounded wait: the app kills a hook after its timeout, and a killed PreToolUse
            # hook counts as a deny on EVERY conversation. Writers append whole lines or
            # os.replace the file, so reading without the lock after ~0.5 s is still safe.
            locked = False
            for _ in range(10):
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                    locked = True
                    break
                except OSError:
                    time.sleep(0.05)
            try:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        obj = json.loads(s)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if not isinstance(obj, dict):
                        continue
                    if str(obj.get("conversationId") or "") != cid:
                        continue
                    seen = True
                    ev = obj.get("event")
                    if obj.get("deleted") is True or obj.get("reconciled") is True or ev in ("deleted", "reconciled"):
                        deleted = True
                    if (ev == "dispatched" or "event" not in obj) and "max_invocations" in obj:
                        mi = obj.get("max_invocations")
                        if isinstance(mi, int) and not isinstance(mi, bool):
                            max_invocations = mi
            finally:
                if locked:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except OSError:
        return False, None
    return (seen and not deleted), max_invocations


def _protected_regex():
    home_exp = os.path.expanduser("~").rstrip("/")
    home_real = os.path.realpath(home_exp).rstrip("/") if home_exp else ""
    prefixes = ["~", "$HOME", "${HOME}"]
    for h in (home_exp, home_real):
        if h and h not in prefixes:
            prefixes.append(h)
    prefix_pat = "|".join(re.escape(p) for p in prefixes)
    return re.compile(
        r"(?:^|[\s'\"`;|&><(=,:])(?:" + prefix_pat + r")/(?:\.agy|\.gemini/config)(?=$|[/\s'\"`;|&><),:\\])"
    ), home_exp, home_real


def _iter_strings(val):
    if isinstance(val, str):
        yield val
    elif isinstance(val, (list, tuple)):
        for item in val:
            if isinstance(item, str):
                yield item


def _is_protected_target(args, cwd):
    # Tripwire only (not a security boundary): checks target arguments for references
    # to ~/.agy/ or ~/.gemini/config/ in both ~ and absolute forms.
    if not isinstance(args, dict):
        return False
    prot_re, home_exp, home_real = _protected_regex()
    roots = set()
    for h in (home_exp, home_real):
        if h:
            roots.add(h + "/.agy")
            roots.add(h + "/.gemini/config")

    for k, v in args.items():
        if not isinstance(k, str):
            continue
        kl = k.lower()
        is_cmd = k == "CommandLine"
        is_path_key = any(sub in kl for sub in TARGET_SUBSTRS)
        if not (is_cmd or is_path_key):
            continue
        for s in _iter_strings(v):
            if prot_re.search(s):
                return True
            if is_path_key:
                cand = s.strip().strip("'\"")
                if not cand:
                    continue
                if cand.startswith("$HOME/"):
                    cand = home_exp + cand[len("$HOME"):]
                elif cand.startswith("${HOME}/"):
                    cand = home_exp + cand[len("${HOME}"):]
                elif cand in ("$HOME", "${HOME}"):
                    cand = home_exp
                expanded = os.path.expanduser(cand)
                if not os.path.isabs(expanded) and isinstance(cwd, str) and cwd:
                    expanded = os.path.join(os.path.expanduser(cwd), expanded)
                if os.path.isabs(expanded):
                    norm = os.path.normpath(expanded)
                    real = os.path.realpath(expanded)
                    for check_p in (norm, real):
                        for root in roots:
                            if check_p == root or check_p.startswith(root + "/"):
                                return True
    return False


def _append_event(wdir, cid, event_name, tool_name=None, error_msg=""):
    try:
        wdir.mkdir(parents=True, exist_ok=True)
        rec = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cid": cid[:8],
            "event": event_name,
            "tool": tool_name,
            "error": str(error_msg or "")[:200],
        }
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
        ev_path = wdir / "events.jsonl"
        with open(ev_path, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(line)
                f.flush()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


def _is_blocked_command(args):
    # Tripwire only (not a security boundary): denies CommandLine invocations of
    # interactive setup/grants/adopt commands.
    if not isinstance(args, dict):
        return False
    val = args.get("CommandLine")
    for s in _iter_strings(val):
        norm = " ".join(s.split())
        if any(phrase in norm for phrase in BLOCKED_COMMAND_PHRASES):
            return True
    return False


def _handle_pre_tool_use(payload, cid, in_scope):
    if not in_scope:
        return {"decision": "ask"}
    tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(tc.get("name") or "")
    args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
    if _is_protected_target(args, payload.get("cwd")):
        _append_event(_wingman_dir(), cid, "deny", tool_name=tool_name)
        return {"decision": "deny", "reason": DENY_REASON}
    if _is_blocked_command(args):
        _append_event(_wingman_dir(), cid, "deny", tool_name=tool_name)
        return {"decision": "deny", "reason": CMD_DENY_REASON}
    return {"decision": "allow"}


def _handle_stop(payload, cid, in_scope):
    if not in_scope or payload.get("terminationReason") != "ERROR":
        return {}
    err_raw = str(payload.get("error") or "")
    err_msg = err_raw[:200]
    wdir = _wingman_dir()
    if not TRANSPORT_ERR_RE.search(err_raw):
        _append_event(wdir, cid, "error-not-retried", error_msg=err_msg)
        return {}
    try:
        cap = int(os.environ.get("AGY_WINGMAN_MAX_RETRIES", "3"))
    except (TypeError, ValueError):
        cap = 3
    wdir.mkdir(parents=True, exist_ok=True)
    lock_path = wdir / "state.lock"
    state_path = wdir / "state.json"
    continued = False
    with open(lock_path, "a+", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            state = {}
            if state_path.is_file():
                try:
                    loaded = json.loads(state_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        state = loaded
                except (OSError, json.JSONDecodeError, ValueError):
                    state = {}
            retries = state.get("retries")
            if not isinstance(retries, dict):
                retries = {}
            raw_count = retries.get(cid, 0)
            try:
                count = int(raw_count) if not isinstance(raw_count, bool) else 0
            except (TypeError, ValueError):
                count = 0
            if count < cap:
                retries[cid] = count + 1
                state["retries"] = retries
                tmp = wdir / "state.json.tmp"
                tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
                os.replace(tmp, state_path)
                continued = True
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    if continued:
        _append_event(wdir, cid, "continue", error_msg=err_msg)
        return {"decision": "continue", "reason": CONTINUE_REASON}
    _append_event(wdir, cid, "cap-reached", error_msg=err_msg)
    return {}


def _handle_pre_invocation(payload, cid, in_scope, max_invocations):
    if not in_scope:
        return {}
    if not isinstance(max_invocations, int) or isinstance(max_invocations, bool):
        return {}
    inv_num = payload.get("invocationNum")
    if not isinstance(inv_num, int) or isinstance(inv_num, bool):
        return {}
    if inv_num >= max_invocations:
        _append_event(_wingman_dir(), cid, "terminate", error_msg=str(payload.get("error") or ""))
        return {
            "injectSteps": [
                {
                    "errorMessage": {
                        "userMessage": (
                            f"wingman: this run reached its limit of {max_invocations} "
                            "model calls (set with agy new --max-invocations)"
                        )
                    }
                }
            ],
            "terminationBehavior": "terminate",
        }
    return {}


def _dispatch(event):
    raw = sys.stdin.read()
    if not raw or not raw.strip():
        return _neutral(event)
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return _neutral(event)
    cid = payload.get("conversationId")
    if not isinstance(cid, str) or not cid:
        return _neutral(event)
    in_scope, max_invocations = _lookup_ledger(cid)
    if event == "PreToolUse":
        return _handle_pre_tool_use(payload, cid, in_scope)
    if event == "Stop":
        return _handle_stop(payload, cid, in_scope)
    if event == "PreInvocation":
        return _handle_pre_invocation(payload, cid, in_scope, max_invocations)
    return {}


def main():
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        out = _dispatch(event)
    except Exception:
        out = _neutral(event)
    if not isinstance(out, dict):
        out = _neutral(event)
    sys.stdout.write(json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
