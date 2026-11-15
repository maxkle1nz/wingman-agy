#!/usr/bin/env python3
"""Local checks only: subprocess, network, and credential access are blocked/mocked."""
import argparse
import contextlib
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("agy_offline_test", str(ROOT / "agy"))
spec = importlib.util.spec_from_loader(loader.name, loader)
agy = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = agy
loader.exec_module(agy)


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(agy.subprocess, "run", side_effect=AssertionError("real subprocess forbidden")))
        self.stack.enter_context(patch.object(agy.urllib.request, "urlopen", side_effect=AssertionError("network forbidden")))
        self.stack.enter_context(patch.object(agy, "_api_key", side_effect=AssertionError("credentials forbidden")))
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.wrapper = Path(self.temp) / "agentapi"
        self.server = Path(self.temp) / "language_server"
        self.stack.enter_context(patch.object(agy, "AGENTAPI", self.wrapper))
        self.stack.enter_context(patch.object(agy, "APP_LANGUAGE_SERVER", self.server))
        self.stack.enter_context(patch.object(agy.sys, "platform", "darwin"))

    def executable(self, path):
        path.write_text("not executed\n")
        path.chmod(0o700)

    def test_wrapper_takes_precedence(self):
        self.executable(self.wrapper)
        self.executable(self.server)
        self.assertEqual(agy._agentapi_command(), [str(self.wrapper)])

    def test_mac_app_fallback(self):
        self.executable(self.server)
        self.assertEqual(agy._agentapi_command(), [str(self.server), "agentapi"])

    def test_non_executable_wrapper_uses_app(self):
        self.wrapper.write_text("not executable")
        self.executable(self.server)
        self.assertEqual(agy._agentapi_command(), [str(self.server), "agentapi"])

    def test_directory_is_not_wrapper(self):
        self.wrapper.mkdir()
        self.executable(self.server)
        self.assertEqual(agy._agentapi_command(), [str(self.server), "agentapi"])

    def test_missing_binary_fails_closed(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            agy._agentapi_command()
        self.assertEqual(caught.exception.code, agy.EXIT_NO_DAEMON)

    def test_non_mac_does_not_use_mac_app(self):
        self.executable(self.server)
        with patch.object(agy.sys, "platform", "linux"), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            agy._agentapi_command()
        self.assertEqual(caught.exception.code, agy.EXIT_NO_DAEMON)

    def test_invocation_and_environment(self):
        self.executable(self.server)
        result = subprocess.CompletedProcess([], 0, '{"ok":true}', "")
        with patch.object(agy, "_run", return_value=result) as run:
            raw, kind, error = agy._agentapi(12345, "synthetic-test-token", ["get-conversation-metadata", "synthetic-id"], extra_env={"ANTIGRAVITY_PROJECT_ID": "synthetic-project"})
        self.assertEqual((raw, kind, error), ('{"ok":true}', "ok", None))
        self.assertEqual(run.call_args.args[0], [str(self.server), "agentapi", "get-conversation-metadata", "synthetic-id"])
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["ANTIGRAVITY_LS_ADDRESS"], "127.0.0.1:12345")
        self.assertEqual(env["ANTIGRAVITY_CSRF_TOKEN"], "synthetic-test-token")
        self.assertEqual(env["ANTIGRAVITY_PROJECT_ID"], "synthetic-project")

    def test_transport_timeout_is_sanitized(self):
        self.executable(self.server)
        with patch.object(agy, "_run", side_effect=subprocess.TimeoutExpired("synthetic", 1)):
            raw, kind, error = agy._agentapi(1, "synthetic-test-token", ["get-conversation-metadata", "synthetic-id"], timeout=1)
        self.assertIsNone(raw)
        self.assertEqual(kind, "transport")
        self.assertNotIn("synthetic-test-token", error)

    def test_paid_or_external_operations_refuse_without_yes(self):
        for operation in (agy.cmd_new, agy.cmd_send, agy.cmd_video):
            with self.subTest(operation=operation.__name__), patch.object(agy, "discover", side_effect=AssertionError("discovery forbidden")), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                operation(argparse.Namespace(yes=False, op=""))
            self.assertEqual(caught.exception.code, agy.EXIT_ERR)

    def test_missing_upload_fails_before_credentials_or_network(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            agy._upload_part(str(Path(self.temp) / "does-not-exist.pdf"))
        self.assertEqual(caught.exception.code, agy.EXIT_ERR)

    def test_help_is_offline(self):
        with patch.object(sys, "argv", ["agy", "--help"]), contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
            agy.main()
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("Antigravity", output.getvalue())
        self.assertIn(f"{agy.EXIT_MODEL_MISMATCH}  model mismatch", output.getvalue())
        self.assertIn(f"{agy.EXIT_UNVERIFIED}  dispatched, but the model that ran could not be verified", output.getvalue())

    def test_full_perm_grants_are_added_once_and_keep_existing_ones(self):
        import json
        config = Path(self.temp) / "config.json"
        config.write_text(json.dumps({"userSettings": {"themeMode": "DARK",
                                                       "globalPermissionGrants": {"allow": ["read_file(/x)"]}}}))
        with contextlib.redirect_stderr(io.StringIO()):
            added = agy._ensure_full_perm_grants(config)
            again = agy._ensure_full_perm_grants(config)
        data = json.loads(config.read_text())
        allow = data["userSettings"]["globalPermissionGrants"]["allow"]
        self.assertEqual(added, list(agy.FULL_PERM_GRANTS))
        self.assertEqual(again, [])
        self.assertEqual(allow, ["read_file(/x)", *agy.FULL_PERM_GRANTS])
        self.assertEqual(data["userSettings"]["themeMode"], "DARK")
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def test_full_perm_grants_never_raise_on_a_broken_config(self):
        config = Path(self.temp) / "broken.json"
        config.write_text("{not json")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(agy._ensure_full_perm_grants(config), [])
            self.assertEqual(agy._ensure_full_perm_grants(Path(self.temp) / "missing.json"), [])
        self.assertEqual(config.read_text(), "{not json")


class RpcAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(agy.subprocess, "run", side_effect=AssertionError("real subprocess forbidden")))
        self.urlopen = self.stack.enter_context(patch.object(agy.urllib.request, "urlopen", side_effect=AssertionError("network forbidden")))
        self.discover = self.stack.enter_context(patch.object(agy, "discover", side_effect=AssertionError("discovery forbidden")))
        agy._RPC_PORT.clear()

    def test_allowlist_is_exactly_the_briefed_methods(self):
        self.assertEqual(agy.RPC_ALLOWLIST, {
            "RetrieveUserQuotaSummary", "GetAvailableModels", "GetCascadeModelConfigData",
            "GetAllCascadeTrajectories", "SearchConversations", "GetConversationMetadata",
            "GetCascadeTrajectoryGeneratorMetadata", "DeleteCascadeTrajectory",
            "GetMcpServerStates", "GetAllSkills", "GetAgentScripts"})
        self.assertEqual(len(agy.RPC_ALLOWLIST), 11)
        self.assertNotIn("GetUserStatus", agy.RPC_ALLOWLIST)

    def test_rpc_refuses_delete_all_user_data_before_any_io(self):
        for method in ("DeleteAllUserData", "RunCommand", "deleteallusERDATA", "GetTokenBase",
                       "GetAvailableModels/../DeleteAllUserData", "", "DeleteCascadeTrajectory "):
            with self.subTest(method=method), self.assertRaises(agy.RpcNotAllowed):
                agy._rpc(method, {})
        self.discover.assert_not_called()
        self.urlopen.assert_not_called()

    def test_low_level_call_refuses_too(self):
        with self.assertRaises(agy.RpcNotAllowed):
            agy._connect_call(1, "synthetic-test-token", "DeleteAllUserData", {})
        self.urlopen.assert_not_called()

    def test_allowed_method_posts_to_the_service_with_both_csrf_headers(self):
        seen = []

        class Reply(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout, context):
            seen.append(req)
            return Reply(b'{"response": {"ok": true}}')

        self.urlopen.side_effect = fake_urlopen
        data, kind, _ = agy._connect_call(4242, "synthetic-test-token", "GetAvailableModels", {"a": 1})
        self.assertEqual((data, kind), ({"response": {"ok": True}}, "ok"))
        req = seen[0]
        self.assertEqual(req.full_url, "https://127.0.0.1:4242/exa.language_server_pb.LanguageServerService/GetAvailableModels")
        self.assertEqual(req.get_header("X-csrf-token"), "synthetic-test-token")
        self.assertEqual(req.get_header("X-codeium-csrf-token"), "synthetic-test-token")
        self.assertEqual(req.data, b'{"a": 1}')
        # the quota helper still goes through the same path, to its own method
        agy._quota_rpc(4242, "synthetic-test-token")
        self.assertTrue(seen[1].full_url.endswith("/RetrieveUserQuotaSummary"))

    def test_rpc_probes_tls_siblings_and_skips_transport_failures(self):
        d = agy.Daemon(pid=7, port=100, token="synthetic-test-token", version="t")
        calls = []

        def fake_call(port, token, method, body):
            calls.append(port)
            return (None, "transport", "wrong port") if port == 101 else ({"x": 1}, "ok", "")

        with patch.object(agy, "_listen_ports", return_value=[100, 101, 102]), \
                patch.object(agy, "_connect_call", side_effect=fake_call):
            self.assertEqual(agy._rpc("GetAvailableModels", {}, daemon=d), ({"x": 1}, "ok", ""))
            self.assertEqual(calls, [101, 102])
            agy._rpc("GetAvailableModels", {}, daemon=d)
            self.assertEqual(calls[-1], 102)  # the proven port is tried first next time

    def test_rpc_without_tls_port_reports_instead_of_dying(self):
        d = agy.Daemon(pid=0, port=100, token="synthetic-test-token", version="forced")
        data, kind, detail = agy._rpc("GetAvailableModels", {}, daemon=d)
        self.assertIsNone(data)
        self.assertEqual(kind, "transport")
        self.assertNotIn("synthetic-test-token", detail)


# Shapes as documented in .pilot/ANTIGRAVITY_CAPABILITIES.md section 2 (synthetic values).
AVAILABLE = {"response": {
    "models": {
        "gemini-4-argon-high": {"displayName": "Gemini 4 Argon (High)", "model": "MODEL_PLACEHOLDER_M417",
                                "modelProvider": "MODEL_PROVIDER_GOOGLE"},
        "gemini-4-hydrogen-high": {"displayName": "Gemini 4 Hydrogen (High)", "model": "MODEL_PLACEHOLDER_M525"},
        "claude-opus-5-5-high": {"displayName": "Claude Opus 5.5 (High)", "model": "MODEL_PLACEHOLDER_M402"},
        "gemini-3.8-flash-tiered": {"displayName": "Gemini 3.8 Flash", "model": "MODEL_PLACEHOLDER_M322"},
        "gemini-3.5-flash-lite": {"displayName": "Gemini 3.5 Flash Lite", "model": "MODEL_PLACEHOLDER_M198"},
        "gemini-4-carbon-disabled": {"displayName": "Gemini 4 Carbon", "model": "MODEL_PLACEHOLDER_M670",
                                     "disabled": True},
    },
    "tieredModelIds": {"flashLite": "gemini-3.5-flash-lite", "flash": "gemini-3.8-flash-tiered",
                       "pro": "gemini-3.8-flash-tiered"},
    "defaultAgentModelId": "gemini-4-argon-high"}}
CONFIG = {"clientModelConfigs": [
    {"label": "Gemini 4 Argon (High)", "modelId": "gemini-4-argon-high",
     "quotaInfo": {"remainingFraction": 0.96, "resetTime": "2099-01-01T00:00:00Z"}},
    {"label": "Gemini 4 Hydrogen (High)", "modelId": "gemini-4-hydrogen-high", "quotaInfo": {}},
    {"label": "Claude Opus 5.5 (High)", "modelId": "claude-opus-5-5-high"},
]}


def _create_fake_wingman_copy(wingman_dir: Path, plugins_dir: Path, profile: str = "default",
                              rev: str = "abc1234", daemon_version: str = "t",
                              setup_dir: Path = None, include_skill: bool = True) -> Path:
    import hashlib, json, shutil
    src = ROOT / "plugin" / "wingman"
    copy_dir = wingman_dir / "plugin" / f"{rev}-{profile}"
    copy_dir.mkdir(parents=True, exist_ok=True)
    for fname in ("plugin.json", "hook.sh", "hook.py"):
        shutil.copy2(str(src / fname), str(copy_dir / fname))
    (copy_dir / "hooks.json").write_text(
        json.dumps(agy._wingman_hooks(profile), indent=2) + "\n", encoding="utf-8")
    hashed = ["plugin.json", "hook.sh", "hook.py", "hooks.json"]
    if include_skill:
        skill_dst = copy_dir / "skills" / "agy" / "SKILL.md"
        skill_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(ROOT / "skills" / "agy" / "SKILL.md"), str(skill_dst))
        hashed.append("skills/agy/SKILL.md")
    sha = {
        fname: hashlib.sha256((copy_dir / fname).read_bytes()).hexdigest()
        for fname in hashed
    }
    (copy_dir / "install.json").write_text(json.dumps({
        "rev": rev,
        "profile": profile,
        "daemon_version": daemon_version,
        "installed_at": "2026-11-15T00:00:00Z",
        "sha256": sha,
    }, indent=2) + "\n", encoding="utf-8")
    plugins_dir.mkdir(parents=True, exist_ok=True)
    link = plugins_dir / "wingman"
    if link.is_symlink() or link.is_file():
        link.unlink()
    os.symlink(str(copy_dir), str(link))
    wingman_dir.mkdir(parents=True, exist_ok=True)
    py_file = wingman_dir / "python"
    py_file.write_text(sys.executable + "\n", encoding="utf-8")
    py_file.chmod(0o600)
    if setup_dir is not None:
        run_dir = setup_dir / "20000101T000000Z"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "manifest.json").write_text(json.dumps({
            "version": 1,
            "created": "2026-11-15T00:00:00Z",
            "agy_rev": rev,
            "actions": [{
                "id": "install-plugin",
                "title": "install the wingman plugin and configure its Python runner",
                "applied": True,
                "changes": [
                    {"kind": "dir-created", "path": str(copy_dir)},
                    {"kind": "file-created", "path": str(py_file)},
                    {"kind": "symlink", "path": str(link), "target": str(copy_dir), "old_target": None},
                ],
            }],
            "backups": [],
            "undone": None,
        }, indent=2), encoding="utf-8")
    return copy_dir


def fake_rpc_factory(replies, calls=None):
    """_rpc stand-in: replies maps method -> data, or a callable(body) -> data."""
    def fake(method, body=None, daemon=None):
        if method not in agy.RPC_ALLOWLIST:
            raise agy.RpcNotAllowed(method)
        if calls is not None:
            calls.append((method, body))
        r = replies.get(method)
        if callable(r):
            r = r(body)
        if r is None:
            return None, "transport", "synthetic outage"
        return r, "ok", ""
    return fake


class OfflineBase(unittest.TestCase):
    """Every daemon/network/subprocess path blocked; tests opt into synthetic RPC replies."""
    def setUp(self):
        agy._WINGMAN_SELFTEST_CACHE.clear()
        agy._WINGMAN_HEALTH_CACHE.clear()
        self._real_subprocess_run = subprocess.run
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(agy.subprocess, "run", side_effect=AssertionError("real subprocess forbidden")))
        self.stack.enter_context(patch.object(agy.urllib.request, "urlopen", side_effect=AssertionError("network forbidden")))
        self.stack.enter_context(patch.object(agy, "_api_key", side_effect=AssertionError("credentials forbidden")))
        self.stack.enter_context(patch.object(agy, "_connect_call", side_effect=AssertionError("daemon forbidden")))
        self.stack.enter_context(patch.object(agy.time, "sleep", lambda s: None))
        self.daemon = agy.Daemon(pid=1, port=2, token="synthetic-test-token", version="t")
        self.stack.enter_context(patch.object(agy, "discover", return_value=self.daemon))
        self.temp = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        # Hermetic app binaries: doctor must not depend on whether this host has Antigravity.
        fake_bin = self.temp / "app_bin"
        fake_bin.mkdir()
        for name in ("language_server", "agentapi"):
            (fake_bin / name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (fake_bin / name).chmod(0o755)
        self.stack.enter_context(patch.object(agy, "APP_LANGUAGE_SERVER", fake_bin / "language_server"))
        self.stack.enter_context(patch.object(agy, "AGENTAPI", fake_bin / "agentapi"))
        self.ledger = self.temp / "ledger.jsonl"
        self.consent = self.temp / "consent.json"
        self.gemini_config = self.temp / "config.json"
        self.plugins_dir = self.temp / "plugins"
        self.wingman_dir = self.temp / "wingman"
        self.claude_home = self.temp / "claude_home"
        self.codex_home = self.temp / "codex_home"
        self.stack.enter_context(patch.dict(os.environ, {
            "AGY_LEDGER": str(self.ledger),
            "AGY_BRIDGE_HOME": str(self.temp / "agy_home"),
            "AGY_CONSENT": str(self.consent),
            "AGY_GEMINI_CONFIG": str(self.gemini_config),
            "AGY_PLUGINS_DIR": str(self.plugins_dir),
            "WINGMAN_DIR": str(self.wingman_dir),
            "AGY_CLAUDE_HOME": str(self.claude_home),
            "AGY_CODEX_HOME": str(self.codex_home),
        }))
        for var in agy._AGENT_ENV_VARS:
            os.environ.pop(var, None)
        self.rpc_calls = []

    def use_rpc(self, replies):
        self.stack.enter_context(patch.object(agy, "_rpc", side_effect=fake_rpc_factory(replies, self.rpc_calls)))

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch.object(sys, "argv", ["agy", *argv]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                agy.main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        return code, out.getvalue(), err.getvalue()


class ModelsTests(OfflineBase):
    def test_catalog_merges_both_rpcs(self):
        self.use_rpc({"GetAvailableModels": AVAILABLE, "GetCascadeModelConfigData": CONFIG})
        cat, why = agy._catalog(self.daemon)
        self.assertEqual(why, "")
        self.assertEqual(cat["tiers"], {"flash_lite": "gemini-3.5-flash-lite", "flash": "gemini-3.8-flash-tiered",
                                        "pro": "gemini-3.8-flash-tiered"})
        argon = cat["models"]["gemini-4-argon-high"]
        self.assertTrue(argon["picker"])
        self.assertEqual(argon["quota"]["remainingFraction"], 0.96)
        self.assertFalse(cat["models"]["gemini-3.8-flash-tiered"]["picker"])
        self.assertTrue(cat["models"]["gemini-4-carbon-disabled"]["disabled"])

    def test_catalog_outage_is_reported_not_raised(self):
        self.use_rpc({})
        cat, why = agy._catalog(self.daemon)
        self.assertIsNone(cat)
        self.assertIn("synthetic outage", why)

    def test_models_lists_exact_ids_labels_and_quota(self):
        self.use_rpc({"GetAvailableModels": AVAILABLE, "GetCascadeModelConfigData": CONFIG})
        code, out, _ = self.run_main("models")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"gemini-4-argon-high\s+Gemini 4 Argon \(High\)\s+96% left")
        self.assertIn("claude-opus-5-5-high", out)
        self.assertNotIn("gemini-3.5-flash-lite ", out.split("tiers")[0])  # outside the picker: --all
        self.assertIn("pro -> gemini-3.8-flash-tiered", out)
        code, out, _ = self.run_main("models", "--all")
        self.assertIn("gemini-3.5-flash-lite", out.split("tiers")[0])

    def test_models_api_flag_keeps_the_gemini_api_listing(self):
        with patch.object(agy, "_api_json", return_value={"models": [
                {"name": "models/gemini-x", "inputTokenLimit": 1, "outputTokenLimit": 2,
                 "supportedGenerationMethods": ["generateContent"]}]}) as api:
            code, out, _ = self.run_main("models", "--api")
        self.assertEqual(code, 0)
        api.assert_called_once()
        self.assertIn("gemini-x", out)

    def test_models_reads_family_quota_from_quota_summary(self):
        cfg = {"clientModelConfigs": [
            {"label": "Gemini 4 Argon (High)", "modelId": "gemini-4-argon-high",
             "quotaInfo": {"remainingFraction": 0.96, "resetTime": "2099-01-01T00:00:00Z"}},
            {"label": "Gemini 4 Hydrogen (High)", "modelId": "gemini-4-hydrogen-high", "quotaInfo": {}},
            {"label": "Claude Opus 5.5 (High)", "modelId": "claude-opus-5-5-high",
             "quotaInfo": {"resetTime": "2099-01-01T00:00:00Z"}},
        ]}
        quota = {"response": {"groups": [
            {"displayName": "Gemini Models", "buckets": [
                {"bucketId": "gemini-weekly", "window": "weekly", "remainingFraction": 0.92, "resetTime": "2099-01-07T00:00:00Z"},
                {"bucketId": "gemini-5h", "window": "5h", "remainingFraction": 0.87, "resetTime": "2099-01-01T00:00:00Z"},
            ]},
            {"displayName": "Claude and GPT models", "buckets": [
                {"bucketId": "3p-weekly", "window": "weekly", "remainingFraction": 0.90, "resetTime": "2099-01-07T00:00:00Z"},
                {"bucketId": "3p-5h", "window": "5h", "remainingFraction": 0.75, "resetTime": "2099-01-01T00:00:00Z"},
            ]},
            {"displayName": "Gemini 4 Argon", "buckets": [
                {"bucketId": "gemini-argon-wtu-weekly", "window": "weekly", "remainingFraction": 0.95, "resetTime": "2099-01-07T00:00:00Z"},
            ]},
        ]}}
        self.use_rpc({"GetAvailableModels": AVAILABLE, "GetCascadeModelConfigData": cfg,
                      "RetrieveUserQuotaSummary": quota})
        code, out, _ = self.run_main("models")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"claude-opus-5-5-high\s+Claude Opus 5\.5 \(High\)\s+~75% left.*\(weekly 90%\)")
        self.assertRegex(out, r"gemini-4-hydrogen-high\s+Gemini 4 Hydrogen \(High\)\s+~87% left.*\(weekly 92%\)")
        self.assertRegex(out, r"gemini-4-argon-high\s+Gemini 4 Argon \(High\)\s+~95% left")
        self.assertIn("~ quota inferred from family bucket name heuristics", out)

        # When 5h omits remainingFraction, protobuf zero-omission doctrine means 0% (exhausted),
        # matching `agy quota`.
        quota["response"]["groups"][1]["buckets"] = [
            {"bucketId": "3p-weekly", "window": "weekly", "remainingFraction": 0.48, "resetTime": "2099-01-07T00:00:00Z"},
            {"bucketId": "3p-5h", "window": "5h", "resetTime": "2099-01-01T00:00:00Z"},
        ]
        code, out, _ = self.run_main("models")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"claude-opus-5-5-high\s+Claude Opus 5\.5 \(High\)\s+~0% left.*\(weekly 48%\)")

        with patch.object(agy, "_quota_ports", return_value=[12345]), \
             patch.object(agy, "_quota_rpc", return_value=(quota, "ok", "")):
            code_q, out_q, _ = self.run_main("quota")
        self.assertEqual(code_q, 0)
        self.assertIn("3p-5h", out_q)
        self.assertIn("0.0%", out_q)
        self.assertIn("EXHAUSTED", out_q)

    def test_models_missing_remaining_fraction_means_zero(self):
        cfg = {"clientModelConfigs": [
            {"label": "Gemini 4 Hydrogen (High)", "modelId": "gemini-4-hydrogen-high", "quotaInfo": {}},
            {"label": "Claude Opus 5.5 (High)", "modelId": "claude-opus-5-5-high",
             "quotaInfo": {"resetTime": "2099-01-01T00:00:00Z"}},
            {"label": "Gemini 4 Argon (High)", "modelId": "gemini-4-argon-high",
             "quotaInfo": {"remainingFraction": 0, "resetTime": "2099-01-01T00:00:00Z"}},
        ]}
        self.use_rpc({"GetAvailableModels": AVAILABLE, "GetCascadeModelConfigData": cfg})
        code, out, _ = self.run_main("models")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"(?m)gemini-4-hydrogen-high\s+Gemini 4 Hydrogen \(High\)\s+-$")
        self.assertRegex(out, r"claude-opus-5-5-high\s+Claude Opus 5\.5 \(High\)\s+0% left, resets")
        self.assertNotIn("unknown, resets", out)
        self.assertRegex(out, r"gemini-4-argon-high\s+Gemini 4 Argon \(High\)\s+0% left")
        self.assertNotIn("~ quota inferred", out)


CONV = "11111111-2222-3333-4444-555555555555"
SECRET_PROMPT = "SECRET-PROMPT-TEXT do the thing"


def generator(*models):
    return {"generatorMetadata": [{"chatModel": {"responseModel": rm, "modelDisplayName": dn},
                                   "systemPrompt": "LONG SYSTEM PROMPT"} for rm, dn in models]}


class StrictNewTests(OfflineBase):
    def setUp(self):
        super().setUp()
        self.grants = self.stack.enter_context(patch.object(agy, "_ensure_full_perm_grants", return_value=[]))
        self.agentapi = self.stack.enter_context(patch.object(
            agy, "_agentapi", return_value=(f'{{"response": {{"conversationId": "{CONV}"}}}}', "ok", None)))

    def new(self, *extra, model="gemini-4-hydrogen-high"):
        return self.run_main("new", "--yes", "--project", "synthetic-project", "--title", "t1",
                             "--model", model, *extra, SECRET_PROMPT)

    def catalog(self, ran=None):
        self.use_rpc({"GetAvailableModels": AVAILABLE, "GetCascadeModelConfigData": CONFIG,
                      "GetCascadeTrajectoryGeneratorMetadata": ran})

    def test_exact_id_that_ran_passes(self):
        self.catalog(generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")))
        code, out, err = self.new()
        self.assertEqual(code, 0, err)
        self.assertIn("ran: Gemini 4 Hydrogen (High) (gemini-4-hydrogen-high)", err)
        self.assertIn("--model=gemini-4-hydrogen-high", self.agentapi.call_args.args[2])

    def test_label_match_counts_as_the_same_model(self):
        # proven live: an argon-high pin reports responseModel gemini-4-argon-trial
        self.catalog(generator(("gemini-4-argon-trial", "Gemini 4 Argon (High)")))
        code, _, err = self.new(model="gemini-4-argon-high")
        self.assertEqual(code, 0, err)

    def test_unknown_id_is_refused_before_dispatch(self):
        self.catalog()
        code, _, err = self.new(model="claude-opus-5-5-max")
        self.assertEqual(code, agy.EXIT_ERR)
        self.assertIn("not in the live catalog", err)
        self.assertIn("claude-opus-5-5-high", err)  # suggestion
        self.agentapi.assert_not_called()
        self.grants.assert_not_called()

    def test_disabled_id_is_refused(self):
        self.catalog()
        code, _, err = self.new(model="gemini-4-carbon-disabled")
        self.assertEqual(code, agy.EXIT_ERR)
        self.assertIn("DISABLED", err)
        self.agentapi.assert_not_called()

    def test_allow_fallback_dispatches_and_the_fallback_is_caught(self):
        self.catalog(generator(("gemini-3.8-flash-tiered", "Gemini 3.8 Flash")))
        code, _, err = self.new("--allow-fallback", model="claude-opus-5-5-max")
        self.agentapi.assert_called_once()
        self.assertIn("--allow-fallback", err)
        self.assertIn("MODEL MISMATCH", err)
        self.assertEqual(code, agy.EXIT_MODEL_MISMATCH)
        self.assertNotEqual(agy.EXIT_MODEL_MISMATCH, agy.EXIT_AUTH)
        self.assertEqual(agy.EXIT_MODEL_MISMATCH, 4)

    def test_mismatch_exits_distinct_code_from_auth(self):
        self.catalog(generator(("gemini-3.8-flash-tiered", "Gemini 3.8 Flash")))
        code, _, err = self.new()
        self.assertEqual(code, agy.EXIT_MODEL_MISMATCH)
        self.assertNotEqual(code, agy.EXIT_AUTH)
        self.assertIn("MODEL MISMATCH: requested gemini-4-hydrogen-high", err)
        self.assertIn("ran: Gemini 3.8 Flash (gemini-3.8-flash-tiered)", err)

    def test_only_the_first_response_model_counts(self):
        self.catalog(generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)"),
                               ("gemini-3.5-flash-lite", "Gemini 3.5 Flash Lite")))
        code, _, err = self.new()
        self.assertEqual(code, 0, err)

    def test_tier_warns_with_what_it_really_runs(self):
        self.catalog(generator(("gemini-3.8-flash-tiered", "Gemini 3.8 Flash")))
        code, _, err = self.new(model="pro")
        self.assertEqual(code, 0, err)
        self.assertIn("--model pro is a TIER", err)
        self.assertIn("it runs gemini-3.8-flash-tiered (Gemini 3.8 Flash)", err)

    def test_tier_that_cannot_be_resolved_gets_the_generic_warning(self):
        self.use_rpc({"GetCascadeTrajectoryGeneratorMetadata": generator(("x-model", "X"))})
        code, _, err = self.new(model="flash")
        self.assertEqual(code, 0, err)
        self.assertIn("tier, resolves server-side; usually flash", err)
        self.agentapi.assert_called_once()

    def test_catalog_outage_refuses_without_allow_fallback(self):
        self.use_rpc({"GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "H"))})
        code, _, err = self.new()
        self.assertEqual(code, agy.EXIT_ERR)
        self.assertIn("could not read the live model catalog", err)
        self.assertIn("--allow-fallback", err)
        self.agentapi.assert_not_called()

    def test_catalog_outage_with_allow_fallback_dispatches(self):
        self.use_rpc({"GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "H"))})
        code, _, err = self.new("--allow-fallback")
        self.assertEqual(code, 0, err)
        self.assertIn("could not read the live model catalog", err)
        self.assertIn("--allow-fallback", err)
        self.agentapi.assert_called_once()

    def test_verify_polls_until_a_model_appears(self):
        replies = iter([{}, generator(), generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)"))])
        self.catalog(lambda body: next(replies))
        code, _, err = self.new()
        self.assertEqual(code, 0, err)
        polls = [b for m, b in self.rpc_calls if m == "GetCascadeTrajectoryGeneratorMetadata"]
        self.assertEqual(polls, [{"cascadeId": CONV}] * 3)

    def test_verify_timeout_is_a_warning_not_a_mismatch(self):
        self.catalog(generator())
        code, _, err = self.new("--verify-timeout", "0")
        self.assertEqual(code, agy.EXIT_UNVERIFIED)
        self.assertIn("no model reported within", err)
        entries = agy._read_ledger()
        self.assertEqual(len(entries), 1)
        self.assertIs(entries[0]["verified"], False)

    def test_verify_rpc_error_surfaces_detail_and_exits_unverified(self):
        def app_404(_method, body=None, daemon=None):
            if _method == "GetAvailableModels":
                return AVAILABLE, "ok", ""
            if _method == "GetCascadeModelConfigData":
                return CONFIG, "ok", ""
            return None, "app", "HTTP 404: unimplemented"

        with patch.object(agy, "_rpc", side_effect=app_404):
            code, _, err = self.new()
        self.assertEqual(code, agy.EXIT_UNVERIFIED)
        self.assertIn("HTTP 404: unimplemented", err)
        self.assertNotIn("no model reported within", err)

        def send_err(_method, body=None, daemon=None):
            return None, "transport", "connection refused"

        with patch.object(agy, "_rpc", side_effect=send_err):
            code_s, _, err_s = self.run_main("send", "--yes", CONV, "hello")
        self.assertEqual(code_s, agy.EXIT_UNVERIFIED)
        self.assertIn("connection refused", err_s)

    def test_no_verify_skips_the_check(self):
        def boom(body):
            raise AssertionError("generator metadata must not be polled with --no-verify")
        self.catalog(boom)
        code, _, err = self.new("--no-verify")
        self.assertEqual(code, 0, err)
        self.assertNotIn("GetCascadeTrajectoryGeneratorMetadata", [m for m, _ in self.rpc_calls])

    def test_send_verifies_the_new_turn_only(self):
        replies = iter([generator(("old-model", "Old")),
                        generator(("old-model", "Old"), ("gemini-4-argon-trial", "Gemini 4 Argon (High)"))])
        self.use_rpc({"GetCascadeTrajectoryGeneratorMetadata": lambda body: next(replies)})
        code, _, err = self.run_main("send", "--yes", CONV, "hello")
        self.assertEqual(code, 0, err)
        self.assertIn("ran: Gemini 4 Argon (High) (gemini-4-argon-trial)", err)
        self.assertNotIn("Old", err)

    def test_show_prints_the_distinct_models_that_ran(self):
        conv_dir = self.temp / "conversations"
        conv_dir.mkdir()
        (conv_dir / f"{CONV}.db").write_text("")
        self.stack.enter_context(patch.object(agy, "AGY_HOME", self.temp))
        self.agentapi.return_value = ('{"metadata": {}}', "ok", None)
        self.use_rpc({"GetCascadeTrajectoryGeneratorMetadata": generator(
            ("gemini-3.8-flash-tiered", "Gemini 3.8 Flash"), ("gemini-3.8-flash-tiered", "Gemini 3.8 Flash"),
            ("gemini-3.5-flash-lite", "Gemini 3.5 Flash Lite"))})
        with patch.object(agy, "_steps_ro", return_value=([], 0)):
            code, out, err = self.run_main("show", CONV[:8])
        self.assertEqual(code, 0, err)
        section = out.split("== models that ran ==")[1]
        self.assertIn("Gemini 3.8 Flash (gemini-3.8-flash-tiered)  x2", section)
        self.assertIn("Gemini 3.5 Flash Lite (gemini-3.5-flash-lite)  x1", section)
        self.assertNotIn("LONG SYSTEM PROMPT", out)

    def test_new_extracts_nested_new_conversation_id(self):
        import json
        nested_id = "47574daa-1111-2222-3333-444455556666"
        self.agentapi.return_value = (
            json.dumps({"response": {"newConversation": {
                "prompt": f"ignore {CONV} inside prompt",
                "projectId": "99999999-aaaa-bbbb-cccc-dddddddddddd",
                "conversationId": nested_id,
            }}}),
            "ok",
            None,
        )
        self.catalog(generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")))
        code, _, err = self.new()
        self.assertEqual(code, 0, err)
        polls = [b for m, b in self.rpc_calls if m == "GetCascadeTrajectoryGeneratorMetadata"]
        self.assertEqual(polls, [{"cascadeId": nested_id}])
        self.assertIn(f"follow it:  agy tail {nested_id[:8]} -f", err)
        entries = agy._read_ledger()
        self.assertEqual([e["conversationId"] for e in entries], [nested_id])

    def test_new_extracts_top_level_conversation_and_cascade_ids(self):
        import json
        for key in ("conversationId", "cascadeId"):
            with self.subTest(key=key):
                self.rpc_calls.clear()
                self.agentapi.return_value = (json.dumps({key: CONV}), "ok", None)
                self.catalog(generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")))
                code, _, err = self.new()
                self.assertEqual(code, 0, err)
                polls = [b for m, b in self.rpc_calls if m == "GetCascadeTrajectoryGeneratorMetadata"]
                self.assertEqual(polls, [{"cascadeId": CONV}])

    def test_new_rejects_invalid_or_missing_conversation_id(self):
        for payload in ('{"response": {"newConversation": {"ok": true}}}',
                        '{"response": {"newConversation": {"conversationId": "not-a-uuid"}}}'):
            with self.subTest(payload=payload):
                self.rpc_calls.clear()
                self.agentapi.return_value = (payload, "ok", None)
                self.catalog(generator())
                code, _, err = self.new()
                self.assertEqual(code, agy.EXIT_UNVERIFIED)
                self.assertIn("reply carries no conversationId", err)
                self.assertNotIn("GetCascadeTrajectoryGeneratorMetadata", [m for m, _ in self.rpc_calls])

    def test_send_resolves_a_short_prefix_and_refuses_unknown_ones(self):
        conv_dir = self.temp / "conversations"
        conv_dir.mkdir()
        (conv_dir / f"{CONV}.db").write_text("")
        self.stack.enter_context(patch.object(agy, "AGY_HOME", self.temp))
        self.use_rpc({"GetCascadeTrajectoryGeneratorMetadata": generator(("m", "M"))})
        code, _, err = self.run_main("send", "--yes", "--no-verify", CONV[:8], "hello")
        self.assertEqual(code, 0, err)
        sent_cmd = self.agentapi.call_args[0][2]
        self.assertIn(CONV, sent_cmd)
        self.assertNotIn(CONV[:8], [a for a in sent_cmd if a != CONV])
        self.agentapi.reset_mock()
        code, _, err = self.run_main("send", "--yes", "--no-verify", "deadbeef", "hello")
        self.assertNotEqual(code, 0)
        self.assertIn("no conversation matches", err)
        self.agentapi.assert_not_called()

    def test_send_accepts_nested_and_empty_reply_shapes(self):
        import json
        for reply in (
            json.dumps({"response": {"sendMessage": {"conversationId": CONV}}}),
            "{}",
        ):
            with self.subTest(reply=reply):
                self.agentapi.return_value = (reply, "ok", None)
                replies = iter([generator(("old-model", "Old")),
                                generator(("old-model", "Old"), ("gemini-4-argon-trial", "Gemini 4 Argon (High)"))])
                self.use_rpc({"GetCascadeTrajectoryGeneratorMetadata": lambda body: next(replies)})
                code, _, err = self.run_main("send", "--yes", CONV, "hello")
                self.assertEqual(code, 0, err)
                self.assertIn("ran: Gemini 4 Argon (High) (gemini-4-argon-trial)", err)


class LedgerTests(OfflineBase):
    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch.object(agy, "_ensure_full_perm_grants", return_value=[]))
        self.agentapi = self.stack.enter_context(patch.object(
            agy, "_agentapi", return_value=(f'{{"response": {{"conversationId": "{CONV}"}}}}', "ok", None)))

    def test_new_writes_ledger_without_prompt_or_token(self):
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        code, _, err = self.run_main(
            "new", "--yes", "--project", "proj-1", "--title", "",
            "--model", "gemini-4-hydrogen-high", SECRET_PROMPT,
        )
        self.assertEqual(code, 0, err)
        raw = self.ledger.read_text(encoding="utf-8")
        self.assertNotIn(SECRET_PROMPT, raw)
        self.assertNotIn(self.daemon.token, raw)
        import json
        lines = [json.loads(line) for line in raw.splitlines() if line.strip()]
        self.assertEqual([ln.get("event") for ln in lines], ["dispatched", "verified"])
        self.assertIsNone(lines[0]["ran_model"])
        self.assertEqual(lines[1]["ran_model"], "gemini-4-hydrogen-high")
        entries = agy._read_ledger()
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["conversationId"], CONV)
        self.assertEqual(entry["requested_model"], "gemini-4-hydrogen-high")
        self.assertEqual(entry["ran_model"], "gemini-4-hydrogen-high")
        self.assertEqual(entry["title"], "")
        self.assertEqual(entry["project"], "proj-1")
        self.assertTrue(entry["verified"])

        # agy ledger lists it
        code, out, _ = self.run_main("ledger")
        self.assertEqual(code, 0)
        self.assertIn(CONV[:12], out)
        self.assertIn("gemini-4-hydrogen-high", out)

    def test_new_keep_writes_kept_event_right_after_dispatched(self):
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        code, _, err = self.run_main(
            "new", "--yes", "--keep", "--project", "proj-1", "--title", "kept-at-dispatch",
            "--model", "gemini-4-hydrogen-high", SECRET_PROMPT,
        )
        self.assertEqual(code, 0, err)
        import json
        lines = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual([ln.get("event") for ln in lines], ["dispatched", "kept", "verified"])
        self.assertEqual(lines[1]["reason"], "--keep at dispatch")
        entries = agy._read_ledger()
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["kept"])
        self.assertEqual(entries[0]["keep_reason"], "--keep at dispatch")
        code_l, out_l, err_l = self.run_main("ledger")
        self.assertEqual(code_l, 0, err_l)
        self.assertIn("kept", out_l)

    def test_new_max_invocations_records_and_folds(self):
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        code_bad, _, err_bad = self.run_main(
            "new", "--yes", "--max-invocations", "0", "--project", "proj-1",
            "--model", "gemini-4-hydrogen-high", "hi",
        )
        self.assertEqual(code_bad, 1)
        self.assertIn("--max-invocations", err_bad)

        code, _, err = self.run_main(
            "new", "--yes", "--max-invocations", "7", "--project", "proj-1",
            "--model", "gemini-4-hydrogen-high", "hi",
        )
        self.assertEqual(code, 0, err)
        import json
        lines = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(lines[0]["event"], "dispatched")
        self.assertEqual(lines[0]["max_invocations"], 7)
        entries = agy._read_ledger()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["max_invocations"], 7)

    def test_sandbox_fallback_and_explicit_workspace_here_still_die(self):
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        with patch.object(agy, "_project_for_workspace", return_value=None), \
             patch.dict(os.environ, {
                 "AGY_SANDBOX_WORKSPACE": str(self.temp / "missing-sandbox"),
                 "ANTIGRAVITY_PROJECT_ID": "",
             }):
            code_ws, _, err_ws = self.run_main(
                "new", "--yes", "--workspace", str(self.temp),
                "--model", "gemini-4-hydrogen-high", "hi",
            )
            self.assertEqual(code_ws, agy.EXIT_ERR)
            self.assertIn("projectId", err_ws)

            code_here, _, err_here = self.run_main(
                "new", "--yes", "--here",
                "--model", "gemini-4-hydrogen-high", "hi",
            )
            self.assertEqual(code_here, agy.EXIT_ERR)
            self.assertIn("projectId", err_here)

            code, _, err = self.run_main(
                "new", "--yes", "--model", "gemini-4-hydrogen-high", "hi",
            )
        self.assertEqual(code, 0, err)
        fallback_lines = [ln for ln in err.splitlines() if "outside-of-project" in ln]
        self.assertEqual(len(fallback_lines), 1, err)
        self.assertEqual(self.agentapi.call_args.kwargs["extra_env"]["ANTIGRAVITY_PROJECT_ID"], "outside-of-project")
        entries = agy._read_ledger()
        self.assertEqual(entries[-1]["project"], "outside-of-project")

    def test_exception_during_verification_preserves_dispatched_ledger_entry(self):
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": lambda _b: (_ for _ in ()).throw(RuntimeError("verify crashed")),
        })
        with self.assertRaises(RuntimeError):
            self.run_main(
                "new", "--yes", "--project", "proj-1", "--title", "crash-test",
                "--model", "gemini-4-hydrogen-high", SECRET_PROMPT,
            )
        entries = agy._read_ledger()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["conversationId"], CONV)
        self.assertEqual(entries[0]["event"], "dispatched")
        self.assertEqual(entries[0]["requested_model"], "gemini-4-hydrogen-high")
        self.assertEqual(entries[0]["title"], "crash-test")

    def test_old_format_and_event_lines_fold_together(self):
        import json
        legacy_id = "99999999-0000-0000-0000-000000000001"
        unver_id = "99999999-0000-0000-0000-000000000002"
        del_id = "99999999-0000-0000-0000-000000000003"
        self.ledger.write_text("\n".join([
            json.dumps({"ts": "2026-11-01T00:00:00Z", "conversationId": legacy_id,
                        "requested_model": "gemini-4-argon-high", "ran_model": "gemini-4-argon-high",
                        "title": "Legacy", "project": "p0", "adopted": True}),
            json.dumps({"ts": "2026-11-02T00:00:00Z", "event": "dispatched",
                        "conversationId": unver_id, "requested_model": "gemini-4-hydrogen-high",
                        "ran_model": None, "title": "Unver", "project": "p1"}),
            json.dumps({"ts": "2026-11-02T00:01:00Z", "event": "unverified",
                        "conversationId": unver_id, "ran_model": None}),
            json.dumps({"ts": "2026-11-03T00:00:00Z", "event": "dispatched",
                        "conversationId": del_id, "requested_model": "pro",
                        "ran_model": None, "title": "Del", "project": "p2"}),
            json.dumps({"ts": "2026-11-03T00:02:00Z", "event": "deleted",
                        "conversationId": del_id}),
        ]) + "\n", encoding="utf-8")
        entries = {e["conversationId"]: e for e in agy._read_ledger()}
        self.assertEqual(len(entries), 3)
        self.assertTrue(entries[legacy_id]["adopted"])
        self.assertFalse(entries[legacy_id].get("deleted", False))
        self.assertIs(entries[unver_id]["verified"], False)
        self.assertEqual(entries[unver_id]["ts"], "2026-11-02T00:00:00Z")
        self.assertTrue(entries[del_id]["deleted"])
        code, out, err = self.run_main("ledger")
        self.assertEqual(code, 0, err)
        self.assertIn("adopted", out)
        self.assertIn("unverified", out)
        self.assertIn("deleted", out)

    def test_ledger_writes_take_flock(self):
        import fcntl
        calls = []
        real_flock = fcntl.flock

        def spy_flock(fd, op):
            calls.append(op)
            return real_flock(fd, op)

        with patch.object(agy.fcntl, "flock", side_effect=spy_flock):
            agy._append_ledger({"ts": "2026-11-10T00:00:00Z", "event": "dispatched",
                                "conversationId": CONV, "requested_model": "pro",
                                "ran_model": None, "title": "t", "project": "p"})
            agy._mark_ledger_deleted(CONV)
        self.assertGreaterEqual(calls.count(fcntl.LOCK_EX), 2)
        self.assertGreaterEqual(calls.count(fcntl.LOCK_UN), 2)

    def test_send_uses_ledger_expectation_to_catch_mismatch(self):
        import json
        self.ledger.write_text(json.dumps({
            "ts": "2026-11-10T00:00:00Z", "conversationId": CONV,
            "requested_model": "gemini-4-hydrogen-high", "ran_model": "gemini-4-hydrogen-high",
            "title": "t1", "project": "proj-1",
        }) + "\n", encoding="utf-8")
        replies = iter([
            generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
            generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)"),
                      ("gemini-3.8-flash-tiered", "Gemini 3.8 Flash")),
        ])
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": lambda body: next(replies),
        })
        code, _, err = self.run_main("send", "--yes", CONV, "keep going")
        self.assertEqual(code, agy.EXIT_MODEL_MISMATCH)
        self.assertIn("MODEL MISMATCH: requested gemini-4-hydrogen-high", err)

    def test_ledger_adopt_marks_adopted_and_skips_prompt_and_duplicates(self):
        import json
        conv2 = "22222222-3333-4444-5555-666666666666"
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetAllCascadeTrajectories": {"trajectorySummaries": {
                CONV: {"summary": "Old Hydrogen Run", "status": "CASCADE_RUN_STATUS_IDLE"},
            }},
            "SearchConversations": {"results": [
                {"cascadeId": conv2, "title": "Search Title", "snippet": "SECRET-SNIPPET-DO-NOT-STORE"},
            ]},
            "GetConversationMetadata": lambda body: {
                "conversationMetadata": {"metadata": {
                    "createdAt": "2026-11-08T12:00:00Z",
                    "projectId": "proj-adopted",
                    "staticConfig": {"cascadeConfig": {"plannerConfig": {"planModel": "MODEL_PLACEHOLDER_M525"}}},
                }},
            },
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-3.8-flash-tiered", "Gemini 3.8 Flash")),
        })
        code, out, err = self.run_main("ledger", "adopt", CONV[:8], conv2)
        self.assertEqual(code, 0, err)
        self.assertIn(f"adopted {CONV}", out)
        self.assertIn(f"adopted {conv2}", out)
        raw = self.ledger.read_text(encoding="utf-8")
        self.assertNotIn("SECRET-SNIPPET-DO-NOT-STORE", raw)
        entries = [json.loads(line) for line in raw.splitlines() if line.strip()]
        self.assertEqual(len(entries), 2)
        self.assertTrue(all(e.get("adopted") is True for e in entries))
        self.assertIsNone(entries[0]["requested_model"])
        self.assertEqual(entries[0]["planned_model"], "gemini-4-hydrogen-high")
        self.assertEqual(entries[0]["ran_model"], "gemini-3.8-flash-tiered")
        self.assertEqual(entries[0]["title"], "Old Hydrogen Run")
        self.assertEqual(entries[0]["project"], "proj-adopted")
        self.assertEqual(entries[1]["title"], "Search Title")

        # Readers handle both planned_model and legacy requested_model.
        code_l, out_l, err_l = self.run_main("ledger")
        self.assertEqual(code_l, 0, err_l)
        self.assertIn("plan:gemini-4-hydrogen", out_l)
        req, expected, _ = agy._send_expectation(self.daemon, CONV)
        self.assertEqual(req, "gemini-4-hydrogen-high")
        self.assertEqual(expected, "gemini-4-hydrogen-high")

        # Idempotent on re-adopt
        code, _, err = self.run_main("ledger", "adopt", CONV)
        self.assertEqual(code, 0)
        self.assertIn("already in ledger", err)
        self.assertEqual(len(self.ledger.read_text(encoding="utf-8").splitlines()), 2)

    def test_ledger_keep_unkeep_fold_in_order_and_preserve_unverified(self):
        import json
        legacy_id = "99999999-0000-0000-0000-000000000001"
        unver_id = "88888888-0000-0000-0000-000000000002"
        self.ledger.write_text("\n".join([
            json.dumps({"ts": "2026-11-01T00:00:00Z", "conversationId": legacy_id,
                        "requested_model": "gemini-4-argon-high", "ran_model": "gemini-4-argon-high",
                        "title": "Legacy", "project": "p0"}),
            json.dumps({"ts": "2026-11-02T00:00:00Z", "event": "dispatched",
                        "conversationId": unver_id, "requested_model": "gemini-4-hydrogen-high",
                        "ran_model": None, "title": "Still Running", "project": "p1"}),
        ]) + "\n", encoding="utf-8")

        code, out, err = self.run_main("ledger", "keep", unver_id[:8], "--reason", "first")
        self.assertEqual(code, 0, err)
        self.assertIn("kept", out)
        code, _, err = self.run_main("ledger", "unkeep", unver_id)
        self.assertEqual(code, 0, err)
        code, _, err = self.run_main("ledger", "keep", unver_id[:8], "--reason", "final")
        self.assertEqual(code, 0, err)

        entries = {e["conversationId"]: e for e in agy._read_ledger()}
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[legacy_id]["title"], "Legacy")
        self.assertFalse(entries[legacy_id].get("kept", False))
        self.assertTrue(entries[unver_id]["kept"])
        self.assertEqual(entries[unver_id]["keep_reason"], "final")
        self.assertEqual(entries[unver_id]["event"], "dispatched")

        code_l, out_l, err_l = self.run_main("ledger")
        self.assertEqual(code_l, 0, err_l)
        unver_line = [ln for ln in out_l.splitlines() if unver_id[:12] in ln][0]
        self.assertIn("kept,unverified", unver_line)

        code, _, err = self.run_main("ledger", "unkeep", unver_id[:8])
        self.assertEqual(code, 0, err)
        entries_after = {e["conversationId"]: e for e in agy._read_ledger()}
        self.assertFalse(entries_after[unver_id]["kept"])
        self.assertEqual(entries_after[unver_id]["keep_reason"], "")

    def test_ledger_keep_rejects_bad_ids_and_writes_nothing(self):
        import json
        id1 = "aaaa1111-0000-0000-0000-000000000001"
        id2 = "aaaa1111-0000-0000-0000-000000000002"
        del_id = "dddd0000-0000-0000-0000-000000000003"
        initial = "\n".join([
            json.dumps({"ts": "2026-11-01T00:00:00Z", "event": "dispatched",
                        "conversationId": id1, "requested_model": "pro", "ran_model": None,
                        "title": "One", "project": "p1"}),
            json.dumps({"ts": "2026-11-01T00:00:00Z", "event": "dispatched",
                        "conversationId": id2, "requested_model": "pro", "ran_model": None,
                        "title": "Two", "project": "p1"}),
            json.dumps({"ts": "2026-11-01T00:00:00Z", "event": "dispatched",
                        "conversationId": del_id, "requested_model": "pro", "ran_model": None,
                        "title": "Del", "project": "p1"}),
            json.dumps({"ts": "2026-11-01T00:01:00Z", "event": "deleted",
                        "conversationId": del_id}),
        ]) + "\n"
        self.ledger.write_text(initial, encoding="utf-8")

        bad_calls = [
            ("ledger", "keep", "ffffffff-0000-0000-0000-000000000000"),
            ("ledger", "keep", "aaaa1111"),
            ("ledger", "keep", "aaaa111"),
            ("ledger", "keep", del_id),
            ("ledger", "keep", del_id[:8]),
            ("ledger", "keep", id1, "deadbeef"),
            ("ledger", "unkeep", "aaaa111"),
            ("ledger", "unkeep", del_id),
        ]
        for argv in bad_calls:
            code, _, err = self.run_main(*argv)
            self.assertEqual(code, 1, f"expected exit 1 for {argv}, got {code}: {err}")
            self.assertTrue(err.strip(), f"expected clear error line for {argv}")
            self.assertEqual(self.ledger.read_text(encoding="utf-8"), initial,
                             f"ledger modified on failed call {argv}")


class GcTests(OfflineBase):
    def setUp(self):
        super().setUp()
        self.home = self.temp / "agy_home"
        self.home.mkdir()
        self.stack.enter_context(patch.dict(os.environ, {"AGY_BRIDGE_HOME": str(self.home)}))

    def _seed_brain(self, cid, payload=b"artifact-bytes"):
        bdir = self.home / "brain" / cid
        bdir.mkdir(parents=True, exist_ok=True)
        (bdir / "report.md").write_bytes(payload)
        pdir = self.home / "presence"
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / f"{cid}.lock").write_bytes(b"lock")
        return len(payload) + 4

    def _iso_ago(self, hours=0, days=0):
        from datetime import datetime, timedelta, timezone
        dt = datetime.now(timezone.utc) - timedelta(days=days, hours=hours)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _write_ledger(self, ids_and_titles):
        import json
        lines = []
        for cid, title in ids_and_titles:
            lines.append(json.dumps({
                "ts": "2026-11-01T00:00:00Z", "conversationId": cid,
                "requested_model": "gemini-4-hydrogen-high", "ran_model": "gemini-4-hydrogen-high",
                "title": title, "project": "p1",
            }))
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_gc_candidate_selection_and_dry_run_deletes_nothing(self):
        parent_id = "1111aaaa-1111-0000-0000-000000000001"
        child_id = "2222bbbb-2222-0000-0000-000000000002"
        running_id = "3333cccc-3333-0000-0000-000000000003"
        busy_id = "4444dddd-4444-0000-0000-000000000004"
        canceling_id = "5555eeee-5555-0000-0000-000000000005"
        young_id = "6666ffff-6666-0000-0000-000000000006"
        unknown_id = "7777aaaa-7777-0000-0000-000000000007"
        non_ledger_id = "8888bbbb-8888-0000-0000-000000000008"
        blocked_parent_id = "9999cccc-9999-0000-0000-000000000009"
        active_child_id = "0000dddd-0000-0000-0000-000000000010"

        self._write_ledger([
            (parent_id, "Old Parent"),
            (child_id, "Old Child"),
            (running_id, "Still Running"),
            (busy_id, "Busy"),
            (canceling_id, "Canceling"),
            (young_id, "Too Young"),
            (unknown_id, "Unknown Status"),
            (blocked_parent_id, "Parent Of Running"),
        ])
        for cid in (parent_id, child_id, running_id, non_ledger_id):
            self._seed_brain(cid, b"x" * 100)

        self.use_rpc({
            "GetAllCascadeTrajectories": {"trajectorySummaries": {
                parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5),
                            "trajectoryMetadata": {"nestingDepth": 0}},
                child_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=4),
                           "trajectoryMetadata": {"parentConversationId": parent_id, "nestingDepth": 1}},
                running_id: {"status": "CASCADE_RUN_STATUS_RUNNING", "lastModifiedTime": self._iso_ago(days=10)},
                busy_id: {"status": "CASCADE_RUN_STATUS_BUSY", "lastModifiedTime": self._iso_ago(days=10)},
                canceling_id: {"status": "CASCADE_RUN_STATUS_CANCELING", "lastModifiedTime": self._iso_ago(days=10)},
                young_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(hours=12)},
                non_ledger_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
                blocked_parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
                active_child_id: {"status": "CASCADE_RUN_STATUS_RUNNING", "lastModifiedTime": self._iso_ago(days=1),
                                  "trajectoryMetadata": {"parentConversationId": blocked_parent_id, "nestingDepth": 1}},
            }},
            "SearchConversations": {"results": [
                # No status here: unknown_id must NOT be considered!
                {"cascadeId": unknown_id, "title": "Unknown Status", "lastModifiedTime": self._iso_ago(days=10)},
            ]},
        })

        code, out, err = self.run_main("gc", "--older-than", "3d")
        self.assertEqual(code, 0, err)
        cand_section, skip_section = out.split("\nskipped:", 1)
        # Child appears before parent in dry-run table
        self.assertLess(cand_section.index(child_id[:12]), cand_section.index(parent_id[:12]))
        for excluded in (running_id, busy_id, canceling_id, young_id, unknown_id, non_ledger_id, blocked_parent_id):
            self.assertNotIn(excluded[:12], cand_section)
        self.assertNotIn(non_ledger_id[:12], out)
        self.assertIn("not loaded / status unknown", skip_section)
        self.assertIn(unknown_id[:12], skip_section)
        self.assertIn(blocked_parent_id[:12], skip_section)
        self.assertIn("parent blocked by active descendant", skip_section)
        self.assertIn("dry run", out)
        self.assertNotIn("DeleteCascadeTrajectory", [m for m, _ in self.rpc_calls])
        self.assertTrue((self.home / "brain" / parent_id).exists())
        self.assertTrue((self.home / "brain" / child_id).exists())
        self.assertTrue((self.home / "brain" / non_ledger_id).exists())

        # Shorter age filter picks up young_id (12h old >= 6h)
        code, out2, _ = self.run_main("gc", "--older-than", "6h")
        self.assertEqual(code, 0)
        self.assertIn(young_id[:12], out2)

    def test_gc_yes_deletes_children_first_confirms_relist_then_cleans_disk_and_marks_ledger(self):
        import json
        parent_id = "bbbbbbbb-0000-0000-0000-000000000001"
        child_id = "bbbbbbbb-0000-0000-0000-000000000002"
        other_id = "bbbbbbbb-0000-0000-0000-000000000003"
        self._write_ledger([(parent_id, "Parent"), (child_id, "Child"), (other_id, "Young Keep")])
        freed_child = self._seed_brain(child_id, b"c" * 50)
        freed_parent = self._seed_brain(parent_id, b"p" * 80)

        live = {
            parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5),
                        "trajectoryMetadata": {"nestingDepth": 0}},
            child_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5),
                       "trajectoryMetadata": {"parentConversationId": parent_id, "nestingDepth": 1}},
            other_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(hours=1)},
        }
        events = []

        def fake_traj(_body):
            return {"trajectorySummaries": dict(live)}

        def fake_delete(body):
            cid = body["cascadeId"]
            # Brain directory MUST STILL EXIST at DeleteCascadeTrajectory time (only removed after re-list!)
            self.assertTrue((self.home / "brain" / cid).exists(), f"brain/{cid} removed before re-list!")
            events.append(("delete", cid))
            live.pop(cid, None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": fake_traj,
            "DeleteCascadeTrajectory": fake_delete,
        })

        code, out, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(events, [("delete", child_id), ("delete", parent_id)])
        # Default gc --yes never rmtrees brain/<id>; leftovers are reported and preserved.
        self.assertTrue((self.home / "brain" / child_id).exists())
        self.assertFalse((self.home / "presence" / f"{child_id}.lock").exists())
        self.assertTrue((self.home / "brain" / parent_id).exists())
        self.assertFalse((self.home / "presence" / f"{parent_id}.lock").exists())
        self.assertIn("leftover", out)
        self.assertIn("8 bytes", out)
        self.assertNotIn(f"{freed_child + freed_parent} bytes", out)

        # Ledger preserves lines and marks deleted: true only on deleted ones
        rows = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        by_id = {r["conversationId"]: r for r in rows}
        self.assertEqual(len(rows), 3)
        self.assertTrue(by_id[child_id].get("deleted"))
        self.assertTrue(by_id[parent_id].get("deleted"))
        self.assertFalse(by_id[other_id].get("deleted", False))

    def test_gc_adopts_unledgered_subagents_of_ledger_parents_only(self):
        parent_id = "cccccccc-0000-0000-0000-000000000001"
        sub_id = "cccccccc-0000-0000-0000-000000000002"      # spawned by parent, not in ledger
        grand_id = "cccccccc-0000-0000-0000-000000000003"    # spawned by sub, not in ledger
        stranger_sub = "cccccccc-0000-0000-0000-000000000004"  # child of a NON-ledger conversation
        stranger = "cccccccc-0000-0000-0000-000000000005"
        self._write_ledger([(parent_id, "Parent")])
        live = {
            parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5)},
            sub_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5),
                     "trajectoryMetadata": {"parentConversationId": parent_id, "nestingDepth": 1}},
            grand_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5),
                       "trajectoryMetadata": {"parentConversationId": sub_id, "nestingDepth": 2}},
            stranger: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5)},
            stranger_sub: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5),
                           "trajectoryMetadata": {"parentConversationId": stranger, "nestingDepth": 1}},
        }
        events = []

        def fake_delete(body):
            events.append(body["cascadeId"])
            live.pop(body["cascadeId"], None)
            return {}

        self.use_rpc({"GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
                      "DeleteCascadeTrajectory": fake_delete})
        code, out, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(events, [grand_id, sub_id, parent_id])  # deepest first, owned tree only
        self.assertNotIn(stranger, events)
        self.assertNotIn(stranger_sub, events)

    def test_gc_yes_refuses_disk_cleanup_if_relist_still_shows_id(self):
        import json
        stuck_id = "cccccccc-0000-0000-0000-000000000001"
        self._write_ledger([(stuck_id, "Stuck")])
        self._seed_brain(stuck_id, b"keep-me")

        # DeleteCascadeTrajectory returns {} but GetAllCascadeTrajectories still lists stuck_id!
        self.use_rpc({
            "GetAllCascadeTrajectories": {"trajectorySummaries": {
                stuck_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=6)},
            }},
            "DeleteCascadeTrajectory": {},
        })
        code, _, err = self.run_main("gc", "--yes")
        self.assertNotEqual(code, 0)
        self.assertIn("refusing disk cleanup", err)
        self.assertTrue((self.home / "brain" / stuck_id).exists())
        self.assertTrue((self.home / "presence" / f"{stuck_id}.lock").exists())
        rows = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertFalse(rows[0].get("deleted", False))

    def test_gc_yes_polls_search_lag_until_gone_and_marks_ledger(self):
        import json
        lag_id = "dddddddd-0000-0000-0000-000000000001"
        self._write_ledger([(lag_id, "Search Lag")])
        freed = self._seed_brain(lag_id, b"l" * 60)
        live = {lag_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5)}}
        search_replies = iter([
            {"results": [{"cascadeId": lag_id}]},  # initial _daemon_trajectories
            {"results": [{"cascadeId": lag_id}]},  # confirm poll 1: lag
            {"results": [{"cascadeId": lag_id}]},  # confirm poll 2: lag
            {"results": []},                       # confirm poll 3: gone
        ])

        def fake_delete(body):
            live.pop(body["cascadeId"], None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "SearchConversations": lambda _b: next(search_replies),
            "DeleteCascadeTrajectory": fake_delete,
        })
        code, out, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        search_polls = [m for m, _ in self.rpc_calls if m == "SearchConversations"]
        self.assertEqual(len(search_polls), 4)
        self.assertTrue((self.home / "brain" / lag_id).exists())
        self.assertFalse((self.home / "presence" / f"{lag_id}.lock").exists())
        self.assertIn("leftover", out)
        self.assertIn("4 bytes", out)
        self.assertNotIn(f"{freed} bytes", out)
        rows = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(rows[0].get("deleted"))

    def test_gc_yes_search_confirm_timeout_refuses_cleanup(self):
        import json
        stuck_id = "eeeeeeee-0000-0000-0000-000000000001"
        self._write_ledger([(stuck_id, "Search Stuck")])
        self._seed_brain(stuck_id, b"keep-search")
        live = {stuck_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5)}}
        clock = [0.0]

        def fake_sleep(secs):
            clock[0] += secs

        def fake_delete(body):
            live.pop(body["cascadeId"], None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "SearchConversations": {"results": [{"cascadeId": stuck_id}]},
            "DeleteCascadeTrajectory": fake_delete,
        })
        with patch.object(agy.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(agy.time, "sleep", side_effect=fake_sleep):
            code, _, err = self.run_main("gc", "--yes", "--confirm-timeout", "2")
        self.assertNotEqual(code, 0)
        self.assertIn("refusing disk cleanup", err)
        self.assertIn("SearchConversations", err)
        search_polls = [m for m, _ in self.rpc_calls if m == "SearchConversations"]
        self.assertEqual(len(search_polls), 4)  # initial + polls at t=0, 1, 2
        self.assertTrue((self.home / "brain" / stuck_id).exists())
        self.assertTrue((self.home / "presence" / f"{stuck_id}.lock").exists())
        rows = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertFalse(rows[0].get("deleted", False))

    def test_gc_yes_reports_freed_bytes_when_daemon_removed_brain(self):
        import json
        import shutil
        cid = "ffffffff-0000-0000-0000-000000000001"
        self._write_ledger([(cid, "Daemon Cleaned")])
        expected_freed = self._seed_brain(cid, b"b" * 120)
        live = {cid: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5)}}

        def fake_delete(body):
            target = body["cascadeId"]
            live.pop(target, None)
            # Live daemon deletes brain/<id> itself during DeleteCascadeTrajectory.
            shutil.rmtree(self.home / "brain" / target)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "SearchConversations": {"results": []},
            "DeleteCascadeTrajectory": fake_delete,
        })
        code, out, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        self.assertIn(f"{expected_freed} bytes", out)
        self.assertIn("(removed by the app)", out)
        self.assertFalse((self.home / "brain" / cid).exists())
        self.assertFalse((self.home / "presence" / f"{cid}.lock").exists())
        rows = [json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(rows[0].get("deleted"))

    def test_reconcile_marks_only_fully_absent_ids(self):
        import json
        gone_id = "aaaa0000-0000-0000-0000-000000000001"
        in_traj_id = "aaaa0000-0000-0000-0000-000000000002"
        in_search_id = "aaaa0000-0000-0000-0000-000000000003"
        has_brain_id = "aaaa0000-0000-0000-0000-000000000004"
        gc_gone_id = "aaaa0000-0000-0000-0000-000000000005"
        self._write_ledger([
            (gone_id, "Gone Everywhere"),
            (in_traj_id, "Still In Traj"),
            (in_search_id, "Still In Search"),
            (has_brain_id, "Brain Still On Disk"),
            (gc_gone_id, "Gone For GC"),
        ])
        (self.home / "brain" / has_brain_id).mkdir(parents=True)
        (self.home / "brain" / gc_gone_id).mkdir(parents=True)

        self.use_rpc({
            "GetAllCascadeTrajectories": {"trajectorySummaries": {
                in_traj_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(hours=1)},
            }},
            "SearchConversations": {"results": [
                {"cascadeId": in_search_id, "title": "Still In Search", "lastModifiedTime": self._iso_ago(hours=1)},
            ]},
        })
        code, out, err = self.run_main("ledger", "reconcile")
        self.assertEqual(code, 0, err)
        self.assertIn(gone_id, out)
        for keep in (in_traj_id, in_search_id, has_brain_id, gc_gone_id):
            self.assertNotIn(keep, out)
        rows = {r["conversationId"]: r for r in
                (json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip())}
        self.assertTrue(rows[gone_id].get("deleted"))
        self.assertTrue(rows[gone_id].get("reconciled"))
        for keep in (in_traj_id, in_search_id, has_brain_id, gc_gone_id):
            self.assertFalse(rows[keep].get("deleted", False))
            self.assertFalse(rows[keep].get("reconciled", False))

        # Now remove brain/gc_gone_id and verify `agy gc` (dry run) reconciles it at start.
        (self.home / "brain" / gc_gone_id).rmdir()
        code, out2, err2 = self.run_main("gc")
        self.assertEqual(code, 0, err2)
        self.assertIn(gc_gone_id, out2)
        rows2 = {r["conversationId"]: r for r in
                 (json.loads(line) for line in self.ledger.read_text(encoding="utf-8").splitlines() if line.strip())}
        self.assertTrue(rows2[gc_gone_id].get("deleted"))
        self.assertTrue(rows2[gc_gone_id].get("reconciled"))
        for keep in (in_traj_id, in_search_id, has_brain_id):
            self.assertFalse(rows2[keep].get("deleted", False))

    def test_concurrent_append_during_reconcile_and_gc_is_not_lost(self):
        gone_id = "aaaa1111-0000-0000-0000-000000000001"
        old_id = "aaaa1111-0000-0000-0000-000000000002"
        new_during_reconcile = "aaaa1111-0000-0000-0000-000000000003"
        new_during_gc = "aaaa1111-0000-0000-0000-000000000004"
        self._write_ledger([(gone_id, "Gone"), (old_id, "Old")])
        live = {old_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=5)}}

        def search_with_concurrent_append(_body):
            agy._append_ledger({
                "ts": "2026-11-14T00:00:00Z", "event": "dispatched",
                "conversationId": new_during_reconcile, "requested_model": "gemini-4-hydrogen-high",
                "ran_model": None, "title": "Concurrent Reconcile", "project": "p1",
            })
            return {"results": []}

        self.use_rpc({
            "GetAllCascadeTrajectories": {"trajectorySummaries": live},
            "SearchConversations": search_with_concurrent_append,
        })
        code, _, err = self.run_main("ledger", "reconcile")
        self.assertEqual(code, 0, err)
        by_id = {e["conversationId"]: e for e in agy._read_ledger()}
        self.assertTrue(by_id[gone_id].get("reconciled"))
        self.assertIn(new_during_reconcile, by_id)
        self.assertFalse(by_id[new_during_reconcile].get("deleted", False))

        def delete_with_concurrent_append(body):
            live.pop(body["cascadeId"], None)
            agy._append_ledger({
                "ts": "2026-11-14T00:01:00Z", "event": "dispatched",
                "conversationId": new_during_gc, "requested_model": "gemini-4-hydrogen-high",
                "ran_model": None, "title": "Concurrent GC", "project": "p1",
            })
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "SearchConversations": {"results": []},
            "DeleteCascadeTrajectory": delete_with_concurrent_append,
        })
        code, _, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        by_id2 = {e["conversationId"]: e for e in agy._read_ledger()}
        self.assertTrue(by_id2[old_id].get("deleted"))
        self.assertIn(new_during_reconcile, by_id2)
        self.assertIn(new_during_gc, by_id2)
        self.assertFalse(by_id2[new_during_gc].get("deleted", False))

    def test_gc_skips_starred_and_pinned_conversations(self):
        starred_id = "aaaa1111-0000-0000-0000-000000000001"
        pinned_id = "bbbb2222-0000-0000-0000-000000000002"
        plain_id = "cccc3333-0000-0000-0000-000000000003"
        self._write_ledger([
            (starred_id, "Starred"),
            (pinned_id, "Pinned"),
            (plain_id, "Plain Old"),
        ])
        deleted = []
        live = {
            starred_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                         "annotations": {"starred": True, "title": "Starred"}},
            pinned_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                        "annotations": {"pinned": True, "title": "Pinned"}},
            plain_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
        }

        def fake_delete(b):
            deleted.append(b["cascadeId"])
            live.pop(b["cascadeId"], None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "DeleteCascadeTrajectory": fake_delete,
        })
        code_dry, out_dry, err_dry = self.run_main("gc")
        self.assertEqual(code_dry, 0, err_dry)
        cand_dry, skip_dry = out_dry.split("\nskipped:", 1)
        self.assertIn(plain_id[:12], cand_dry)
        self.assertNotIn(starred_id[:12], cand_dry)
        self.assertNotIn(pinned_id[:12], cand_dry)
        self.assertIn(f"{starred_id[:12]} (Starred) — starred", skip_dry)
        self.assertIn(f"{pinned_id[:12]} (Pinned) — pinned", skip_dry)
        code, out, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(deleted, [plain_id])
        self.assertIn(plain_id[:12], out)

    def test_gc_and_disk_helpers_reject_non_uuid_ids(self):
        for bad in ("../escape", "foo/bar", "not-a-uuid", ""):
            with self.assertRaises(ValueError):
                agy._brain_dir(bad)
            with self.assertRaises(ValueError):
                agy._presence_lock(bad)

        bad_id = "../../escape-attempt"
        good_id = "dddd4444-0000-0000-0000-000000000001"
        self._write_ledger([(bad_id, "Bad Traversal"), (good_id, "Good")])
        deleted = []
        live = {
            bad_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            good_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
        }

        def fake_delete(b):
            deleted.append(b["cascadeId"])
            live.pop(b["cascadeId"], None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "DeleteCascadeTrajectory": fake_delete,
        })
        code, out, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(deleted, [good_id])
        self.assertNotIn("DeleteCascadeTrajectory", [m for m, body in self.rpc_calls if body and body.get("cascadeId") == bad_id])

    def test_gc_adopts_only_real_subagents_and_shows_parent_in_table(self):
        parent_id = "eeee5555-0000-0000-0000-000000000001"
        sub_depth_id = "1111eeee-0000-0000-0000-000000000002"
        sub_spec_id = "2222eeee-0000-0000-0000-000000000003"
        fork_parent_id = "ffff6666-0000-0000-0000-000000000004"
        non_subagent_id = "7777ffff-0000-0000-0000-000000000005"
        self._write_ledger([(parent_id, "Main Agent"), (fork_parent_id, "Forked Parent")])
        live = {
            parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            sub_depth_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                           "annotations": {"title": "Depth Sub"},
                           "trajectoryMetadata": {"parentConversationId": parent_id, "nestingDepth": 1}},
            sub_spec_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                          "annotations": {"title": "Spec Sub"},
                          "trajectoryMetadata": {"parentConversationId": parent_id, "nestingDepth": 0,
                                                 "subagentSpec": {"typeName": "image-generator"}}},
            fork_parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            non_subagent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                              "annotations": {"title": "Regular Child"},
                              "trajectoryMetadata": {"parentConversationId": fork_parent_id, "nestingDepth": 0}},
        }
        deleted = []

        def fake_delete(b):
            deleted.append(b["cascadeId"])
            live.pop(b["cascadeId"], None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "DeleteCascadeTrajectory": fake_delete,
        })
        code_dry, out_dry, err_dry = self.run_main("gc")
        self.assertEqual(code_dry, 0, err_dry)
        cand_dry, skip_dry = out_dry.split("\nskipped:", 1)
        self.assertIn(sub_depth_id[:12], cand_dry)
        self.assertIn(sub_spec_id[:12], cand_dry)
        self.assertIn(f"subagent of {parent_id[:12]}", cand_dry)
        self.assertNotIn(non_subagent_id[:12], cand_dry)
        self.assertIn(fork_parent_id[:12], skip_dry)

        code, _, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        self.assertIn(sub_depth_id, deleted)
        self.assertIn(sub_spec_id, deleted)
        self.assertIn(parent_id, deleted)
        self.assertNotIn(non_subagent_id, deleted)
        self.assertNotIn(fork_parent_id, deleted)

    def test_gc_never_deletes_parent_or_ancestor_of_non_deleted_or_active_descendant(self):
        gp_id = "10101010-0000-0000-0000-000000000001"
        p_id = "20202020-0000-0000-0000-000000000002"
        active_gc_id = "30303030-0000-0000-0000-000000000003"
        young_parent_id = "40404040-0000-0000-0000-000000000004"
        young_child_id = "50505050-0000-0000-0000-000000000005"
        star_parent_id = "60606060-0000-0000-0000-000000000006"
        star_child_id = "70707070-0000-0000-0000-000000000007"
        fail_parent_id = "80808080-0000-0000-0000-000000000008"
        fail_child_id = "90909090-0000-0000-0000-000000000009"
        solo_id = "a0a0a0a0-0000-0000-0000-000000000010"
        self._write_ledger([
            (gp_id, "Grandparent"),
            (young_parent_id, "Parent Of Young"),
            (star_parent_id, "Parent Of Starred"),
            (fail_parent_id, "Parent Of Failing"),
            (solo_id, "Solo Eligible"),
        ])
        live = {
            gp_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            p_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                   "trajectoryMetadata": {"parentConversationId": gp_id, "nestingDepth": 1}},
            active_gc_id: {"status": "CASCADE_RUN_STATUS_RUNNING", "lastModifiedTime": self._iso_ago(days=10),
                           "trajectoryMetadata": {"parentConversationId": p_id, "nestingDepth": 2}},
            young_parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            young_child_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(hours=1),
                             "trajectoryMetadata": {"parentConversationId": young_parent_id, "nestingDepth": 1}},
            star_parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            star_child_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                            "annotations": {"starred": True},
                            "trajectoryMetadata": {"parentConversationId": star_parent_id, "nestingDepth": 1}},
            fail_parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            fail_child_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                            "trajectoryMetadata": {"parentConversationId": fail_parent_id, "nestingDepth": 1}},
            solo_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
        }
        deleted = []

        def fake_delete(b):
            cid = b["cascadeId"]
            if cid == fail_child_id:
                return None  # triggers transport outage in fake_rpc_factory
            deleted.append(cid)
            live.pop(cid, None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "DeleteCascadeTrajectory": fake_delete,
        })
        code_dry, out_dry, err_dry = self.run_main("gc")
        self.assertEqual(code_dry, 0, err_dry)
        cand_dry, skip_dry = out_dry.split("\nskipped:", 1)
        for blocked in (gp_id, p_id, young_parent_id, star_parent_id):
            self.assertNotIn(blocked[:12], cand_dry)
            self.assertIn(blocked[:12], skip_dry)
        self.assertIn(solo_id[:12], cand_dry)

        code, _, err = self.run_main("gc", "--yes")
        self.assertNotEqual(code, 0)
        self.assertIn("skipping parent", err)
        self.assertEqual(deleted, [solo_id])

    def test_gc_reports_skips_and_reasons_even_when_nothing_eligible(self):
        unloaded_id = "11112222-0000-0000-0000-000000000001"
        bad_date_id = "11112222-0000-0000-0000-000000000002"
        starred_id = "11112222-0000-0000-0000-000000000003"
        blocked_id = "11112222-0000-0000-0000-000000000004"
        live_child_id = "11112222-0000-0000-0000-000000000005"
        self._write_ledger([
            (unloaded_id, "Unloaded"),
            (bad_date_id, "Bad Date"),
            (starred_id, "Starred"),
            (blocked_id, "Blocked Parent"),
        ])
        self.use_rpc({
            "GetAllCascadeTrajectories": {"trajectorySummaries": {
                bad_date_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": "not-a-timestamp"},
                starred_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                             "annotations": {"starred": True}},
                blocked_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
                live_child_id: {"status": "CASCADE_RUN_STATUS_RUNNING", "lastModifiedTime": self._iso_ago(hours=1),
                                "trajectoryMetadata": {"parentConversationId": blocked_id, "nestingDepth": 1}},
            }},
            "SearchConversations": {"results": [
                {"cascadeId": unloaded_id, "title": "Unloaded", "lastModifiedTime": self._iso_ago(days=10)},
            ]},
        })
        code, out, err = self.run_main("gc")
        self.assertEqual(code, 0, err)
        self.assertIn("no ledger conversations eligible for gc", out)
        self.assertIn(unloaded_id[:12], out)
        self.assertIn("not loaded / status unknown", out)
        self.assertIn(bad_date_id[:12], out)
        self.assertIn("unparseable date", out)
        self.assertIn(starred_id[:12], out)
        self.assertIn("starred", out)
        self.assertIn(blocked_id[:12], out)
        self.assertIn("parent blocked by active descendant", out)

    def test_gc_yes_revalidates_status_immediately_before_delete(self):
        first_id = "11113333-0000-0000-0000-000000000001"
        parent_id = "22223333-0000-0000-0000-000000000002"
        child_id = "33333333-0000-0000-0000-000000000003"
        self._write_ledger([(first_id, "First"), (parent_id, "Parent")])
        live = {
            first_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            child_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                       "trajectoryMetadata": {"parentConversationId": parent_id, "nestingDepth": 1}},
        }
        deleted = []
        traj_calls = [0]

        def fake_traj(_b):
            traj_calls[0] += 1
            # After initial listing (call 1), child_id becomes RUNNING before its delete re-check!
            if traj_calls[0] >= 2 and child_id in live:
                live[child_id]["status"] = "CASCADE_RUN_STATUS_RUNNING"
            return {"trajectorySummaries": {k: dict(v) for k, v in live.items()}}

        def fake_delete(b):
            cid = b["cascadeId"]
            deleted.append(cid)
            live.pop(cid, None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": fake_traj,
            "DeleteCascadeTrajectory": fake_delete,
        })
        code, _, err = self.run_main("gc", "--yes")
        self.assertNotEqual(code, 0)
        self.assertEqual(deleted, [first_id])
        self.assertIn("status changed to CASCADE_RUN_STATUS_RUNNING", err)
        self.assertIn(f"skipping parent {parent_id}", err)

    def test_gc_skips_kept_entries_and_kept_child_blocks_old_idle_parent(self):
        kept_reason_id = "11114444-0000-0000-0000-000000000001"
        kept_unlisted_id = "22224444-0000-0000-0000-000000000002"
        parent_id = "33334444-0000-0000-0000-000000000003"
        kept_child_id = "44444444-0000-0000-0000-000000000004"
        solo_id = "55554444-0000-0000-0000-000000000005"
        self._write_ledger([
            (kept_reason_id, "Kept With Reason"),
            (kept_unlisted_id, "Kept Unlisted"),
            (parent_id, "Old Idle Parent"),
            (kept_child_id, "Kept Idle Child"),
            (solo_id, "Eligible Solo"),
        ])
        self._seed_brain(kept_unlisted_id)
        self.assertEqual(self.run_main("ledger", "keep", kept_reason_id, "--reason", "hold for audit")[0], 0)
        self.assertEqual(self.run_main("ledger", "keep", kept_unlisted_id)[0], 0)
        self.assertEqual(self.run_main("ledger", "keep", kept_child_id, "--reason", "child keep")[0], 0)

        live = {
            kept_reason_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            parent_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
            kept_child_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10),
                            "trajectoryMetadata": {"parentConversationId": parent_id, "nestingDepth": 1}},
            solo_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": self._iso_ago(days=10)},
        }
        deleted = []

        def fake_delete(b):
            cid = b["cascadeId"]
            deleted.append(cid)
            live.pop(cid, None)
            return {}

        self.use_rpc({
            "GetAllCascadeTrajectories": lambda _b: {"trajectorySummaries": dict(live)},
            "SearchConversations": lambda _b: {"results": [{"cascadeId": cid} for cid in live]},
            "DeleteCascadeTrajectory": fake_delete,
        })
        code_dry, out_dry, err_dry = self.run_main("gc")
        self.assertEqual(code_dry, 0, err_dry)
        cand_dry, skip_dry = out_dry.split("\nskipped:", 1)
        self.assertIn(solo_id[:12], cand_dry)
        for kcid in (kept_reason_id, kept_unlisted_id, kept_child_id, parent_id):
            self.assertNotIn(kcid[:12], cand_dry)
        self.assertIn(f"{kept_reason_id[:12]} (Kept With Reason) — kept in ledger (hold for audit)", skip_dry)
        self.assertIn(f"{kept_unlisted_id[:12]} (Kept Unlisted) — kept in ledger", skip_dry)
        self.assertNotIn("not in daemon listings", skip_dry)
        self.assertIn(f"{kept_child_id[:12]} (Kept Idle Child) — kept in ledger (child keep)", skip_dry)
        self.assertIn(f"{parent_id[:12]} (Old Idle Parent) — parent blocked by non-deleted descendant {kept_child_id[:12]}", skip_dry)

        code, _, err = self.run_main("gc", "--yes")
        self.assertEqual(code, 0, err)
        self.assertEqual(deleted, [solo_id])

    def test_parse_iso_normalizes_nine_digit_fraction_and_z(self):
        from datetime import datetime, timedelta, timezone
        dt9 = agy._parse_iso("2026-11-01T12:34:56.123456789Z")
        self.assertIsNotNone(dt9)
        self.assertEqual(dt9, datetime(2026, 11, 1, 12, 34, 56, 123456, tzinfo=timezone.utc))
        dt1 = agy._parse_iso("2026-11-01T12:34:56.5Z")
        self.assertEqual(dt1, datetime(2026, 11, 1, 12, 34, 56, 500000, tzinfo=timezone.utc))
        dt_off = agy._parse_iso("2026-11-01T12:34:56.987654321-03:00")
        self.assertEqual(dt_off.utcoffset(), timedelta(hours=-3))
        self.assertEqual(dt_off.microsecond, 987654)
        self.assertIsNone(agy._parse_iso("not-a-timestamp"))

        nano_id = "44445555-0000-0000-0000-000000000001"
        self._write_ledger([(nano_id, "Nano Timestamp")])
        old_nano = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")
        self.use_rpc({
            "GetAllCascadeTrajectories": {"trajectorySummaries": {
                nano_id: {"status": "CASCADE_RUN_STATUS_IDLE", "lastModifiedTime": old_nano},
            }},
        })
        code, out, err = self.run_main("gc")
        self.assertEqual(code, 0, err)
        self.assertIn(nano_id[:12], out.split("\ndry run:", 1)[0])

    def test_python_below_3_9_is_refused(self):
        with patch.object(agy.sys, "version_info", (3, 8, 19, "final", 0)):
            code, _, err = self.run_main("--help")
        self.assertEqual(code, 1)
        self.assertIn("Python 3.9+", err)
        self.assertIn("3.8.19", err)


class GrantsConsentTests(OfflineBase):
    def setUp(self):
        super().setUp()
        self.agentapi = self.stack.enter_context(patch.object(
            agy, "_agentapi", return_value=(f'{{"response": {{"conversationId": "{CONV}"}}}}', "ok", None)))

    def test_new_and_send_without_consent_leave_config_byte_identical_and_warn(self):
        import json
        original = json.dumps({"userSettings": {"themeMode": "DARK",
                                                "globalPermissionGrants": {"allow": ["read_file(/x)"]}}}, indent=2)
        self.gemini_config.write_text(original, encoding="utf-8")
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        code, _, err = self.run_main("new", "--yes", "--project", "p1", "--model", "gemini-4-hydrogen-high", "hi")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.gemini_config.read_text(encoding="utf-8"), original)
        self.assertIn("agy grants enable", err)
        self.assertIn("approval prompts", err)

        replies = iter([
            generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
            generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)"),
                      ("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        ])
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": lambda _b: next(replies),
        })
        code_s, _, err_s = self.run_main("send", "--yes", CONV, "ping")
        self.assertEqual(code_s, 0, err_s)
        self.assertEqual(self.gemini_config.read_text(encoding="utf-8"), original)
        self.assertIn("agy grants enable", err_s)

    def test_new_and_send_with_existing_grants_do_not_warn_without_consent(self):
        import json
        original = json.dumps({"userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}}})
        self.gemini_config.write_text(original, encoding="utf-8")
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        code, _, err = self.run_main("new", "--yes", "--project", "p1", "--model", "gemini-4-hydrogen-high", "hi")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.gemini_config.read_text(encoding="utf-8"), original)
        self.assertNotIn("agy grants enable", err)

    def test_check_perm_grants_silent_with_healthy_wingman(self):
        import json
        original = json.dumps({"userSettings": {"globalPermissionGrants": {"allow": []}}})
        self.gemini_config.write_text(original, encoding="utf-8")
        # Default profile does NOT include PreToolUse scoped approvals -> should still warn.
        _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, profile="default")
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        with patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run):
            code_def, _, err_def = self.run_main("new", "--yes", "--project", "p1", "--model", "gemini-4-hydrogen-high", "hi")
            self.assertEqual(code_def, 0, err_def)
            self.assertIn("wildcard grants absent", err_def)

            # Scoped profile IS silent when healthy.
            _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, profile="scoped")
            code, _, err = self.run_main("new", "--yes", "--project", "p1", "--model", "gemini-4-hydrogen-high", "hi")
            self.assertEqual(code, 0, err)
            self.assertEqual(self.gemini_config.read_text(encoding="utf-8"), original)
            self.assertNotIn("agy grants enable", err)
            self.assertNotIn("wildcard grants absent", err)

    def test_grants_status_is_readonly_and_shows_presence(self):
        import json
        original = json.dumps({"userSettings": {"globalPermissionGrants": {
            "allow": ["read_file(*)", "command(*)", "read_file(/custom)"]}}})
        self.gemini_config.write_text(original, encoding="utf-8")
        code, out, err = self.run_main("grants", "status")
        self.assertEqual(code, 0, err)
        self.assertIn("not recorded", out)
        self.assertIn("[x] read_file(*)", out)
        self.assertIn("[x] command(*)", out)
        self.assertIn("[ ] write_file(*)", out)
        self.assertIn("2/6 present", out)
        self.assertEqual(self.gemini_config.read_text(encoding="utf-8"), original)
        self.assertFalse(self.consent.exists())

    def test_grants_enable_refuses_non_tty_with_exit_2(self):
        original = '{"userSettings": {}}'
        self.gemini_config.write_text(original, encoding="utf-8")
        with patch.object(agy.sys.stdin, "isatty", return_value=False):
            code, _, err = self.run_main("grants", "enable")
        self.assertEqual(code, 2)
        self.assertIn("interactive terminal", err)
        self.assertNotIn("human", err)
        self.assertFalse(self.consent.exists())
        self.assertEqual(self.gemini_config.read_text(encoding="utf-8"), original)

    def test_grants_enable_with_tty_backs_up_records_consent_and_adds_grants(self):
        import json
        original = json.dumps({"userSettings": {"themeMode": "LIGHT",
                                                "globalPermissionGrants": {"allow": ["read_file(/keep)"]}}})
        self.gemini_config.write_text(original, encoding="utf-8")
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="n"):
            code_n, _, _ = self.run_main("grants", "enable")
        self.assertNotEqual(code_n, 0)
        self.assertFalse(self.consent.exists())
        self.assertEqual(self.gemini_config.read_text(encoding="utf-8"), original)

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code_y, out_y, err_y = self.run_main("grants", "enable")
        self.assertEqual(code_y, 0, err_y)
        self.assertTrue(self.consent.exists())
        self.assertTrue(agy._has_grants_consent())
        backups = list(self.temp.glob("config.json.bak-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(encoding="utf-8"), original)
        allow = json.loads(self.gemini_config.read_text(encoding="utf-8"))["userSettings"]["globalPermissionGrants"]["allow"]
        self.assertEqual(allow, ["read_file(/keep)", *agy.FULL_PERM_GRANTS])
        self.assertIn("added grants:", out_y)

    def test_grants_disable_removes_only_agy_grants_with_backup(self):
        import json
        self.consent.write_text(json.dumps({"wildcard_grants": True}), encoding="utf-8")
        original = json.dumps({"userSettings": {"themeMode": "DARK", "globalPermissionGrants": {
            "allow": ["read_file(/keep)", *agy.FULL_PERM_GRANTS, "mcp(server:tool)"]}}})
        self.gemini_config.write_text(original, encoding="utf-8")
        code, out, err = self.run_main("grants", "disable")
        self.assertEqual(code, 0, err)
        self.assertFalse(self.consent.exists())
        backups = list(self.temp.glob("config.json.bak-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(encoding="utf-8"), original)
        data = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertEqual(data["userSettings"]["themeMode"], "DARK")
        self.assertEqual(data["userSettings"]["globalPermissionGrants"]["allow"],
                         ["read_file(/keep)", "mcp(server:tool)"])
        self.assertIn("removed grants:", out)

    def test_new_max_invocations_without_healthy_wingman_warns(self):
        import json
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}},
        }), encoding="utf-8")
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        code, _, err = self.run_main(
            "new", "--yes", "--project", "p1", "--model", "gemini-4-hydrogen-high",
            "--max-invocations", "3", "hi",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("--max-invocations has no enforcement", err)

    def test_send_out_of_ledger_not_silenced_by_scoped_wingman(self):
        import json
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": []}},
        }), encoding="utf-8")
        _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, profile="scoped")
        self.use_rpc({
            "GetCascadeTrajectoryGeneratorMetadata": generator(("gemini-4-hydrogen-high", "Gemini 4 Hydrogen (High)")),
        })
        unledgered_cid = "88888888-1111-2222-3333-444444444444"
        ledgered_cid = "77777777-1111-2222-3333-444444444444"
        self.ledger.write_text(json.dumps({
            "conversationId": ledgered_cid, "ts": "2026-11-15T00:00:00Z", "event": "dispatched",
        }) + "\n", encoding="utf-8")
        with patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run):
            c_out, _, e_out = self.run_main("send", "--yes", "--no-verify", unledgered_cid, "hi")
            self.assertEqual(c_out, 0, e_out)
            self.assertIn("wildcard grants absent", e_out)

            c_in, _, e_in = self.run_main("send", "--yes", "--no-verify", ledgered_cid, "hi")
            self.assertEqual(c_in, 0, e_in)
            self.assertNotIn("wildcard grants absent", e_in)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.env = {"HOME": str(self.home), "PATH": "/usr/bin:/bin"}

    def install(self):
        return subprocess.run(["/bin/sh", str(ROOT / "install-codex.sh")],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_install_is_idempotent(self):
        for _ in range(2):
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.home / ".local/bin/agy").resolve(), ROOT / "agy")
        self.assertIn("agy setup --apply", result.stdout)
        self.assertFalse((self.home / ".codex").exists())
        self.assertFalse((self.home / ".claude").exists())
        self.assertFalse((self.home / ".gemini").exists())

    def test_existing_destination_is_preserved(self):
        target = self.home / ".local/bin/agy"
        target.parent.mkdir(parents=True)
        target.write_text("keep me")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), "keep me")
        self.assertFalse((self.home / ".codex").exists())

    def test_install_sh_does_not_symlink_claude_skill_and_preserves_setup_copy(self):
        r1 = subprocess.run(["/bin/sh", str(ROOT / "install.sh")],
                            env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertEqual((self.home / ".local/bin/agy").resolve(), ROOT / "agy")
        self.assertIn("agy setup --apply", r1.stdout)
        self.assertFalse((self.home / ".claude").exists())

        # Simulate agy setup --apply creating ~/.claude/skills/agy/SKILL.md, then re-run install.sh
        skill_dir = self.home / ".claude/skills/agy"
        skill_dir.mkdir(parents=True)
        src = (ROOT / "skills/agy/SKILL.md").read_bytes()
        (skill_dir / "SKILL.md").write_bytes(src)

        r2 = subprocess.run(["/bin/sh", str(ROOT / "install.sh")],
                            env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertFalse(skill_dir.is_symlink())
        self.assertEqual([p.name for p in skill_dir.iterdir()], ["SKILL.md"])
        self.assertEqual((skill_dir / "SKILL.md").read_bytes(), src)


class DoctorTests(OfflineBase):
    def setUp(self):
        super().setUp()
        self.wrapper = self.temp / "agentapi"
        self.server = self.temp / "language_server"
        self.wrapper.write_text("#!/bin/sh\n")
        self.wrapper.chmod(0o700)
        self.server.write_text("#!/bin/sh\n")
        self.server.chmod(0o700)
        self.stack.enter_context(patch.object(agy, "AGENTAPI", self.wrapper))
        self.stack.enter_context(patch.object(agy, "APP_LANGUAGE_SERVER", self.server))
        self.stack.enter_context(patch.object(
            agy, "_run", return_value=subprocess.CompletedProcess([], 0, "abc1234\n", "")))
        self.stack.enter_context(patch.object(agy, "_api_key_present", return_value=False))
        self.sandbox = self.temp / "sandbox"
        self.stack.enter_context(patch.dict(os.environ, {"AGY_SANDBOX_WORKSPACE": str(self.sandbox)}))
        self.quota_ok = {"response": {"groups": [
            {"displayName": "Gemini Models", "buckets": [
                {"bucketId": "gemini-5h", "window": "5h", "remainingFraction": 0.85,
                 "resetTime": "2099-01-01T00:00:00Z"},
            ]},
        ]}}

    def test_doctor_json_summary_matches_checks(self):
        import json
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}},
        }), encoding="utf-8")
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
        })
        code, out, err = self.run_main("doctor", "--json")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        payload = json.loads(out)
        checks = payload["checks"]
        summary = payload["summary"]
        for lvl in agy.DOCTOR_LEVELS:
            self.assertEqual(summary[lvl], sum(1 for c in checks if c["level"] == lvl))
        self.assertEqual(summary["exit"], 0)
        by_name = {(c["section"], c["name"]): c for c in checks}
        self.assertEqual(by_name[("runtime", "python")]["level"], "OK")
        self.assertIn("abc1234", by_name[("runtime", "agy")]["detail"])
        self.assertEqual(by_name[("app", "daemon")]["level"], "OK")
        self.assertNotIn(self.daemon.token, out)
        self.assertEqual(by_name[("models", "catalog")]["level"], "OK")
        self.assertEqual(by_name[("models", "quota")]["level"], "INFO")
        self.assertIn("85.0%", by_name[("models", "quota")]["detail"])
        self.assertEqual(by_name[("permissions", "grants")]["level"], "OK")

    def test_doctor_daemon_down_fails_app_and_skips_dependent_checks(self):
        import json
        self.use_rpc({})
        with patch.object(agy, "discover", side_effect=lambda quiet=False: agy.die("not running", agy.EXIT_NO_DAEMON)):
            code, out, err = self.run_main("doctor", "--json")
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertNotIn("Traceback", out)
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["exit"], 1)
        by_name = {(c["section"], c["name"]): c for c in payload["checks"]}
        self.assertEqual(by_name[("app", "daemon")]["level"], "FAIL")
        self.assertIn("open the Antigravity app", by_name[("app", "daemon")]["fix"])
        for key in (("app", "rpc_canary"), ("models", "catalog"), ("models", "quota"),
                    ("extensions", "mcp_servers"), ("extensions", "mcp_tools"),
                    ("extensions", "skills"), ("extensions", "agent_scripts"),
                    ("extensions", "baseline_context"), ("agents", "antigravity")):
            self.assertEqual(by_name[key]["level"], "SKIP")

    def test_doctor_warns_on_exhausted_quota_and_missing_grants_without_consent(self):
        import json
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": ["read_file(*)"]}},
        }), encoding="utf-8")
        exhausted_quota = {"response": {"groups": [
            {"displayName": "Claude", "buckets": [
                {"bucketId": "3p-5h", "window": "5h", "resetTime": "2099-01-01T00:00:00Z"},
            ]},
        ]}}
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": exhausted_quota,
        })
        code, out, _ = self.run_main("doctor", "--json")
        self.assertEqual(code, 0)
        by_name = {(c["section"], c["name"]): c for c in json.loads(out)["checks"]}
        self.assertEqual(by_name[("models", "quota")]["level"], "WARN")
        self.assertIn("3p-5h", by_name[("models", "quota")]["detail"])
        self.assertEqual(by_name[("permissions", "grants")]["level"], "WARN")
        self.assertIn("agy grants enable", by_name[("permissions", "grants")]["fix"])

    def test_doctor_git_rev_falls_back_to_version_on_error(self):
        import json
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
        })
        with patch.object(agy, "_run", side_effect=OSError("no git")):
            code, out, _ = self.run_main("doctor", "--json")
        self.assertEqual(code, 0)
        by_name = {(c["section"], c["name"]): c for c in json.loads(out)["checks"]}
        # Outside a git checkout (a release install) the rev falls back to the version.
        self.assertIn(f"(rev v{agy.__version__})", by_name[("runtime", "agy")]["detail"])

    def test_doctor_extensions_error_mcp_warns_and_secrets_never_leak(self):
        import json
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}},
            "plugins": {"alpha": {"enabled": True}, "beta": {"enabled": False}},
        }), encoding="utf-8")
        self.ledger.write_text(json.dumps({
            "ts": "2026-11-14T00:00:00Z", "event": "verified",
            "conversationId": CONV, "requested_model": "gemini-4-argon-high",
            "ran_model": "gemini-4-argon-high",
        }) + "\n", encoding="utf-8")
        env_secret = "SECRET-ENV-VALUE-999"
        args_secret = "SECRET-ARGS-VALUE-888"
        cmd_secret = "SECRET-CMD-VALUE-777"
        cwd_secret = "SECRET-CWD-VALUE-666"
        skill_secret = "SECRET-SKILL-CONTENT-555"
        long_err = "E" * 150
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
            "GetMcpServerStates": {"states": [
                {
                    "spec": {
                        "serverName": "healthy-srv",
                        "command": cmd_secret,
                        "args": [args_secret],
                        "env": {"MY_SECRET": env_secret},
                        "cwd": cwd_secret,
                    },
                    "status": "MCP_SERVER_STATUS_READY",
                    "tools": [{"name": "t1", "description": "desc", "jsonSchemaString": "{}", "serverName": "healthy-srv"}],
                },
                {
                    "spec": {"serverName": "broken-srv"},
                    "status": "MCP_SERVER_STATUS_ERROR",
                    "error": long_err,
                    "tools": [],
                },
                {
                    "spec": {"serverName": "leaky-srv", "pluginName": "alpha",
                             "env": {"TOKEN": "SECRET-ERRENV-444"}, "args": ["--key", "SECRET-ERRARG-333"]},
                    "status": "MCP_SERVER_STATUS_ERROR",
                    "error": ("proxy failed for https://h.example/v1?api_key=SECRET-URL-222&x=1 "
                              "env SECRET-ERRENV-444 arg SECRET-ERRARG-333"),
                    "tools": [],
                },
            ]},
            "GetAllSkills": {"skills": [
                {"name": "s1", "description": "first", "content": skill_secret, "pluginName": ""},
                {"name": "s2", "description": "second", "content": skill_secret, "pluginName": "alpha"},
            ]},
            "GetAgentScripts": {"agentScripts": [{"name": "a1"}], "agentCustomizations": [{"name": "c1"}]},
            "GetCascadeTrajectoryGeneratorMetadata": {"generatorMetadata": [
                {"chatModel": {"responseModel": "gemini-4-argon-high", "usage": {"inputTokens": "27742"}}},
            ]},
        })
        for args in (("doctor",), ("doctor", "--json")):
            code, out, err = self.run_main(*args)
            self.assertEqual(code, 0, err)
            for secret in (env_secret, args_secret, cmd_secret, cwd_secret, skill_secret, self.daemon.token,
                           "SECRET-URL-222", "SECRET-ERRENV-444", "SECRET-ERRARG-333"):
                self.assertNotIn(secret, out)
                self.assertNotIn(secret, err)
            self.assertIn("broken-srv", out)
            self.assertIn("27,742", out)
            self.assertIn(CONV[:8], out)
        payload = json.loads(out)
        by_name = {(c["section"], c["name"]): c for c in payload["checks"]}
        self.assertEqual(by_name[("extensions", "plugins")]["level"], "INFO")
        self.assertIn("1 enabled (alpha), 1 disabled (beta)", by_name[("extensions", "plugins")]["detail"])
        self.assertEqual(by_name[("extensions", "mcp:broken-srv")]["level"], "WARN")
        self.assertIn("E" * 120, by_name[("extensions", "mcp:broken-srv")]["detail"])
        self.assertNotIn("E" * 121, by_name[("extensions", "mcp:broken-srv")]["detail"])
        self.assertIn("1 tools", by_name[("extensions", "mcp_tools")]["detail"])
        self.assertIn("builtin:1", by_name[("extensions", "skills")]["detail"])
        self.assertIn("alpha:1", by_name[("extensions", "skills")]["detail"])
        self.assertIn("1 scripts", by_name[("extensions", "agent_scripts")]["detail"])
        self.assertIn(f"measured on {CONV[:8]}", by_name[("extensions", "baseline_context")]["detail"])

    def test_doctor_full_fake_host_all_sections_exit_zero(self):
        import json
        self.sandbox.mkdir()
        rt_dir = self.temp / "m1nd-rt"
        rt_dir.mkdir()
        rt_dir.chmod(0o700)
        ws_dir = self.temp / "m1nd-ws"
        ws_dir.mkdir()
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}},
            "plugins": {"science": {"enabled": True}},
        }), encoding="utf-8")
        (self.temp / "mcp_config.json").write_text(json.dumps({
            "mcpServers": {"m1nd": {"env": {
                "M1ND_WORKSPACE_ROOT": str(ws_dir),
                "M1ND_RUNTIME_DIR": str(rt_dir),
            }}},
        }), encoding="utf-8")
        self.ledger.write_text("\n".join([
            json.dumps({"ts": "2026-11-10T00:00:00Z", "conversationId": CONV, "kept": True}),
            json.dumps({"ts": "2026-11-11T00:00:00Z", "conversationId": "22222222-3333-4444-5555-666666666666",
                        "deleted": True}),
        ]) + "\n", encoding="utf-8")
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
            "GetMcpServerStates": {"states": [
                {"spec": {"serverName": "m1nd", "env": {
                    "M1ND_WORKSPACE_ROOT": str(ws_dir),
                    "M1ND_RUNTIME_DIR": str(rt_dir),
                }}, "status": "MCP_SERVER_STATUS_READY", "tools": []},
            ]},
            "GetAllSkills": {"skills": []},
            "GetAgentScripts": {"agentScripts": [], "agentCustomizations": []},
            "GetCascadeTrajectoryGeneratorMetadata": {"generatorMetadata": [
                {"chatModel": {"usage": {"inputTokens": "12345"}}},
            ]},
        })
        with patch.object(agy, "_api_key_present", return_value=True):
            code, out, err = self.run_main("doctor", "--json")
        self.assertEqual(code, 0, err)
        self.assertNotIn("SECRET-API-KEY-VALUE", out)
        self.assertNotIn(str(rt_dir), out)
        self.assertNotIn(str(ws_dir), out)
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["exit"], 0)
        sections = {c["section"] for c in payload["checks"]}
        self.assertEqual(sections, {
            "runtime", "app", "models", "permissions", "extensions",
            "agents", "workspace", "ledger", "m1nd", "api",
        })
        by_name = {(c["section"], c["name"]): c for c in payload["checks"]}
        self.assertEqual(by_name[("workspace", "sandbox")]["level"], "OK")
        self.assertIn("2 total, 1 active, 1 kept, 1 deleted", by_name[("ledger", "entries")]["detail"])
        self.assertEqual(by_name[("m1nd", "server")]["level"], "OK")
        self.assertEqual(by_name[("m1nd", "env")]["level"], "OK")
        self.assertEqual(by_name[("m1nd", "runtime_dir")]["level"], "OK")
        self.assertEqual(by_name[("api", "gemini_key")]["level"], "OK")

        # Also check human-readable grouped output
        with patch.object(agy, "_api_key_present", return_value=True):
            code_t, out_t, _ = self.run_main("doctor")
        self.assertEqual(code_t, 0)
        self.assertNotIn("SECRET-API-KEY-VALUE", out_t)
        for sec in ("== runtime ==", "== app ==", "== m1nd ==", "== api =="):
            self.assertIn(sec, out_t)

    def test_doctor_is_strictly_readonly_in_empty_temp_dir(self):
        import json
        empty_root = self.temp / "isolated_empty"
        empty_root.mkdir()
        ledger = empty_root / "ledger.jsonl"
        consent = empty_root / "consent.json"
        cfg = empty_root / "config.json"
        sandbox = empty_root / "agy-sandbox"
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
            "GetMcpServerStates": {"states": []},
            "GetAllSkills": {"skills": []},
            "GetAgentScripts": {"agentScripts": [], "agentCustomizations": []},
        })
        env_patch = {
            "HOME": str(empty_root),
            "AGY_LEDGER": str(ledger),
            "AGY_CONSENT": str(consent),
            "AGY_GEMINI_CONFIG": str(cfg),
            "AGY_SANDBOX_WORKSPACE": str(sandbox),
            "AGY_PLUGINS_DIR": str(empty_root / "plugins"),
            "WINGMAN_DIR": str(empty_root / "wingman"),
        }
        with patch.dict(os.environ, env_patch):
            self.assertEqual(list(empty_root.rglob("*")), [])
            code, out, err = self.run_main("doctor", "--json")
            self.assertEqual(code, 0, err)
            self.assertEqual(list(empty_root.rglob("*")), [])
            code2, _, err2 = self.run_main("doctor")
            self.assertEqual(code2, 0, err2)
            self.assertEqual(list(empty_root.rglob("*")), [])
        by_name = {(c["section"], c["name"]): c for c in json.loads(out)["checks"]}
        self.assertEqual(by_name[("ledger", "entries")]["level"], "INFO")
        self.assertIn("no ledger yet", by_name[("ledger", "entries")]["detail"])
        self.assertEqual(by_name[("workspace", "sandbox")]["level"], "INFO")
        self.assertEqual(by_name[("workspace", "sandbox")]["detail"],
                         "missing; agy new falls back to outside-of-project")
        self.assertEqual(by_name[("extensions", "baseline_context")]["detail"], "nothing to measure")

    def test_doctor_m1nd_warns_on_missing_env_and_bad_runtime_dir_mode(self):
        import json
        rt_dir = self.temp / "bad-rt"
        rt_dir.mkdir()
        rt_dir.chmod(0o755)
        (self.temp / "mcp_config.json").write_text(json.dumps({
            "mcpServers": {"m1nd": {"env": {"M1ND_RUNTIME_DIR": str(rt_dir)}}},
        }), encoding="utf-8")
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
            "GetMcpServerStates": {"states": [
                {"spec": {"serverName": "m1nd"}, "status": "MCP_SERVER_STATUS_ERROR", "error": "boom"},
            ]},
            "GetAllSkills": {"skills": []},
            "GetAgentScripts": {"agentScripts": []},
        })
        code, out, _ = self.run_main("doctor", "--json")
        self.assertEqual(code, 0)
        by_name = {(c["section"], c["name"]): c for c in json.loads(out)["checks"]}
        self.assertEqual(by_name[("m1nd", "server")]["level"], "WARN")
        self.assertIn("docs/AGENT-AUTONOMY.md", by_name[("m1nd", "server")]["fix"])
        self.assertEqual(by_name[("m1nd", "env")]["level"], "WARN")
        self.assertIn("M1ND_WORKSPACE_ROOT", by_name[("m1nd", "env")]["detail"])
        self.assertIn("docs/AGENT-AUTONOMY.md", by_name[("m1nd", "env")]["fix"])
        self.assertEqual(by_name[("m1nd", "runtime_dir")]["level"], "WARN")
        self.assertIn("0o755", by_name[("m1nd", "runtime_dir")]["detail"])
        self.assertIn("docs/AGENT-AUTONOMY.md", by_name[("m1nd", "runtime_dir")]["fix"])

    def test_doctor_wingman_check_all_three_states(self):
        import json, shutil
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
        })

        def _wingman_check(extra_args=()):
            code, out, err = self.run_main("doctor", "--json", *extra_args)
            self.assertEqual(code, 0, err)
            by_name = {(c["section"], c["name"]): c for c in json.loads(out)["checks"]}
            return by_name[("permissions", "wingman")]

        def _wingman_text_lines():
            code, out, err = self.run_main("doctor")
            self.assertEqual(code, 0, err)
            return [line for line in out.splitlines() if len(line.split()) >= 2 and line.split()[1] == "wingman"]

        with patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run):
            # 1. Not installed -> INFO (still ends with kill switch)
            c = _wingman_check()
            self.assertEqual(c["level"], "INFO")
            self.assertIn("not installed (agy setup will offer it)", c["detail"])
            self.assertTrue(c["detail"].endswith("disable: rm ~/.gemini/config/plugins/wingman"))
            lines = _wingman_text_lines()
            self.assertTrue(lines and all(l.endswith("disable: rm ~/.gemini/config/plugins/wingman") for l in lines))

            # 2a. Installed, python missing -> WARN with "run agy setup"
            _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, profile="default")
            (self.wingman_dir / "python").unlink()
            c = _wingman_check()
            self.assertEqual(c["level"], "WARN")
            self.assertIn("run agy setup", c["detail"])
            self.assertTrue(c["detail"].endswith("disable: rm ~/.gemini/config/plugins/wingman"))
            lines = _wingman_text_lines()
            self.assertTrue(lines and all(l.endswith("disable: rm ~/.gemini/config/plugins/wingman") for l in lines))

            # 2b. Installed, python ok, disabled in config.json -> WARN
            (self.wingman_dir / "python").write_text(sys.executable + "\n", encoding="utf-8")
            self.gemini_config.write_text(json.dumps({"plugins": {"wingman": {"enabled": False}}}), encoding="utf-8")
            c = _wingman_check()
            self.assertEqual(c["level"], "WARN")
            self.assertIn("run agy setup", c["detail"])
            self.assertTrue(c["detail"].endswith("disable: rm ~/.gemini/config/plugins/wingman"))

            # 2c. Enabled, self-test fails on installed copy (broken hook.sh) -> WARN
            self.gemini_config.write_text(json.dumps({"plugins": {"wingman": {"enabled": True}}}), encoding="utf-8")
            copy_dir = self.wingman_dir / "plugin" / "abc1234-default"
            orig_hook_sh = (copy_dir / "hook.sh").read_bytes()
            (copy_dir / "hook.sh").write_text("#!/bin/sh\necho broken\nexit 1\n", encoding="utf-8")
            (copy_dir / "hook.sh").chmod(0o755)
            agy._WINGMAN_SELFTEST_CACHE.clear()
            c = _wingman_check()
            self.assertEqual(c["level"], "WARN")
            self.assertIn("self-test failed", c["detail"])
            self.assertTrue(c["detail"].endswith("disable: rm ~/.gemini/config/plugins/wingman"))
            (copy_dir / "hook.sh").write_bytes(orig_hook_sh)
            (copy_dir / "hook.sh").chmod(0o755)
            agy._WINGMAN_SELFTEST_CACHE.clear()

            # 2d. Symlink straight into repo / outside $WINGMAN_DIR/plugin -> WARN "unmanaged install; run agy setup"
            outside_dir = self.temp / "repo_wingman"
            outside_dir.mkdir()
            for fname in ("plugin.json", "hook.sh", "hook.py", "hooks.json"):
                shutil.copy2(str(copy_dir / fname), str(outside_dir / fname))
            (outside_dir / "install.json").write_text((copy_dir / "install.json").read_text(), encoding="utf-8")
            link = self.plugins_dir / "wingman"
            link.unlink()
            os.symlink(str(outside_dir), str(link))
            c = _wingman_check()
            self.assertEqual(c["level"], "WARN")
            self.assertIn("unmanaged install; run agy setup", c["detail"])
            self.assertTrue(c["detail"].endswith("disable: rm ~/.gemini/config/plugins/wingman"))

            # Restore managed symlink to abc1234-default
            link.unlink()
            os.symlink(str(copy_dir), str(link))

            # 2e. Running daemon version differs from install.json -> WARN
            ij = json.loads((copy_dir / "install.json").read_text(encoding="utf-8"))
            ij_orig = dict(ij)
            ij["daemon_version"] = "old-ver"
            (copy_dir / "install.json").write_text(json.dumps(ij), encoding="utf-8")
            c = _wingman_check()
            self.assertEqual(c["level"], "WARN")
            self.assertIn("Antigravity updated since wingman was installed; re-run agy setup", c["detail"])
            self.assertTrue(c["detail"].endswith("disable: rm ~/.gemini/config/plugins/wingman"))
            (copy_dir / "install.json").write_text(json.dumps(ij_orig), encoding="utf-8")

            # 2f. Repo rev differs but the plugin bytes are the same -> no update warning
            with patch.object(agy, "_run", return_value=subprocess.CompletedProcess([], 0, "def5678\n", "")):
                c = _wingman_check()
            self.assertNotIn("update available", c["detail"])
            self.assertNotIn("changed since install", c["detail"])

            # 2g. The repo would install different bytes -> WARN "update available: agy setup"
            newer_src = self.temp / "newer_src"
            newer_src.mkdir()
            for fname in ("plugin.json", "hook.sh", "hook.py"):
                shutil.copy2(str(ROOT / "plugin" / "wingman" / fname), str(newer_src / fname))
            with open(newer_src / "hook.py", "a", encoding="utf-8") as fh:
                fh.write("\n# newer hook\n")
            with patch.object(agy, "_wingman_source_dir", return_value=newer_src):
                c = _wingman_check()
            self.assertEqual(c["level"], "WARN")
            self.assertIn("update available: agy setup", c["detail"])
            self.assertTrue(c["detail"].endswith("disable: rm ~/.gemini/config/plugins/wingman"))

            # 2h. The installed copy no longer matches its install.json -> WARN, before "update"
            orig_hook_py = (copy_dir / "hook.py").read_bytes()
            with open(copy_dir / "hook.py", "a", encoding="utf-8") as fh:
                fh.write("\n# edited in place\n")
            agy._WINGMAN_SELFTEST_CACHE.clear()
            c = _wingman_check()
            self.assertEqual(c["level"], "WARN")
            self.assertIn("installed copy changed since install; re-run agy setup", c["detail"])
            self.assertNotIn("update available", c["detail"])
            (copy_dir / "hook.py").write_bytes(orig_hook_py)
            agy._WINGMAN_SELFTEST_CACHE.clear()

            # 3. Healthy with retries in events.jsonl -> OK with rev/profile/daemon + kill switch
            _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, profile="scoped")
            (self.wingman_dir / "events.jsonl").write_text(
                json.dumps({"event": "continue"}) + "\n"
                + json.dumps({"event": "deny"}) + "\n"
                + json.dumps({"event": "continue"}) + "\n",
                encoding="utf-8",
            )
            c = _wingman_check()
            self.assertEqual(c["level"], "OK")
            self.assertIn("rev abc1234", c["detail"])
            self.assertIn("profile scoped", c["detail"])
            self.assertIn("daemon t", c["detail"])
            self.assertIn("2 transport retries so far", c["detail"])
            self.assertTrue(c["detail"].endswith("disable: rm ~/.gemini/config/plugins/wingman"))
            lines = _wingman_text_lines()
            self.assertTrue(lines and all(l.endswith("disable: rm ~/.gemini/config/plugins/wingman") for l in lines))

    def test_wingman_healthy_caches_selftest_per_process(self):
        self._create_calls = 0
        _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, profile="default")
        real_selftest = agy._wingman_selftest
        calls = []

        def counting_selftest(plugin_dir, profile="default", python_exe=None):
            calls.append((str(plugin_dir), profile))
            return real_selftest(plugin_dir, profile=profile, python_exe=python_exe)

        with patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run), \
             patch.object(agy, "_wingman_selftest", side_effect=counting_selftest):
            self.assertTrue(agy._wingman_healthy())
            self.assertTrue(agy._wingman_healthy())
            self.assertEqual(len(calls), 1)

    def test_doctor_agents_section_and_setup_after_summary(self):
        import json
        import shutil
        skill_secret = "SECRET-AGENT-SKILL-CONTENT-987"
        src_bytes = (ROOT / "skills" / "agy" / "SKILL.md").read_bytes()

        # 1. Host homes missing -> no host lines; daemon down -> antigravity SKIP
        self.use_rpc({})
        with patch.object(agy, "discover", side_effect=lambda quiet=False: agy.die("not running", agy.EXIT_NO_DAEMON)):
            c0, o0, _ = self.run_main("doctor", "--json")
        self.assertEqual(c0, 1)
        by0 = {(c["section"], c["name"]): c for c in json.loads(o0)["checks"]}
        self.assertNotIn(("agents", "claude_code"), by0)
        self.assertNotIn(("agents", "codex"), by0)
        self.assertEqual(by0[("agents", "antigravity")]["level"], "SKIP")

        # 2. Claude absent (INFO), Codex symlink (WARN), wingman not installed (INFO)
        self.claude_home.mkdir()
        self.codex_home.mkdir()
        (self.codex_home / "skills").mkdir()
        os.symlink(str(ROOT / "skills" / "agy-codex"), str(self.codex_home / "skills" / "agy"))
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
            "GetMcpServerStates": {"states": []},
            "GetAllSkills": {"skills": [
                {"name": "other", "description": "d", "content": skill_secret, "pluginName": "wingman"},
            ]},
            "GetAgentScripts": {"agentScripts": [], "agentCustomizations": []},
        })
        c1, o1, e1 = self.run_main("doctor", "--json")
        self.assertEqual(c1, 0, e1)
        self.assertNotIn(skill_secret, o1)
        by1 = {(c["section"], c["name"]): c for c in json.loads(o1)["checks"]}
        self.assertEqual(by1[("agents", "claude_code")]["level"], "INFO")
        self.assertEqual(by1[("agents", "claude_code")]["detail"], "agy skill not installed (agy setup will offer it)")
        self.assertEqual(by1[("agents", "codex")]["level"], "WARN")
        self.assertEqual(by1[("agents", "codex")]["detail"], "agy skill outdated")
        self.assertIn("agy setup --apply", by1[("agents", "codex")]["fix"])
        self.assertEqual(by1[("agents", "antigravity")]["level"], "INFO")

        # 3a. Wingman installed WITHOUT skill, skill missing from GetAllSkills -> WARN; outdated host file -> WARN
        _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, profile="default", include_skill=False)
        (self.claude_home / "skills" / "agy").mkdir(parents=True)
        (self.claude_home / "skills" / "agy" / "SKILL.md").write_text("stale", encoding="utf-8")
        with patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run):
            c2, o2, e2 = self.run_main("doctor", "--json")
        self.assertEqual(c2, 0, e2)
        by2 = {(c["section"], c["name"]): c for c in json.loads(o2)["checks"]}
        self.assertEqual(by2[("agents", "claude_code")]["level"], "WARN")
        self.assertEqual(by2[("agents", "claude_code")]["detail"], "agy skill outdated")
        self.assertEqual(by2[("agents", "antigravity")]["level"], "WARN")
        self.assertIn("update wingman: run `agy setup --apply` in a terminal", by2[("agents", "antigravity")]["detail"])

        # 3b. Wingman installed WITH matching skill, GetAllSkills still omits it -> INFO (restart Antigravity)
        (self.plugins_dir / "wingman").unlink()
        shutil.rmtree(self.wingman_dir / "plugin")
        _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, profile="default", include_skill=True)
        with patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run):
            c2b, o2b, e2b = self.run_main("doctor", "--json")
        self.assertEqual(c2b, 0, e2b)
        by2b = {(c["section"], c["name"]): c for c in json.loads(o2b)["checks"]}
        self.assertEqual(by2b[("agents", "antigravity")]["level"], "INFO")
        self.assertIn("restart Antigravity", by2b[("agents", "antigravity")]["detail"])

        # 4. Both hosts current (OK) and GetAllSkills lists agy under wingman (OK); content secret never leaks
        (self.claude_home / "skills" / "agy" / "SKILL.md").write_bytes(src_bytes)
        (self.codex_home / "skills" / "agy").unlink()
        (self.codex_home / "skills" / "agy").mkdir()
        (self.codex_home / "skills" / "agy" / "SKILL.md").write_bytes(src_bytes)
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
            "GetMcpServerStates": {"states": []},
            "GetAllSkills": {"skills": [
                {"name": "agy", "description": "agy skill", "content": skill_secret, "pluginName": "wingman"},
            ]},
            "GetAgentScripts": {"agentScripts": [], "agentCustomizations": []},
        })
        with patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run):
            c3, o3, e3 = self.run_main("doctor", "--json")
            c3t, o3t, e3t = self.run_main("doctor")
        self.assertEqual(c3, 0, e3)
        self.assertEqual(c3t, 0, e3t)
        for text in (o3, o3t):
            self.assertNotIn(skill_secret, text)
        self.assertIn("== agents ==", o3t)
        by3 = {(c["section"], c["name"]): c for c in json.loads(o3)["checks"]}
        self.assertEqual(by3[("agents", "claude_code")]["level"], "OK")
        self.assertEqual(by3[("agents", "claude_code")]["detail"], "agy skill installed (current)")
        self.assertEqual(by3[("agents", "codex")]["level"], "OK")
        self.assertEqual(by3[("agents", "codex")]["detail"], "agy skill installed (current)")
        self.assertEqual(by3[("agents", "antigravity")]["level"], "OK")
        self.assertEqual(by3[("agents", "antigravity")]["detail"], "Antigravity agents see the agy skill (via wingman)")

        # 5. Setup "after" summary includes the agents lines
        (self.claude_home / "skills" / "agy" / "SKILL.md").unlink()
        (self.claude_home / "skills" / "agy").rmdir()
        with patch.object(agy, "_api_key_present", return_value=True), \
             patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            sc, so, se = self.run_main("setup", "--apply")
        self.assertEqual(sc, 0, se)
        self.assertNotIn(skill_secret, so)
        self.assertIn("== after ==", so)
        after_block = so.split("== after ==", 1)[1]
        self.assertIn("claude_code", after_block)
        self.assertIn("codex", after_block)
        self.assertIn("antigravity", after_block)
        self.assertIn("Antigravity agents see the agy skill (via wingman)", after_block)

    def test_doctor_and_plan_handle_ds_store_tmp_orphans_symlinked_skills_dir_and_missing_source(self):
        import json
        src_bytes = (ROOT / "skills" / "agy" / "SKILL.md").read_bytes()
        self.use_rpc({
            "GetAvailableModels": AVAILABLE,
            "GetCascadeModelConfigData": CONFIG,
            "RetrieveUserQuotaSummary": self.quota_ok,
            "GetMcpServerStates": {"states": []},
            "GetAllSkills": {"skills": []},
            "GetAgentScripts": {"agentScripts": [], "agentCustomizations": []},
        })

        # 1. Identical SKILL.md + .DS_Store + orphan SKILL.md.agy-tmp-* -> OK in doctor and not offered in setup
        claude_skill_dir = self.claude_home / "skills" / "agy"
        claude_skill_dir.mkdir(parents=True)
        (claude_skill_dir / "SKILL.md").write_bytes(src_bytes)
        (claude_skill_dir / ".DS_Store").write_bytes(b"finder")
        orphan = claude_skill_dir / "SKILL.md.agy-tmp-12345"
        orphan.write_bytes(b"partial")

        # Codex has SKILL.md + another real file -> WARN in doctor WITHOUT "setup --apply", refused in setup
        codex_skill_dir = self.codex_home / "skills" / "agy"
        codex_skill_dir.mkdir(parents=True)
        (codex_skill_dir / "SKILL.md").write_text("old", encoding="utf-8")
        (codex_skill_dir / "notes.md").write_text("keep", encoding="utf-8")

        c0, o0, e0 = self.run_main("doctor", "--json")
        self.assertEqual(c0, 0, e0)
        by0 = {(c["section"], c["name"]): c for c in json.loads(o0)["checks"]}
        self.assertEqual(by0[("agents", "claude_code")]["level"], "OK")
        self.assertEqual(by0[("agents", "codex")]["level"], "WARN")
        self.assertNotIn("setup --apply", by0[("agents", "codex")].get("fix") or "")
        self.assertNotIn("setup --apply", by0[("agents", "codex")].get("detail") or "")

        actions0, _notes0, refusals0 = agy._setup_plan()
        action_ids0 = [a["id"] for a in actions0]
        self.assertNotIn("teach-claude-code", action_ids0)
        self.assertNotIn("teach-codex", action_ids0)
        self.assertTrue(any("teach-codex" in r for r in refusals0), refusals0)
        self.assertTrue(orphan.exists())  # read-only checks do not clean orphans

        # 2. Missing skill source -> doctor emits INFO "cannot verify (agy skill source not found)" without "run setup"
        missing_src = self.temp / "no-such-SKILL.md"
        with patch.object(agy, "_agy_skill_source", return_value=missing_src):
            c1, o1, e1 = self.run_main("doctor", "--json")
        self.assertEqual(c1, 0, e1)
        by1 = {(c["section"], c["name"]): c for c in json.loads(o1)["checks"]}
        self.assertEqual(by1[("agents", "claude_code")]["level"], "INFO")
        self.assertEqual(by1[("agents", "claude_code")]["detail"], "cannot verify (agy skill source not found)")
        self.assertEqual(by1[("agents", "claude_code")].get("fix") or "", "")

        # 3. Symlinked skills/ parent dir -> refused in plan, WARN in doctor without "setup --apply", nothing written through it
        outside = self.temp / "elsewhere"
        outside.mkdir()
        (codex_skill_dir / "SKILL.md").unlink()
        (codex_skill_dir / "notes.md").unlink()
        codex_skill_dir.rmdir()
        (self.codex_home / "skills").rmdir()
        os.symlink(str(outside), str(self.codex_home / "skills"))

        actions2, _notes2, refusals2 = agy._setup_plan()
        self.assertNotIn("teach-codex", [a["id"] for a in actions2])
        self.assertTrue(any("teach-codex" in r and "symlink" in r for r in refusals2), refusals2)
        c2, o2, e2 = self.run_main("doctor", "--json")
        self.assertEqual(c2, 0, e2)
        by2 = {(c["section"], c["name"]): c for c in json.loads(o2)["checks"]}
        self.assertEqual(by2[("agents", "codex")]["level"], "WARN")
        self.assertIn("symlink", by2[("agents", "codex")]["detail"])
        self.assertNotIn("setup --apply", by2[("agents", "codex")].get("fix") or "")
        self.assertEqual(list(outside.iterdir()), [])

        # 4. Orphan SKILL.md.agy-tmp-* is ignored in plan/doctor (stale SKILL.md -> differs) and cleaned during apply
        (claude_skill_dir / "SKILL.md").write_text("stale", encoding="utf-8")
        actions3, _notes3, _refusals3 = agy._setup_plan()
        self.assertIn("teach-claude-code", [a["id"] for a in actions3])
        c3, o3, e3 = self.run_main("doctor", "--json")
        self.assertEqual(c3, 0, e3)
        by3 = {(c["section"], c["name"]): c for c in json.loads(o3)["checks"]}
        self.assertEqual(by3[("agents", "claude_code")]["level"], "WARN")
        self.assertEqual(by3[("agents", "claude_code")]["detail"], "agy skill outdated")
        self.assertTrue(orphan.exists())

        with patch.object(agy, "_api_key_present", return_value=True), \
             patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            sc, _so, se = self.run_main("setup", "--apply")
        self.assertEqual(sc, 0, se)
        self.assertFalse(orphan.exists())
        self.assertTrue((claude_skill_dir / ".DS_Store").exists())
        self.assertEqual((claude_skill_dir / "SKILL.md").read_bytes(), src_bytes)


class WingmanHookTests(unittest.TestCase):
    PLUGIN_DIR = ROOT / "plugin" / "wingman"
    HOOK_PY = PLUGIN_DIR / "hook.py"
    HOOK_SH = PLUGIN_DIR / "hook.sh"
    CID = "11111111-2222-3333-4444-555555555555"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp = Path(self.temp_dir.name)
        self.wingman_dir = self.temp / "wingman"
        self.wingman_dir.mkdir()
        self.ledger = self.temp / "ledger.jsonl"
        self.env = os.environ.copy()
        self.env["WINGMAN_DIR"] = str(self.wingman_dir)
        self.env["AGY_LEDGER"] = str(self.ledger)
        self.env.pop("AGY_WINGMAN_MAX_RETRIES", None)

    def _write_dispatched(self, cid=None, max_invocations=None, extra=None):
        import json
        row = {
            "ts": "2026-11-15T00:00:00Z",
            "event": "dispatched",
            "conversationId": cid or self.CID,
            "requested_model": "flash_lite",
        }
        if max_invocations is not None:
            row["max_invocations"] = max_invocations
        if extra:
            row.update(extra)
        with open(self.ledger, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")

    def _run_hook(self, script, event, stdin_text, env=None):
        import json
        proc = subprocess.run(
            [str(script), event] if script == self.HOOK_SH else [sys.executable, str(script), event],
            input=stdin_text,
            text=True,
            capture_output=True,
            cwd=str(self.PLUGIN_DIR),
            env=env or self.env,
            timeout=5,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = proc.stdout.splitlines()
        self.assertEqual(len(lines), 1, f"expected 1 JSON line, got {proc.stdout!r}")
        return json.loads(lines[0])

    # --- failure paths first ---

    def test_failure_paths_return_exact_neutral_json(self):
        import json
        for raw in ("not json at all", "", "   \n", "[]", '"hello"', "null"):
            self.assertEqual(self._run_hook(self.HOOK_PY, "PreToolUse", raw), {"decision": "ask"})
            self.assertEqual(self._run_hook(self.HOOK_PY, "Stop", raw), {})
            self.assertEqual(self._run_hook(self.HOOK_PY, "PreInvocation", raw), {})

        # Missing ledger -> neutral
        payload = json.dumps({"conversationId": self.CID, "toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}}})
        self.assertEqual(self._run_hook(self.HOOK_PY, "PreToolUse", payload), {"decision": "ask"})
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "Stop", json.dumps({"conversationId": self.CID, "terminationReason": "ERROR"})),
            {},
        )

        # Deleted and reconciled entries -> out of scope (neutral)
        self._write_dispatched(self.CID)
        with open(self.ledger, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": "2026-11-15T00:01:00Z", "event": "deleted", "conversationId": self.CID}) + "\n")
        self.assertEqual(self._run_hook(self.HOOK_PY, "PreToolUse", payload), {"decision": "ask"})

        cid_rec = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        self._write_dispatched(cid_rec)
        with open(self.ledger, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": "2026-11-15T00:01:00Z", "event": "reconciled", "conversationId": cid_rec}) + "\n")
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "PreToolUse", json.dumps({"conversationId": cid_rec, "toolCall": {"name": "read_file", "args": {"Path": "/tmp/x"}}})),
            {"decision": "ask"},
        )

    def test_hook_sh_non_json_success_output_is_neutral(self):
        import json
        self._write_dispatched(self.CID)
        pre_payload = json.dumps({"conversationId": self.CID, "toolCall": {"name": "read_file", "args": {"Path": "/tmp/x"}}})
        chatty = self.temp / "chatty_py"
        chatty.write_text("#!/bin/sh\necho 'Traceback: not json'\nexit 0\n", encoding="utf-8")
        chatty.chmod(0o755)
        (self.wingman_dir / "python").write_text(str(chatty) + "\n", encoding="utf-8")
        self.assertEqual(self._run_hook(self.HOOK_SH, "PreToolUse", pre_payload), {"decision": "ask"})
        self.assertEqual(self._run_hook(self.HOOK_SH, "Stop", pre_payload), {})

    def test_hook_answers_fast_while_another_process_holds_the_ledger_lock(self):
        import fcntl, json, time
        self._write_dispatched(self.CID)
        payload = json.dumps({"conversationId": self.CID, "toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}}})
        with open(self.ledger, "a") as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX)
            t0 = time.monotonic()
            out = self._run_hook(self.HOOK_PY, "PreToolUse", payload)
            elapsed = time.monotonic() - t0
            fcntl.flock(held.fileno(), fcntl.LOCK_UN)
        self.assertEqual(out, {"decision": "allow"})
        self.assertLess(elapsed, 3.0)

    def test_hook_sh_missing_python_and_failing_python_return_neutral(self):
        import json
        self._write_dispatched(self.CID)
        pre_payload = json.dumps({"conversationId": self.CID, "toolCall": {"name": "read_file", "args": {"Path": "/tmp/x"}}})
        stop_payload = json.dumps({"conversationId": self.CID, "terminationReason": "ERROR"})

        # No python file -> neutral
        self.assertEqual(self._run_hook(self.HOOK_SH, "PreToolUse", pre_payload), {"decision": "ask"})
        self.assertEqual(self._run_hook(self.HOOK_SH, "Stop", stop_payload), {})

        # Non-executable target -> neutral
        non_exec = self.temp / "non_exec"
        non_exec.write_text("#!/bin/sh\necho '{\"decision\":\"allow\"}'\n", encoding="utf-8")
        non_exec.chmod(0o644)
        (self.wingman_dir / "python").write_text(str(non_exec) + "\n", encoding="utf-8")
        self.assertEqual(self._run_hook(self.HOOK_SH, "PreToolUse", pre_payload), {"decision": "ask"})

        # Script that prints garbage and exits 1 -> neutral
        bad_py = self.temp / "bad_py"
        bad_py.write_text("#!/bin/sh\necho 'partial-trash'\nexit 1\n", encoding="utf-8")
        bad_py.chmod(0o755)
        (self.wingman_dir / "python").write_text(str(bad_py) + "\n", encoding="utf-8")
        self.assertEqual(self._run_hook(self.HOOK_SH, "PreToolUse", pre_payload), {"decision": "ask"})
        self.assertEqual(self._run_hook(self.HOOK_SH, "Stop", stop_payload), {})

        # Script that exits 0 with empty stdout -> neutral
        empty_py = self.temp / "empty_py"
        empty_py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        empty_py.chmod(0o755)
        (self.wingman_dir / "python").write_text(str(empty_py) + "\n", encoding="utf-8")
        self.assertEqual(self._run_hook(self.HOOK_SH, "PreToolUse", pre_payload), {"decision": "ask"})
        self.assertEqual(self._run_hook(self.HOOK_SH, "Stop", stop_payload), {})

        # Valid sys.executable -> passes hook.py's answer through
        (self.wingman_dir / "python").write_text(sys.executable + "\n", encoding="utf-8")
        self.assertEqual(self._run_hook(self.HOOK_SH, "PreToolUse", pre_payload), {"decision": "allow"})

    # --- happy paths and tripwire ---

    def test_manifests_match_contract(self):
        import json
        pjson = json.loads((self.PLUGIN_DIR / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(pjson, {"name": "wingman"})
        hjson = json.loads((self.PLUGIN_DIR / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual(list(hjson.keys()), ["wingman"])
        spec = hjson["wingman"]
        self.assertEqual(set(spec.keys()), {"PreToolUse", "Stop", "PreInvocation"})
        self.assertEqual(spec["PreToolUse"][0]["matcher"], "*")
        self.assertEqual(spec["PreToolUse"][0]["hooks"][0]["timeout"], 5)
        self.assertEqual(spec["Stop"][0]["timeout"], 5)
        self.assertEqual(spec["PreInvocation"][0]["timeout"], 5)

    def test_wingman_hooks_profiles_pin_both_shapes(self):
        import json
        default_hooks = agy._wingman_hooks("default")
        self.assertEqual(default_hooks, {
            "wingman": {
                "Stop": [{"type": "command", "command": "./hook.sh Stop", "timeout": 5}],
                "PreInvocation": [{"type": "command", "command": "./hook.sh PreInvocation", "timeout": 5}],
            }
        })
        self.assertNotIn("PreToolUse", default_hooks["wingman"])

        scoped_hooks = agy._wingman_hooks("scoped")
        self.assertEqual(scoped_hooks, {
            "wingman": {
                "PreToolUse": [{
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": "./hook.sh PreToolUse", "timeout": 5}],
                }],
                "Stop": [{"type": "command", "command": "./hook.sh Stop", "timeout": 5}],
                "PreInvocation": [{"type": "command", "command": "./hook.sh PreInvocation", "timeout": 5}],
            }
        })
        ref_hooks = json.loads((self.PLUGIN_DIR / "hooks.json").read_text(encoding="utf-8"))
        self.assertEqual(scoped_hooks, ref_hooks)

        with self.assertRaises(ValueError):
            agy._wingman_hooks("unknown")

    def test_wingman_selftest_profiles_and_bad_interpreter(self):
        # Passes for both default and scoped on the plugin directory without touching real state
        for profile in ("default", "scoped"):
            ok, err = agy._wingman_selftest(self.PLUGIN_DIR, profile)
            self.assertTrue(ok, err)

        # An interpreter that exits 1 causes self-test to fail (even though wrapper prints neutral)
        exit1_py = self.temp / "exit1_py"
        exit1_py.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        exit1_py.chmod(0o755)
        with patch.object(agy.sys, "executable", str(exit1_py)):
            for profile in ("default", "scoped"):
                ok, err = agy._wingman_selftest(self.PLUGIN_DIR, profile)
                self.assertFalse(ok)
                self.assertIn("self-test", err)

        # Unknown profile fails cleanly
        ok_unk, err_unk = agy._wingman_selftest(self.PLUGIN_DIR, "bogus")
        self.assertFalse(ok_unk)
        self.assertIn("unknown", err_unk)

    def test_pre_tool_use_scope_allow_and_protected_path_tripwire(self):
        import json
        self._write_dispatched(self.CID)
        other_cid = "99999999-2222-3333-4444-555555555555"

        # Out of scope -> ask
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "PreToolUse", json.dumps({
                "conversationId": other_cid,
                "toolCall": {"name": "write_file", "args": {"Path": "/tmp/ok.txt"}},
            })),
            {"decision": "ask"},
        )

        # In scope normal path -> allow
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "PreToolUse", json.dumps({
                "conversationId": self.CID,
                "toolCall": {"name": "write_file", "args": {"Path": "/tmp/ok.txt"}},
            })),
            {"decision": "allow"},
        )

        # In scope write_file whose Content mentions ~/.agy/ledger.jsonl -> allow
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "PreToolUse", json.dumps({
                "conversationId": self.CID,
                "toolCall": {"name": "write_file", "args": {
                    "Path": "/tmp/notes.md",
                    "Content": "Do not touch ~/.agy/ledger.jsonl or ~/.gemini/config/config.json",
                }},
            })),
            {"decision": "allow"},
        )

        # In scope with protected Path (~ and absolute) -> deny + event logged without args/content
        abs_ledger = str(Path("~/.agy/ledger.jsonl").expanduser())
        for prot_path in ("~/.agy/ledger.jsonl", abs_ledger, "~/.gemini/config/config.json"):
            res = self._run_hook(self.HOOK_PY, "PreToolUse", json.dumps({
                "conversationId": self.CID,
                "toolCall": {"name": "write_file", "args": {"Path": prot_path, "Content": "SECRET_BODY"}},
            }))
            self.assertEqual(res["decision"], "deny")
            self.assertIn("ledger", res["reason"])

        # In scope run_command whose CommandLine touches ~/.gemini/config/config.json -> deny
        res_cmd = self._run_hook(self.HOOK_PY, "PreToolUse", json.dumps({
            "conversationId": self.CID,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "cat ~/.gemini/config/config.json"}},
        }))
        self.assertEqual(res_cmd["decision"], "deny")

        # In scope run_command running blocked agy interactive/adopt commands -> deny
        for cmd in (
            "agy setup --apply",
            "./agy setup --apply --scoped",
            "agy setup --undo",
            "agy grants enable",
            "agy ledger adopt deadbeef",
        ):
            res_blk = self._run_hook(self.HOOK_PY, "PreToolUse", json.dumps({
                "conversationId": self.CID,
                "toolCall": {"name": "run_command", "args": {"CommandLine": cmd}},
            }))
            self.assertEqual(res_blk["decision"], "deny", cmd)
            self.assertTrue(res_blk["reason"].startswith("wingman: "))

        # write_file Content mentioning blocked command phrases is allowed
        res_content = self._run_hook(self.HOOK_PY, "PreToolUse", json.dumps({
            "conversationId": self.CID,
            "toolCall": {"name": "write_file", "args": {
                "Path": "/tmp/docs.md",
                "Content": "Run agy setup --apply or agy grants enable in a terminal.",
            }},
        }))
        self.assertEqual(res_content, {"decision": "allow"})

        ev_text = (self.wingman_dir / "events.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("SECRET_BODY", ev_text)
        self.assertNotIn("CommandLine", ev_text)
        events = [json.loads(line) for line in ev_text.splitlines() if line.strip()]
        self.assertEqual(len(events), 9)
        self.assertTrue(all(e["event"] == "deny" and e["cid"] == self.CID[:8] for e in events))

    def test_stop_retries_cap_and_events(self):
        import json
        self._write_dispatched(self.CID)
        other_cid = "99999999-2222-3333-4444-555555555555"

        # Out of scope Stop ERROR -> {}
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "Stop", json.dumps({
                "conversationId": other_cid,
                "terminationReason": "ERROR",
                "error": "stream idle timeout",
            })),
            {},
        )
        # In scope Stop NO_TOOL_CALL -> {}
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "Stop", json.dumps({
                "conversationId": self.CID,
                "terminationReason": "NO_TOOL_CALL",
            })),
            {},
        )

        # In scope Stop ERROR with transport error -> continue 3 times, then {}
        long_err = "stream idle timeout: " + "E" * 250
        for i in range(3):
            res = self._run_hook(self.HOOK_PY, "Stop", json.dumps({
                "conversationId": self.CID,
                "terminationReason": "ERROR",
                "error": long_err,
            }))
            self.assertEqual(res["decision"], "continue", f"retry {i+1}")
            self.assertIn("transport error", res["reason"])
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "Stop", json.dumps({
                "conversationId": self.CID,
                "terminationReason": "ERROR",
                "error": long_err,
            })),
            {},
        )
        events = [json.loads(line) for line in (self.wingman_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["event"] for e in events], ["continue", "continue", "continue", "cap-reached"])
        self.assertTrue(all(len(e["error"]) == 200 for e in events))

    def test_stop_retries_only_transport_errors_and_logs_other_errors(self):
        import json
        self._write_dispatched(self.CID)
        for bad_err in ("quota exceeded for model", "authentication failed: 401", "policy violation", "", None):
            payload = {"conversationId": self.CID, "terminationReason": "ERROR"}
            if bad_err is not None:
                payload["error"] = bad_err
            self.assertEqual(self._run_hook(self.HOOK_PY, "Stop", json.dumps(payload)), {})

        events = [json.loads(line) for line in (self.wingman_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["event"] for e in events], ["error-not-retried"] * 5)
        self.assertFalse((self.wingman_dir / "state.json").exists())

        # Case-insensitive transport match still retries after non-retried errors
        res = self._run_hook(self.HOOK_PY, "Stop", json.dumps({
            "conversationId": self.CID,
            "terminationReason": "ERROR",
            "error": "503 Service UNAVAILABLE (unexpected eof)",
        }))
        self.assertEqual(res["decision"], "continue")

    def test_pre_invocation_cap(self):
        import json
        self._write_dispatched(self.CID, max_invocations=5)
        self.assertEqual(
            self._run_hook(self.HOOK_PY, "PreInvocation", json.dumps({"conversationId": self.CID, "invocationNum": 4})),
            {},
        )
        res = self._run_hook(self.HOOK_PY, "PreInvocation", json.dumps({"conversationId": self.CID, "invocationNum": 5}))
        self.assertEqual(res["terminationBehavior"], "terminate")
        msg = res["injectSteps"][0]["errorMessage"]["userMessage"]
        self.assertIn("5 model calls", msg)
        self.assertIn("--max-invocations", msg)
        events = [json.loads(line) for line in (self.wingman_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["event"] for e in events], ["terminate"])

    def test_hook_sh_uses_isolated_mode_ignoring_pythonpath(self):
        import json
        poison_dir = self.temp / "poison_py"
        poison_dir.mkdir()
        (poison_dir / "json.py").write_text("raise RuntimeError('poisoned import')\n", encoding="utf-8")
        hook_sh = self.PLUGIN_DIR / "hook.sh"
        env = dict(os.environ)
        env.update({
            "WINGMAN_DIR": str(self.wingman_dir),
            "AGY_LEDGER": str(self.ledger),
            "PYTHONPATH": str(poison_dir),
        })
        res = subprocess.run(
            ["/bin/sh", str(hook_sh), "PreToolUse"],
            input=json.dumps({
                "conversationId": "99999999-2222-3333-4444-555555555555",
                "toolCall": {"name": "write_file", "args": {"Path": "/tmp/a"}},
            }),
            capture_output=True, text=True, timeout=5, env=env,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(json.loads(res.stdout), {"decision": "ask"})


class SwapSymlinkTests(unittest.TestCase):
    def test_swap_symlink_replaces_atomically_and_keeps_old_link_on_failure(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "a").mkdir(); (d / "b").mkdir()
            link = d / "wingman"
            os.symlink(str(d / "a"), str(link))
            agy._swap_symlink(link, str(d / "b"))
            self.assertEqual(os.readlink(link), str(d / "b"))
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["a", "b", "wingman"])
            with patch.object(agy.os, "replace", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    agy._swap_symlink(link, str(d / "a"))
            self.assertEqual(os.readlink(link), str(d / "b"))
            self.assertEqual(sorted(p.name for p in d.iterdir()), ["a", "b", "wingman"])


class WingmanTransportPatternTests(unittest.TestCase):
    def test_transport_pattern_ignores_quota_reset_wording(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("wingman_hook", str(ROOT / "plugin" / "wingman" / "hook.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rx = mod.TRANSPORT_ERR_RE
        for msg in ("stream idle timeout (5m0s)", "connection reset by peer", "HTTP 503 Service Unavailable",
                    "unexpected EOF", "context deadline exceeded: timed out",
                    # Seen live 2026-11-15 on two agents at once (truncated by events.jsonl at 200 chars):
                    'generating and executing: request failed: Post "https://example.invalid/v1:streamGenerateContent?alt=sse": '
                    "read tcp 10.0.0.2:63826->10.0.0.9:443: read: can't assign",
                    "dial tcp 10.0.0.9:443: connect: network is unreachable",
                    "dial tcp: lookup example.invalid: no route to host",
                    "net/http: TLS handshake timeout", "connection aborted"):
            self.assertTrue(rx.search(msg), msg)
        for msg in ("RESOURCE_EXHAUSTED: quota resets in 5h", "permission denied: policy",
                    "invalid API key", "error 5030 in tool", "Your quota will reset after 3h",
                    "Quota reset at 05:00Z", "no connection to the model is allowed on this plan"):
            self.assertFalse(rx.search(msg), msg)


class SetupTests(OfflineBase):
    def setUp(self):
        self._real_subprocess_run = subprocess.run
        super().setUp()
        self.setup_dir = self.temp / "setup"
        self.stack.enter_context(patch.dict(os.environ, {"AGY_SETUP_DIR": str(self.setup_dir)}))
        self.stack.enter_context(patch.object(
            agy, "_run", return_value=subprocess.CompletedProcess([], 0, "abc1234\n", "")))
        self.stack.enter_context(patch.object(agy, "_api_key_present", return_value=True))
        self.stack.enter_context(patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run))
        self.plugin_src = ROOT / "plugin" / "wingman"

    def _make_healthy_wingman(self, profile="default", rev="abc1234", daemon_version="t"):
        return _create_fake_wingman_copy(
            self.wingman_dir, self.plugins_dir, profile=profile, rev=rev,
            daemon_version=daemon_version, setup_dir=self.setup_dir)

    def _latest_manifest(self):
        import json
        dirs = sorted(p for p in self.setup_dir.iterdir() if p.is_dir())
        self.assertTrue(dirs, "expected a setup run directory")
        mf = dirs[-1] / "manifest.json"
        return mf, json.loads(mf.read_text(encoding="utf-8"))

    def test_setup_plan_is_strictly_readonly_in_empty_temp_dir(self):
        empty_root = self.temp / "isolated_empty"
        empty_root.mkdir()
        env_patch = {
            "HOME": str(empty_root),
            "AGY_LEDGER": str(empty_root / "ledger.jsonl"),
            "AGY_CONSENT": str(empty_root / "consent.json"),
            "AGY_GEMINI_CONFIG": str(empty_root / "config.json"),
            "AGY_PLUGINS_DIR": str(empty_root / "plugins"),
            "WINGMAN_DIR": str(empty_root / "wingman"),
            "AGY_SETUP_DIR": str(empty_root / "setup"),
        }
        with patch.object(agy, "discover", side_effect=lambda quiet=False: agy.die("not running", agy.EXIT_NO_DAEMON)), \
             patch.dict(os.environ, env_patch):
            self.assertEqual(list(empty_root.rglob("*")), [])
            code, out, err = self.run_main("setup")
            self.assertEqual(code, 0, err)
            self.assertEqual(err, "")
            self.assertEqual(list(empty_root.rglob("*")), [])
        self.assertIn("daemon not running: plugin health not checked", out)
        self.assertIn("[1/1]", out)
        self.assertIn("what", out)
        self.assertIn("why", out)
        self.assertIn("how-to-undo", out)

    def test_setup_plan_healthy_fake_host_lists_no_actions(self):
        import json
        self._make_healthy_wingman()
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": ["read_file(/custom)"]}},
            "plugins": {"healthy": {"enabled": True}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": [
            {"spec": {"serverName": "ok-srv", "pluginName": "healthy"}, "status": "MCP_SERVER_STATUS_READY"},
        ]}})
        code, out, err = self.run_main("setup")
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        self.assertIn("no actions needed", out)

    def test_setup_plan_keeps_same_bytes_install_from_older_rev_and_offers_changed_source(self):
        import json, shutil
        self._make_healthy_wingman()
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": ["read_file(/custom)"]}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        # A later agy commit that does not touch the plugin is not an update.
        with patch.object(agy, "_agy_git_rev", return_value="def5678"):
            code, out, err = self.run_main("setup")
        self.assertEqual(code, 0, err)
        self.assertIn("no actions needed", out)
        # A changed hook in the repo is.
        newer_src = self.temp / "newer_src"
        newer_src.mkdir()
        for fname in ("plugin.json", "hook.sh", "hook.py"):
            shutil.copy2(str(ROOT / "plugin" / "wingman" / fname), str(newer_src / fname))
        with open(newer_src / "hook.py", "a", encoding="utf-8") as fh:
            fh.write("\n# newer hook\n")
        with patch.object(agy, "_agy_git_rev", return_value="def5678"), \
             patch.object(agy, "_wingman_source_dir", return_value=newer_src):
            code, out, err = self.run_main("setup")
        self.assertEqual(code, 0, err)
        self.assertIn("update the wingman plugin", out)
        self.assertIn("def5678-default", out)

    def test_setup_plan_lists_needed_actions_and_refuses_real_dir(self):
        import json
        real_dir = self.plugins_dir / "wingman"
        real_dir.mkdir(parents=True)
        (real_dir / "plugin.json").write_text('{"name":"wingman"}\n', encoding="utf-8")
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}},
            "plugins": {"broken": {"enabled": True}, "mixed": {"enabled": True}, "already_off": {"enabled": False}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": [
            {
                "spec": {"serverName": "b1", "pluginName": "broken", "env": {"API_KEY": "SECRET-MCP-KEY-999"}},
                "status": "MCP_SERVER_STATUS_ERROR",
                "error": "failed with SECRET-MCP-KEY-999 and token=SECRET-TOK-111",
            },
            {
                "spec": {"serverName": "b2", "pluginName": "broken"},
                "status": "MCP_SERVER_STATUS_ERROR",
                "error": "second error",
            },
            {"spec": {"serverName": "m1", "pluginName": "mixed"}, "status": "MCP_SERVER_STATUS_ERROR", "error": "err"},
            {"spec": {"serverName": "m2", "pluginName": "mixed"}, "status": "MCP_SERVER_STATUS_READY"},
            {"spec": {"serverName": "o1", "pluginName": "already_off"}, "status": "MCP_SERVER_STATUS_ERROR", "error": "off"},
        ]}})
        # Default `setup` without --scoped must never mention scoped-approvals
        code, out, err = self.run_main("setup")
        self.assertEqual(code, 0, err)
        self.assertIn("refused:", out)
        self.assertIn("real directory", out)
        self.assertNotIn("scoped-approvals", out)
        self.assertNotIn("switch to scoped approvals", out)
        self.assertIn("disable plugin broken (its 2 MCP servers all fail; its skills are unloaded too)", out)
        self.assertNotIn("disable plugin mixed", out)
        self.assertNotIn("disable plugin already_off", out)
        self.assertNotIn("SECRET-MCP-KEY-999", out)
        self.assertNotIn("SECRET-TOK-111", out)

        # With --scoped and healthy scoped wingman inside real_dir, scoped-approvals is offered
        import shutil
        for fname in ("hook.sh", "hook.py"):
            shutil.copy2(str(self.plugin_src / fname), str(real_dir / fname))
        (real_dir / "hooks.json").write_text(json.dumps(agy._wingman_hooks("scoped")), encoding="utf-8")
        (real_dir / "install.json").write_text(json.dumps({"profile": "scoped", "rev": "abc1234"}), encoding="utf-8")
        self.wingman_dir.mkdir(parents=True, exist_ok=True)
        (self.wingman_dir / "python").write_text(sys.executable + "\n", encoding="utf-8")
        agy._WINGMAN_SELFTEST_CACHE.clear()
        agy._WINGMAN_HEALTH_CACHE.clear()
        scode, sout, serr = self.run_main("setup", "--scoped")
        self.assertEqual(scode, 0, serr)
        self.assertIn("[y/N]", sout)
        self.assertIn("your own Antigravity conversations will ask again", sout)
        self.assertIn("agy's agents keep running unattended", sout)
        self.assertIn("subagents spawned by agy's agents are NOT covered yet", sout)

    def test_setup_apply_and_undo_refuse_without_tty(self):
        with patch.object(agy.sys.stdin, "isatty", return_value=False):
            for flag in ("--apply", "--undo"):
                code, out, err = self.run_main("setup", flag)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("terminal", err)
                self.assertNotIn("human", err)
        self.assertFalse(self.setup_dir.exists())
        self.assertFalse(self.wingman_dir.exists())
        self.assertFalse(self.plugins_dir.exists())

    def test_human_gate_refuses_agent_env_vars_even_with_tty(self):
        self.gemini_config.write_text('{"userSettings": {}}', encoding="utf-8")
        for var in ("ANTIGRAVITY_AGENT", "ANTIGRAVITY_CONVERSATION_ID", "CLAUDECODE",
                    "CODEX_SANDBOX", "CODEX_THREAD_ID"):
            with patch.dict(os.environ, {var: "1"}), \
                 patch.object(agy.sys.stdin, "isatty", return_value=True):
                for argv in (("setup", "--apply"), ("setup", "--undo"), ("grants", "enable")):
                    code, out, err = self.run_main(*argv)
                    self.assertEqual(code, 2, f"{var} / {argv}: {err}")
                    self.assertEqual(out, "")
                    self.assertIn("run this yourself in a terminal; agents may not apply setup", err)
        self.assertFalse(self.setup_dir.exists())
        self.assertFalse(self.wingman_dir.exists())
        self.assertFalse(self.plugins_dir.exists())
        self.assertFalse(self.consent.exists())

    def test_setup_install_plugin_creates_dir_0700_python_and_symlink_and_undoes(self):
        import hashlib, json
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code, out, err = self.run_main("setup", "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.wingman_dir.stat().st_mode & 0o777, 0o700)
        py_file = self.wingman_dir / "python"
        self.assertEqual(py_file.read_text(encoding="utf-8").strip(), sys.executable)
        copy_dir = self.wingman_dir / "plugin" / "abc1234-default"
        self.assertTrue(copy_dir.is_dir())
        link = self.plugins_dir / "wingman"
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), copy_dir.resolve())
        self.assertEqual(json.loads((copy_dir / "hooks.json").read_text(encoding="utf-8")), agy._wingman_hooks("default"))
        inst = json.loads((copy_dir / "install.json").read_text(encoding="utf-8"))
        self.assertEqual(inst["rev"], "abc1234")
        self.assertEqual(inst["profile"], "default")
        self.assertEqual(inst["daemon_version"], "t")
        self.assertTrue(inst["installed_at"])
        for fname in ("plugin.json", "hook.sh", "hook.py", "hooks.json", "skills/agy/SKILL.md"):
            self.assertTrue((copy_dir / fname).is_file())
            self.assertEqual(inst["sha256"][fname], hashlib.sha256((copy_dir / fname).read_bytes()).hexdigest())
        self.assertIn("wingman", out)
        self.assertIn("grants", out)
        self.assertIn("plugins", out)

        _, mf = self._latest_manifest()
        self.assertEqual(mf["version"], 1)
        self.assertEqual(mf["agy_rev"], "abc1234")
        self.assertIsNone(mf["undone"])
        self.assertEqual(len(mf["actions"]), 1)
        self.assertTrue(mf["actions"][0]["applied"])

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode, _, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        self.assertFalse(link.is_symlink())
        self.assertFalse(py_file.exists())
        self.assertFalse(copy_dir.exists())

    def test_setup_install_plugin_pinned_copy_isolated_from_repo_edits_and_undo_keeps_preexisting_dir(self):
        import shutil
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        repo_copy = self.temp / "repo_plugin"
        shutil.copytree(str(self.plugin_src), str(repo_copy))
        with patch.object(agy, "_wingman_source_dir", return_value=repo_copy), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code, _, err = self.run_main("setup", "--apply")
        self.assertEqual(code, 0, err)
        live_dir = self.wingman_dir / "plugin" / "abc1234-default"
        orig_hook_bytes = (live_dir / "hook.py").read_bytes()
        # Editing the repo working tree does not mutate the live pinned copy
        (repo_copy / "hook.py").write_text("#!/usr/bin/env python3\n# edited in repo\n", encoding="utf-8")
        self.assertEqual((live_dir / "hook.py").read_bytes(), orig_hook_bytes)

        # Undo removes the copy dir created by setup; if copy dir already existed before setup, undo keeps it
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            self.run_main("setup", "--undo")
        self.assertFalse(live_dir.exists())

        live_dir.mkdir(parents=True)
        sentinel = live_dir / "keep.txt"
        sentinel.write_text("preexisting\n", encoding="utf-8")
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code2, _, err2 = self.run_main("setup", "--apply")
        self.assertEqual(code2, 0, err2)
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode2, _, uerr2 = self.run_main("setup", "--undo")
        self.assertEqual(ucode2, 0, uerr2)
        self.assertTrue(live_dir.is_dir())
        self.assertTrue(sentinel.is_file())

    def test_setup_manifest_is_saved_after_each_action_even_if_a_later_one_crashes(self):
        import json
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}},
        }), encoding="utf-8")
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"), \
             patch.object(agy, "_apply_scoped_approvals", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.run_main("setup", "--apply", "--scoped")
        _, mf = self._latest_manifest()
        self.assertEqual([a["id"] for a in mf["actions"]], ["install-plugin"])
        self.assertTrue(mf["actions"][0]["applied"])
        self.assertTrue((self.plugins_dir / "wingman").is_symlink())

    def test_setup_install_plugin_restores_a_replaced_python_file_on_undo(self):
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        self.wingman_dir.mkdir(parents=True, exist_ok=True)
        py_file = self.wingman_dir / "python"
        py_file.write_text("/old/interpreter/python3\n", encoding="utf-8")
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code, _, err = self.run_main("setup", "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(py_file.read_text(encoding="utf-8").strip(), sys.executable)
        _, mf = self._latest_manifest()
        kinds = [c["kind"] for c in mf["actions"][0]["changes"]]
        self.assertIn("file-replaced", kinds)
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode, _, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        self.assertEqual(py_file.read_text(encoding="utf-8"), "/old/interpreter/python3\n")
        self.assertFalse((self.plugins_dir / "wingman").is_symlink())

    def test_setup_adopts_unmanaged_wingman_link_and_undo_restores_old_target(self):
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        legacy_dir = self.wingman_dir / "plugin" / "a136513-nopretool"
        legacy_dir.mkdir(parents=True)
        (legacy_dir / "plugin.json").write_text('{"name": "wingman"}\n', encoding="utf-8")
        (self.wingman_dir / "python").write_text(sys.executable + "\n", encoding="utf-8")
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        link = self.plugins_dir / "wingman"
        os.symlink(str(legacy_dir), str(link))

        code, out, err = self.run_main("setup")
        self.assertEqual(code, 0, err)
        self.assertIn("replace the unmanaged wingman install with a managed one", out)

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            acode, aout, aerr = self.run_main("setup", "--apply")
        self.assertEqual(acode, 0, aerr)
        self.assertIn("replace the unmanaged wingman install with a managed one", aout)
        expected_copy = self.wingman_dir / "plugin" / "abc1234-default"
        self.assertEqual(link.resolve(), expected_copy.resolve())
        _, mf = self._latest_manifest()
        sym_changes = [c for c in mf["actions"][0]["changes"] if c["kind"] == "symlink"]
        self.assertEqual(len(sym_changes), 1)
        self.assertEqual(sym_changes[0]["old_target"], str(legacy_dir))

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode, _, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(legacy_dir))

    def test_doctor_grants_ok_without_wildcards_when_wingman_is_healthy(self):
        import json
        # default profile still warns on missing grants; scoped profile satisfies grants check.
        self._make_healthy_wingman(profile="default")
        self.gemini_config.write_text(json.dumps({"userSettings": {"globalPermissionGrants": {"allow": []}}}),
                                      encoding="utf-8")
        by_name_def = {c["name"]: c for c in agy._doctor_permissions(self.daemon)}
        self.assertEqual(by_name_def["grants"]["level"], "WARN")
        self.assertEqual(by_name_def["wingman"]["level"], "OK")

        self._make_healthy_wingman(profile="scoped")
        by_name = {c["name"]: c for c in agy._doctor_permissions(self.daemon)}
        self.assertEqual(by_name["grants"]["level"], "OK")
        self.assertIn("not needed", by_name["grants"]["detail"])
        self.assertEqual(by_name["wingman"]["level"], "OK")

    def test_setup_install_plugin_preflight_failure_creates_no_symlink(self):
        import shutil
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        bad_py = self.temp / "bad_py.sh"
        bad_py.write_text("#!/bin/sh\necho '{\"garbage\":true}'\nexit 0\n", encoding="utf-8")
        bad_py.chmod(0o755)
        with patch.object(agy.sys, "executable", str(bad_py)), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code, _, err = self.run_main("setup", "--apply")
        self.assertNotEqual(code, 0)
        self.assertIn("self-test", err)
        self.assertFalse((self.plugins_dir / "wingman").exists())
        self.assertFalse((self.plugins_dir / "wingman").is_symlink())
        self.assertFalse((self.wingman_dir / "python").exists())
        self.assertFalse((self.wingman_dir / "plugin" / "abc1234-default").exists())
        _, mf = self._latest_manifest()
        self.assertFalse(mf["actions"][0]["applied"])

        # An interpreter that exits 1 is also refused
        exit1_py = self.temp / "exit1_py.sh"
        exit1_py.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        exit1_py.chmod(0o755)
        with patch.object(agy.sys, "executable", str(exit1_py)), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code_e1, _, err_e1 = self.run_main("setup", "--apply")
        self.assertNotEqual(code_e1, 0)
        self.assertIn("self-test", err_e1)
        self.assertFalse((self.plugins_dir / "wingman").is_symlink())
        self.assertFalse((self.wingman_dir / "python").exists())
        self.assertFalse((self.wingman_dir / "plugin" / "abc1234-default").exists())

        # Also verify non-JSON garbage from a broken hook.sh aborts self-test with no symlink
        fake_src = self.temp / "fake_wingman"
        shutil.copytree(str(self.plugin_src), str(fake_src))
        fake_hook = fake_src / "hook.sh"
        fake_hook.write_text("#!/bin/sh\necho 'not-json-garbage'\nexit 0\n", encoding="utf-8")
        fake_hook.chmod(0o755)
        with patch.object(agy, "_wingman_source_dir", return_value=fake_src), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code2, _, err2 = self.run_main("setup", "--apply")
        self.assertNotEqual(code2, 0)
        self.assertIn("self-test", err2)
        self.assertFalse((self.plugins_dir / "wingman").is_symlink())
        self.assertFalse((self.wingman_dir / "plugin" / "abc1234-default").exists())

    def test_setup_install_plugin_replaces_foreign_symlink_and_restores_on_undo(self):
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        foreign = self.temp / "foreign_plugin"
        foreign.mkdir()
        self.plugins_dir.mkdir(parents=True)
        link = self.plugins_dir / "wingman"
        os.symlink(str(foreign), str(link))

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code, _, err = self.run_main("setup", "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(link.resolve(), (self.wingman_dir / "plugin" / "abc1234-default").resolve())
        _, mf = self._latest_manifest()
        sym_changes = [c for c in mf["actions"][0]["changes"] if c["kind"] == "symlink"]
        self.assertEqual(sym_changes[0]["old_target"], str(foreign))

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode, _, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), str(foreign))

    def test_setup_scoped_approvals_removes_only_six_grants_and_consent_and_undoes(self):
        import hashlib, json
        self._make_healthy_wingman(profile="scoped")
        orig_cfg = json.dumps({
            "userSettings": {
                "themeMode": "DARK",
                "globalPermissionGrants": {"allow": ["read_file(/keep)", *agy.FULL_PERM_GRANTS, "mcp(ok)"]},
            },
            "plugins": {"healthy": {"enabled": True}},
        })
        self.gemini_config.write_text(orig_cfg, encoding="utf-8")
        self.gemini_config.chmod(0o600)
        orig_consent = json.dumps({"wildcard_grants": True, "ts": "2026-11-14T00:00:00Z"})
        self.consent.write_text(orig_consent, encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": [
            {"spec": {"serverName": "ok", "pluginName": "healthy"}, "status": "MCP_SERVER_STATUS_READY"},
        ]}})

        prompts = []

        def fake_input(p):
            prompts.append(p)
            return "y"

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=fake_input):
            code, out, err = self.run_main("setup", "--apply", "--scoped")
        self.assertEqual(code, 0, err)
        self.assertTrue(any("[y/N]" in p for p in prompts))
        self.assertIn("your own Antigravity conversations will ask again", out)
        self.assertIn("agy's agents keep running unattended", out)
        self.assertIn("subagents spawned by agy's agents are NOT covered yet", out)

        new_cfg = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertEqual(new_cfg["userSettings"]["globalPermissionGrants"]["allow"], ["read_file(/keep)", "mcp(ok)"])
        self.assertEqual(new_cfg["userSettings"]["themeMode"], "DARK")
        self.assertEqual(self.gemini_config.stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.consent.exists())

        mf_path, mf = self._latest_manifest()
        backups_by_path = {b["path"]: b for b in mf["backups"]}
        self.assertEqual(
            backups_by_path[str(self.gemini_config)]["sha256_before"],
            hashlib.sha256(orig_cfg.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            backups_by_path[str(self.consent)]["sha256_before"],
            hashlib.sha256(orig_consent.encode("utf-8")).hexdigest(),
        )
        self.assertTrue(Path(backups_by_path[str(self.consent)]["backup"]).is_file())

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode, uout, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        restored_cfg = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertEqual(
            restored_cfg["userSettings"]["globalPermissionGrants"]["allow"],
            ["read_file(/keep)", "mcp(ok)", *agy.FULL_PERM_GRANTS],
        )
        self.assertEqual(self.consent.read_text(encoding="utf-8"), orig_consent)
        # Backups stay on disk and their paths are printed
        self.assertTrue(Path(backups_by_path[str(self.gemini_config)]["backup"]).is_file())
        self.assertIn(backups_by_path[str(self.gemini_config)]["backup"], uout)

        # Second --undo finds nothing to undo (remove synthetic fixture seed first)
        import shutil as _shutil
        _shutil.rmtree(self.setup_dir / "20000101T000000Z", ignore_errors=True)
        mf_after = json.loads(mf_path.read_text(encoding="utf-8"))
        self.assertIsNotNone(mf_after["undone"])
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=AssertionError("should not prompt")):
            u2code, u2out, u2err = self.run_main("setup", "--undo")
        self.assertEqual(u2code, 0, u2err)
        self.assertIn("nothing to undo", u2out)

    def test_setup_disable_broken_plugins_apply_and_undo_respects_user_edits(self):
        import json
        self._make_healthy_wingman()
        self.gemini_config.write_text(json.dumps({
            "plugins": {"broken": {"enabled": True}, "partial": {"enabled": True}},
        }), encoding="utf-8")
        self.gemini_config.chmod(0o600)
        self.use_rpc({"GetMcpServerStates": {"states": [
            {"spec": {"serverName": "b1", "pluginName": "broken"}, "status": "MCP_SERVER_STATUS_ERROR", "error": "boom"},
            {"spec": {"serverName": "p1", "pluginName": "partial"}, "status": "MCP_SERVER_STATUS_ERROR", "error": "err"},
            {"spec": {"serverName": "p2", "pluginName": "partial"}, "status": "MCP_SERVER_STATUS_READY"},
        ]}})

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code, _, err = self.run_main("setup", "--apply")
        self.assertEqual(code, 0, err)
        cfg = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertFalse(cfg["plugins"]["broken"]["enabled"])
        self.assertTrue(cfg["plugins"]["partial"]["enabled"])

        # Undo restores when still false
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode, _, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        cfg2 = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertTrue(cfg2["plugins"]["broken"]["enabled"])

        # Second apply, then user manually re-enables before undo -> undo leaves it alone
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code2, _, err2 = self.run_main("setup", "--apply")
        self.assertEqual(code2, 0, err2)
        cfg3 = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        cfg3["plugins"]["broken"]["enabled"] = True
        self.gemini_config.write_text(json.dumps(cfg3), encoding="utf-8")

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode2, uout2, uerr2 = self.run_main("setup", "--undo")
        self.assertEqual(ucode2, 0, uerr2)
        self.assertIn("changed since setup; left as is", uout2)
        cfg4 = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertTrue(cfg4["plugins"]["broken"]["enabled"])

    def test_setup_answering_n_skips_action_and_records_applied_false(self):
        import json
        self._make_healthy_wingman(profile="scoped")
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}},
            "plugins": {"broken": {"enabled": True}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": [
            {"spec": {"serverName": "b1", "pluginName": "broken"}, "status": "MCP_SERVER_STATUS_ERROR", "error": "boom"},
        ]}})

        # Decline scoped-approvals (n), accept disable-broken-plugins (y)
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["n", "y"]):
            code, _, err = self.run_main("setup", "--apply", "--scoped")
        self.assertEqual(code, 0, err)
        cfg = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertEqual(cfg["userSettings"]["globalPermissionGrants"]["allow"], list(agy.FULL_PERM_GRANTS))
        self.assertFalse(cfg["plugins"]["broken"]["enabled"])

        _, mf = self._latest_manifest()
        by_id = {a["id"]: a for a in mf["actions"]}
        self.assertFalse(by_id["scoped-approvals"]["applied"])
        self.assertEqual(by_id["scoped-approvals"]["changes"], [])
        self.assertTrue(by_id["disable-broken-plugins:broken"]["applied"])

    def test_setup_scoped_flag_hides_scoped_approvals_by_default_and_gates_on_scoped_selftest(self):
        import json
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": list(agy.FULL_PERM_GRANTS)}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}})

        # Without --scoped: plan offers default wingman and shows nothing about scoped-approvals
        code, out, err = self.run_main("setup")
        self.assertEqual(code, 0, err)
        self.assertIn("default profile", out)
        self.assertNotIn("scoped-approvals", out)
        self.assertNotIn("switch to scoped approvals", out)

        # --apply without --scoped installs default profile and keeps all grants
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            acode, aout, aerr = self.run_main("setup", "--apply")
        self.assertEqual(acode, 0, aerr)
        self.assertNotIn("switch to scoped approvals", aout)
        self.assertEqual((self.plugins_dir / "wingman").resolve(), (self.wingman_dir / "plugin" / "abc1234-default").resolve())
        cfg_after_def = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertEqual(cfg_after_def["userSettings"]["globalPermissionGrants"]["allow"], list(agy.FULL_PERM_GRANTS))

        # --apply --scoped when install-plugin is declined skips scoped-approvals (scoped not healthy yet)
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="n"):
            dcode, dout, derr = self.run_main("setup", "--apply", "--scoped")
        self.assertEqual(dcode, 0, derr)
        self.assertIn("skipping scoped-approvals", dout)
        self.assertEqual((self.plugins_dir / "wingman").resolve(), (self.wingman_dir / "plugin" / "abc1234-default").resolve())

        # --apply --scoped accepting both upgrades default -> scoped and removes the 6 grants
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["y", "y"]):
            scode, _, serr = self.run_main("setup", "--apply", "--scoped")
        self.assertEqual(scode, 0, serr)
        self.assertEqual((self.plugins_dir / "wingman").resolve(), (self.wingman_dir / "plugin" / "abc1234-scoped").resolve())
        cfg_after_scoped = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertEqual(cfg_after_scoped["userSettings"]["globalPermissionGrants"]["allow"], [])

    def test_setup_midway_exception_persists_partial_changes_for_undo(self):
        import json
        self._make_healthy_wingman(profile="scoped")
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": ["read_file(/keep)", *agy.FULL_PERM_GRANTS]}},
        }), encoding="utf-8")
        self.consent.write_text(json.dumps({"wildcard_grants": True}), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}})

        orig_backup = agy._setup_backup_file
        calls = {"n": 0}

        def boom_on_consent_move(*args, **kwargs):
            calls["n"] += 1
            if kwargs.get("move") and args[0] == self.consent:
                raise RuntimeError("simulated crash before consent move")
            return orig_backup(*args, **kwargs)

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"), \
             patch.object(agy, "_setup_backup_file", side_effect=boom_on_consent_move):
            with self.assertRaises(RuntimeError):
                self.run_main("setup", "--apply", "--scoped")

        _, mf = self._latest_manifest()
        self.assertEqual(len(mf["actions"]), 1)
        self.assertTrue(mf["actions"][0]["applied"])
        self.assertEqual([c["kind"] for c in mf["actions"][0]["changes"]], ["grants-removed"])
        cfg = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertEqual(cfg["userSettings"]["globalPermissionGrants"]["allow"], ["read_file(/keep)"])

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode, uout, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        self.assertIn("  revert:", uout)
        self.assertIn("    - re-add grants to", uout)
        restored = json.loads(self.gemini_config.read_text(encoding="utf-8"))
        self.assertEqual(restored["userSettings"]["globalPermissionGrants"]["allow"], ["read_file(/keep)", *agy.FULL_PERM_GRANTS])

    def test_setup_undo_validates_manifest_entries_and_prints_preview(self):
        import json
        outside = self.temp / "outside.txt"
        outside.write_text("do-not-touch", encoding="utf-8")
        bad_mf = self.setup_dir / "20260101T000000Z" / "manifest.json"
        bad_mf.parent.mkdir(parents=True, exist_ok=True)
        bad_mf.write_text(json.dumps({
            "version": 1,
            "ts": "20260101T000000Z",
            "undone": None,
            "backups": [],
            "actions": [{"id": "tampered", "applied": True, "changes": [
                {"kind": "file-created", "path": str(outside)},
                {"kind": "symlink", "path": str(outside)},
                {"kind": "grants-removed", "path": str(self.gemini_config), "grants": ["RunCommand(*)"]},
                {"kind": "file-moved", "path": str(outside), "to": str(self.setup_dir / "20260101T000000Z" / "x")},
                {"kind": "keychain-item", "service": "rogue-service", "account": "u", "replaced": False, "fingerprint": "12345678"},
            ]}],
        }), encoding="utf-8")

        prompts = []

        def fake_input(p):
            prompts.append(p)
            return "y"

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=fake_input):
            ucode, uout, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        self.assertEqual(uout.count("refusing "), 5)
        self.assertIn("  revert: tampered", uout)
        self.assertIn(f"    - remove file {outside}", uout)
        self.assertEqual(outside.read_text(encoding="utf-8"), "do-not-touch")

    def test_setup_plan_teach_agents_detection_notes_and_refusals(self):
        import json
        self._make_healthy_wingman()
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": ["read_file(/custom)"]}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}})

        # Neither host home exists -> nothing offered
        code, out, err = self.run_main("setup")
        self.assertEqual(code, 0, err)
        self.assertIn("no actions needed", out)

        # Create Claude home (absent skill) and Codex home via CODEX_HOME fallback (current skill)
        self.claude_home.mkdir()
        codex_fallback = self.temp / "codex_via_env"
        (codex_fallback / "skills" / "agy").mkdir(parents=True)
        src_bytes = (ROOT / "skills" / "agy" / "SKILL.md").read_bytes()
        (codex_fallback / "skills" / "agy" / "SKILL.md").write_bytes(src_bytes)

        with patch.dict(os.environ, {"AGY_CODEX_HOME": "", "CODEX_HOME": str(codex_fallback)}):
            code2, out2, err2 = self.run_main("setup")
        self.assertEqual(code2, 0, err2)
        self.assertIn("teach Claude Code to use agy (install the agy skill)", out2)
        self.assertNotIn("teach Codex to use agy", out2)

        # Missing skill source -> nothing offered, one note
        missing_src = self.temp / "missing_SKILL.md"
        with patch.object(agy, "_agy_skill_source", return_value=missing_src):
            code3, out3, err3 = self.run_main("setup")
        self.assertEqual(code3, 0, err3)
        self.assertIn("agy skill source not found; agents not taught", out3)
        self.assertNotIn("teach Claude Code", out3)
        self.assertNotIn("teach Codex", out3)

        # Real dir with extra files and regular file -> refused, never overwritten
        claude_skill = self.claude_home / "skills" / "agy"
        claude_skill.mkdir(parents=True)
        (claude_skill / "SKILL.md").write_bytes(src_bytes)
        (claude_skill / "extra.txt").write_text("keep", encoding="utf-8")
        self.codex_home.mkdir()
        (self.codex_home / "skills").mkdir()
        (self.codex_home / "skills" / "agy").write_text("not a dir", encoding="utf-8")
        code4, out4, err4 = self.run_main("setup")
        self.assertEqual(code4, 0, err4)
        self.assertIn("refused: teach-claude-code:", out4)
        self.assertIn("refused: teach-codex:", out4)
        self.assertNotIn("teach Claude Code to use agy", out4)
        self.assertNotIn("teach Codex to use agy", out4)

    def test_setup_teach_agents_apply_and_undo_all_cases(self):
        import hashlib, json
        self._make_healthy_wingman()
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": ["read_file(/custom)"]}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        src_bytes = (ROOT / "skills" / "agy" / "SKILL.md").read_bytes()
        src_sha = hashlib.sha256(src_bytes).hexdigest()

        # Case 1: absent (claude_home exists, skills/ absent; codex_home absent)
        self.claude_home.mkdir()
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            c1, _, e1 = self.run_main("setup", "--apply")
        self.assertEqual(c1, 0, e1)
        claude_target = self.claude_home / "skills" / "agy"
        claude_file = claude_target / "SKILL.md"
        self.assertTrue(claude_file.is_file())
        self.assertFalse(claude_target.is_symlink())
        self.assertEqual(claude_file.stat().st_mode & 0o777, 0o644)
        self.assertEqual(claude_file.read_bytes(), src_bytes)
        _, mf1 = self._latest_manifest()
        ch1 = mf1["actions"][0]["changes"][0]
        self.assertEqual(ch1["kind"], "skill-installed")
        self.assertEqual(ch1["host"], "claude-code")
        self.assertEqual(ch1["path"], str(claude_target))
        self.assertEqual(ch1["sha256"], src_sha)
        self.assertIsNone(ch1["previous"])
        self.assertEqual(ch1["created_dirs"], [str(self.claude_home / "skills"), str(claude_target)])

        # Undo Case 1 removes SKILL.md and both created_dirs
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            u1, _, ue1 = self.run_main("setup", "--undo")
        self.assertEqual(u1, 0, ue1)
        self.assertFalse(claude_target.exists())
        self.assertFalse((self.claude_home / "skills").exists())
        self.claude_home.rmdir()

        # Case 2: dangling symlink in codex_home
        self.codex_home.mkdir()
        (self.codex_home / "skills").mkdir()
        codex_target = self.codex_home / "skills" / "agy"
        dangling_target = str(self.temp / "nonexistent" / "skills" / "agy-codex")
        os.symlink(dangling_target, str(codex_target))
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            c2, _, e2 = self.run_main("setup", "--apply")
        self.assertEqual(c2, 0, e2)
        self.assertFalse(codex_target.is_symlink())
        self.assertEqual((codex_target / "SKILL.md").read_bytes(), src_bytes)
        _, mf2 = self._latest_manifest()
        ch2 = mf2["actions"][0]["changes"][0]
        self.assertEqual(ch2["host"], "codex")
        self.assertEqual(ch2["previous"], {"symlink": dangling_target})
        self.assertEqual(ch2["created_dirs"], [str(codex_target)])

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            u2, _, ue2 = self.run_main("setup", "--undo")
        self.assertEqual(u2, 0, ue2)
        self.assertTrue(codex_target.is_symlink())
        self.assertEqual(os.readlink(codex_target), dangling_target)
        codex_target.unlink()

        # Case 3: real dir containing ONLY outdated SKILL.md -> backed up & restored
        codex_target.mkdir()
        old_bytes = b"# old skill content\n"
        old_sha = hashlib.sha256(old_bytes).hexdigest()
        (codex_target / "SKILL.md").write_bytes(old_bytes)
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            c3, _, e3 = self.run_main("setup", "--apply")
        self.assertEqual(c3, 0, e3)
        self.assertEqual((codex_target / "SKILL.md").read_bytes(), src_bytes)
        _, mf3 = self._latest_manifest()
        ch3 = mf3["actions"][0]["changes"][0]
        self.assertEqual(ch3["created_dirs"], [])
        self.assertEqual(ch3["previous"]["sha256"], old_sha)
        bak_path = Path(ch3["previous"]["backup"])
        self.assertTrue(bak_path.is_file())
        self.assertEqual(bak_path.read_bytes(), old_bytes)
        self.assertTrue(any(b["path"] == str(codex_target / "SKILL.md") and b["sha256_before"] == old_sha
                            for b in mf3["backups"]))

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            u3, _, ue3 = self.run_main("setup", "--undo")
        self.assertEqual(u3, 0, ue3)
        self.assertEqual((codex_target / "SKILL.md").read_bytes(), old_bytes)

    def test_setup_teach_symlink_restored_on_interrupt_and_loop_does_not_crash(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp(dir=str(self.temp)))
        codex_home = tmp / "codex"
        (codex_home / "skills").mkdir(parents=True)
        old_dir = tmp / "old-skill"
        old_dir.mkdir()
        link = codex_home / "skills" / "agy"
        os.symlink(str(old_dir), str(link))
        # Ctrl-C between unlink and write: the link comes back and the interrupt propagates.
        with patch.dict(os.environ, {"AGY_CODEX_HOME": str(codex_home)}), \
             patch.object(agy, "_write_bytes_atomic", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                agy._apply_teach_host("codex", [], set(), tmp / "run", changes=[])
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(str(link)), str(old_dir))
        # A `skills -> skills` loop is refused, never a crash (RuntimeError on Python < 3.13).
        loop_home = tmp / "loophome"
        loop_home.mkdir()
        os.symlink("skills", str(loop_home / "skills"))
        state, info = agy._inspect_skill_target(loop_home / "skills" / "agy", b"x")
        self.assertEqual(state, "refuse")
        self.assertIn("is a symlink", info)

    def test_setup_teach_codex_symlink_restored_when_install_fails_midway(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp(dir=str(self.temp)))
        codex_home = tmp / "codex"
        (codex_home / "skills").mkdir(parents=True)
        old_dir = tmp / "old-skill"
        old_dir.mkdir()
        (old_dir / "SKILL.md").write_text("old\n", encoding="utf-8")
        link = codex_home / "skills" / "agy"
        os.symlink(str(old_dir), str(link))
        changes = []
        with patch.dict(os.environ, {"AGY_CODEX_HOME": str(codex_home)}), \
             patch.object(agy, "_write_bytes_atomic", side_effect=OSError("disk full")):
            ok, out_changes, err = agy._apply_teach_host("codex", [], set(), tmp / "run", changes=changes)
        self.assertFalse(ok)
        self.assertIn("disk full", err)
        self.assertIn(str(old_dir), err)
        self.assertEqual(out_changes, [])
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(str(link)), str(old_dir))

        # Absent host failing write cleans up created dirs and setup --apply continues to next host
        self._make_healthy_wingman()
        self.gemini_config.write_text('{"userSettings":{"globalPermissionGrants":{"allow":["read_file(/custom)"]}}}\n', encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}, "GetAllSkills": {"skills": []}})
        self.claude_home.mkdir()
        self.codex_home.mkdir()
        real_write_bytes = agy._write_bytes_atomic

        def fail_claude_only(p, data, mode=0o644):
            if str(p).startswith(str(self.claude_home)):
                raise OSError("claude disk full")
            return real_write_bytes(p, data, mode=mode)

        with patch.object(agy, "_api_key_present", return_value=True), \
             patch.object(agy, "_write_bytes_atomic", side_effect=fail_claude_only), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            sc, so, se = self.run_main("setup", "--apply")
        self.assertEqual(sc, agy.EXIT_ERR)
        self.assertIn("teach-claude-code aborted", se)
        self.assertIn("== after ==", so)
        self.assertFalse((self.claude_home / "skills").exists())
        self.assertTrue((self.codex_home / "skills" / "agy" / "SKILL.md").is_file())

    def test_setup_teach_undo_backup_hash_mode_and_atomic_symlink_restore(self):
        import json
        import stat
        self._make_healthy_wingman()
        self.gemini_config.write_text('{"userSettings":{"globalPermissionGrants":{"allow":["read_file(/custom)"]}}}\n', encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}, "GetAllSkills": {"skills": []}})

        # 1. Pre-existing file with mode 0o640 -> setup backs up & records mode; undo restores mode 0o640
        claude_skill = self.claude_home / "skills" / "agy"
        claude_skill.mkdir(parents=True)
        claude_md = claude_skill / "SKILL.md"
        claude_md.write_bytes(b"custom claude 0640\n")
        os.chmod(claude_md, 0o640)

        # Codex has a symlink -> replaced on apply
        (self.codex_home / "skills").mkdir(parents=True)
        old_codex_dir = self.temp / "old-codex-skill"
        old_codex_dir.mkdir()
        os.symlink(str(old_codex_dir), str(self.codex_home / "skills" / "agy"))

        with patch.object(agy, "_api_key_present", return_value=True), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            c1, _, e1 = self.run_main("setup", "--apply")
        self.assertEqual(c1, 0, e1)
        src_bytes = (ROOT / "skills" / "agy" / "SKILL.md").read_bytes()
        self.assertEqual(claude_md.read_bytes(), src_bytes)
        self.assertEqual(stat.S_IMODE(claude_md.stat().st_mode), 0o644)

        # Tamper with claude backup file -> undo refuses to restore claude from altered backup
        run_dirs = sorted(p for p in self.setup_dir.iterdir() if p.is_dir())
        mf_data = json.loads((run_dirs[-1] / "manifest.json").read_text(encoding="utf-8"))
        claude_ch = next(
            ch for a in mf_data["actions"] for ch in a.get("changes", [])
            if ch.get("host") == "claude-code"
        )
        self.assertEqual(claude_ch["previous"]["mode"], 0o640)
        bak_path = Path(claude_ch["previous"]["backup"])
        orig_bak = bak_path.read_bytes()
        bak_path.write_bytes(b"tampered!\n")

        # Also patch os.symlink to fail during undo -> codex directory & SKILL.md remain intact
        with patch.object(agy.os, "symlink", side_effect=OSError("symlink blocked")), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            u1, uout1, ue1 = self.run_main("setup", "--undo")
        self.assertEqual(u1, 0, ue1)
        self.assertIn("backup changed; left as is", uout1)
        self.assertEqual(claude_md.read_bytes(), src_bytes)
        self.assertIn("failed to restore symlink", uout1)
        codex_md = self.codex_home / "skills" / "agy" / "SKILL.md"
        self.assertTrue(codex_md.is_file())
        self.assertEqual(codex_md.read_bytes(), src_bytes)

        # Restore original backup bytes and re-run undo without symlink failure -> restores 0o640 & symlink
        bak_path.write_bytes(orig_bak)
        mf_data["undone"] = None
        (run_dirs[-1] / "manifest.json").write_text(json.dumps(mf_data), encoding="utf-8")
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            u2, _, ue2 = self.run_main("setup", "--undo")
        self.assertEqual(u2, 0, ue2)
        self.assertEqual(claude_md.read_bytes(), b"custom claude 0640\n")
        self.assertEqual(stat.S_IMODE(claude_md.stat().st_mode), 0o640)
        codex_target = self.codex_home / "skills" / "agy"
        self.assertTrue(codex_target.is_symlink())
        self.assertEqual(os.readlink(str(codex_target)), str(old_codex_dir))

    def test_setup_teach_agents_undo_respects_edits_and_validates_manifest(self):
        import json
        self._make_healthy_wingman()
        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": ["read_file(/custom)"]}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}})

        self.claude_home.mkdir()
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            c1, _, e1 = self.run_main("setup", "--apply")
        self.assertEqual(c1, 0, e1)

        # User edits SKILL.md after setup -> undo leaves it alone
        claude_file = self.claude_home / "skills" / "agy" / "SKILL.md"
        claude_file.write_text("# user edited\n", encoding="utf-8")
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            u1, uout1, ue1 = self.run_main("setup", "--undo")
        self.assertEqual(u1, 0, ue1)
        self.assertIn("changed since setup; left as is", uout1)
        self.assertEqual(claude_file.read_text(encoding="utf-8"), "# user edited\n")

        # Tampered manifest: path points elsewhere (<tmp>/etc/agy) and backup outside setup_dir
        etc_agy = self.temp / "etc" / "agy"
        etc_agy.mkdir(parents=True)
        (etc_agy / "SKILL.md").write_text("keep", encoding="utf-8")
        outside_bak = self.temp / "outside_bak.md"
        outside_bak.write_text("evil", encoding="utf-8")
        bad_mf = self.setup_dir / "20261201T000000Z" / "manifest.json"
        bad_mf.parent.mkdir(parents=True, exist_ok=True)
        bad_mf.write_text(json.dumps({
            "version": 1,
            "created": "2026-12-01T00:00:00Z",
            "undone": None,
            "backups": [],
            "actions": [{"id": "tampered-skill", "applied": True, "changes": [
                {
                    "kind": "skill-installed",
                    "host": "claude-code",
                    "path": str(etc_agy),
                    "sha256": "0" * 64,
                    "previous": None,
                    "created_dirs": [],
                },
                {
                    "kind": "skill-installed",
                    "host": "claude-code",
                    "path": str(self.claude_home / "skills" / "agy"),
                    "sha256": "0" * 64,
                    "previous": {"backup": str(outside_bak), "sha256": "1" * 64},
                    "created_dirs": [],
                },
                {
                    "kind": "skill-installed",
                    "host": "claude-code",
                    "path": str(self.claude_home / "skills" / "agy"),
                    "sha256": "0" * 64,
                    "previous": None,
                    "created_dirs": [str(etc_agy)],
                },
            ]}],
        }), encoding="utf-8")
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            u2, uout2, ue2 = self.run_main("setup", "--undo")
        self.assertEqual(u2, 0, ue2)
        self.assertEqual(uout2.count("refusing "), 3)
        self.assertEqual((etc_agy / "SKILL.md").read_text(encoding="utf-8"), "keep")

    def test_setup_wingman_skill_drift_outdated_and_modified(self):
        import json
        # Old copy without skills/agy/SKILL.md -> outdated (not modified), offered by setup, warned by doctor
        old_copy = _create_fake_wingman_copy(
            self.wingman_dir, self.plugins_dir, profile="default",
            setup_dir=self.setup_dir, include_skill=False,
        )
        ws_old = agy._wingman_state()
        drift_old = agy._wingman_install_drift(ws_old)
        self.assertFalse(drift_old["modified"])
        self.assertTrue(drift_old["outdated"])

        self.gemini_config.write_text(json.dumps({
            "userSettings": {"globalPermissionGrants": {"allow": ["read_file(/custom)"]}},
        }), encoding="utf-8")
        self.use_rpc({"GetMcpServerStates": {"states": []}, "RetrieveUserQuotaSummary": {"response": {"groups": []}},
                      "GetAvailableModels": AVAILABLE, "GetCascadeModelConfigData": CONFIG})
        pcode, pout, perr = self.run_main("setup")
        self.assertEqual(pcode, 0, perr)
        self.assertIn("update the wingman plugin", pout)
        dcode, dout, derr = self.run_main("doctor", "--json")
        self.assertEqual(dcode, 0, derr)
        by_name = {(c["section"], c["name"]): c for c in json.loads(dout)["checks"]}
        self.assertEqual(by_name[("permissions", "wingman")]["level"], "WARN")
        self.assertIn("update available: agy setup", by_name[("permissions", "wingman")]["detail"])

        # Re-apply installs into a fresh timestamped dir (never overwrites old_copy in place);
        # editing the new live copy's SKILL.md -> modified
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            acode, _, aerr = self.run_main("setup", "--apply")
        self.assertEqual(acode, 0, aerr)
        self.assertFalse((old_copy / "skills" / "agy" / "SKILL.md").exists())
        ws_cur = agy._wingman_state()
        new_copy = ws_cur["installed_dir"]
        self.assertNotEqual(new_copy.resolve(), old_copy.resolve())
        self.assertTrue((new_copy / "skills" / "agy" / "SKILL.md").is_file())
        self.assertEqual(agy._wingman_install_drift(ws_cur), {"modified": False, "outdated": False})

        (new_copy / "skills" / "agy" / "SKILL.md").write_text("# edited in place\n", encoding="utf-8")
        agy._WINGMAN_SELFTEST_CACHE.clear()
        drift_mod = agy._wingman_install_drift(agy._wingman_state())
        self.assertTrue(drift_mod["modified"])
        d2code, d2out, d2err = self.run_main("doctor", "--json")
        self.assertEqual(d2code, 0, d2err)
        by_name2 = {(c["section"], c["name"]): c for c in json.loads(d2out)["checks"]}
        self.assertEqual(by_name2[("permissions", "wingman")]["level"], "WARN")
        self.assertIn("installed copy changed since install", by_name2[("permissions", "wingman")]["detail"])

    def test_setup_install_plugin_same_rev_creates_fresh_dir_and_undo_restores_old_link(self):
        self.use_rpc({"GetMcpServerStates": {"states": []}})
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            c1, _, e1 = self.run_main("setup", "--apply")
        self.assertEqual(c1, 0, e1)

        link_path = self.plugins_dir / "wingman"
        old_copy = link_path.resolve()
        # Modify existing live copy so setup offers update on the same git rev
        (old_copy / "hook.py").write_bytes((old_copy / "hook.py").read_bytes() + b"\n# local edit\n")
        agy._WINGMAN_SELFTEST_CACHE.clear()
        old_snapshot = {
            str(p.relative_to(old_copy)): p.read_bytes()
            for p in sorted(old_copy.rglob("*")) if p.is_file()
        }

        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            c2, _, e2 = self.run_main("setup", "--apply")
        self.assertEqual(c2, 0, e2)

        new_copy = link_path.resolve()
        self.assertNotEqual(new_copy, old_copy)
        self.assertTrue(new_copy.name.startswith(f"{old_copy.name}-"))
        # Old directory stayed byte-identical
        after_snapshot = {
            str(p.relative_to(old_copy)): p.read_bytes()
            for p in sorted(old_copy.rglob("*")) if p.is_file()
        }
        self.assertEqual(after_snapshot, old_snapshot)

        # Undo points symlink back to old_copy and removes new_copy
        with patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            uc, _, ue = self.run_main("setup", "--undo")
        self.assertEqual(uc, 0, ue)
        self.assertEqual(link_path.resolve(), old_copy)
        self.assertFalse(new_copy.exists())


class ApiKeyTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(agy.subprocess, "run", side_effect=AssertionError("real subprocess forbidden")))
        self.stack.enter_context(patch.object(agy.urllib.request, "urlopen", side_effect=AssertionError("network forbidden")))

    def test_api_account_default_env_override_and_no_account_fallback(self):
        import getpass
        if not os.environ.get("AGY_API_KEY_ACCOUNT"):
            self.assertEqual(agy.API_ACCOUNT, getpass.getuser())

        seen = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            seen.append(cmd)
            # Only the no-account fallback on the second service returns a key.
            if cmd == ["security", "find-generic-password", "-s", "GEMINI_API_KEY", "-w"]:
                return subprocess.CompletedProcess(cmd, 0, "FAKEKEY-FROM-FALLBACK-123456\n", "")
            return subprocess.CompletedProcess(cmd, 44, "", "not found")

        clean_env = dict(os.environ)
        clean_env.pop("GEMINI_API_KEY", None)
        clean_env.pop("AGY_API_KEY_ACCOUNT", None)
        with patch.dict(os.environ, clean_env, clear=True), \
             patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.getpass, "getuser", return_value="alice"):
            self.assertEqual(agy._api_account(), "alice")
            self.assertEqual(agy._api_key(), "FAKEKEY-FROM-FALLBACK-123456")

        self.assertEqual(seen, [
            ["security", "find-generic-password", "-s", "gemini-api-key", "-a", "alice", "-w"],
            ["security", "find-generic-password", "-s", "gemini-api-key", "-w"],
            ["security", "find-generic-password", "-s", "GEMINI_API_KEY", "-a", "alice", "-w"],
            ["security", "find-generic-password", "-s", "GEMINI_API_KEY", "-w"],
        ])

        seen.clear()
        with patch.dict(os.environ, {**clean_env, "AGY_API_KEY_ACCOUNT": "bob"}, clear=True), \
             patch.object(agy, "_run", side_effect=fake_run):
            self.assertEqual(agy._api_account(), "bob")
            agy._api_key()
        self.assertEqual(seen[0], ["security", "find-generic-password", "-s", "gemini-api-key", "-a", "bob", "-w"])

        # Env GEMINI_API_KEY still wins first without touching Keychain.
        seen.clear()
        with patch.dict(os.environ, {**clean_env, "GEMINI_API_KEY": "FAKE-ENV-KEY-123456789012"}, clear=True), \
             patch.object(agy, "_run", side_effect=fake_run):
            self.assertEqual(agy._api_key(), "FAKE-ENV-KEY-123456789012")
        self.assertEqual(seen, [])


class SetupApiKeyTests(OfflineBase):
    KEY_1 = "AIzaSyFakeKeyAlpha_00000001"
    KEY_2 = "AIzaSyFakeKeyBeta__00000002"
    KEY_3 = "AIzaSyFakeKeyGamma_00000003"
    KEY_BAD = "AIzaSyFakeKeyInval_00000004"

    def setUp(self):
        self._real_api_key = agy._api_key
        super().setUp()
        self.home = self.temp / "home"
        self.home.mkdir()
        self.setup_dir = self.temp / "setup"
        self.stack.enter_context(patch.object(agy.subprocess, "run", side_effect=self._real_subprocess_run))
        self.stack.enter_context(patch.object(agy, "_agy_git_rev", return_value="abc1234"))
        _create_fake_wingman_copy(self.wingman_dir, self.plugins_dir, rev="abc1234", setup_dir=self.setup_dir)
        self.gemini_config.write_text('{"userSettings": {"globalPermissionGrants": {"allow": []}}}', encoding="utf-8")

        clean = {
            "HOME": str(self.home),
            "AGY_SETUP_DIR": str(self.setup_dir),
            "AGY_API_KEY_ACCOUNT": "testuser",
        }
        self.stack.enter_context(patch.dict(os.environ, clean))
        for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
            os.environ.pop(var, None)
        self.stack.enter_context(patch.object(agy, "_api_key", side_effect=self._real_api_key))
        self.use_rpc({"GetMcpServerStates": {"states": []}})

    def _assert_no_secret_leaked(self, text: str, *keys: str):
        for key in keys:
            self.assertNotIn(key, text)
            for i in range(len(key) - 5):
                sub = key[i:i + 6]
                self.assertNotIn(sub, text, f"6-char key substring leaked: {sub!r}")

    def _assert_security_argv_safe(self, recorded_cmds: list, *keys: str):
        for cmd in recorded_cmds:
            if not cmd or cmd[0] != "security":
                continue
            self.assertNotIn("dump-keychain", cmd)
            if "-s" in cmd:
                svc = cmd[cmd.index("-s") + 1]
                self.assertIn(svc, agy.API_KEY_SERVICES)
                self.assertNotEqual(svc, "gemini")
            for key in keys:
                for arg in cmd:
                    self.assertNotIn(key, arg)

    def _make_urlopen_mock(self, status_by_key: dict):
        requests = []

        class _Resp(io.BytesIO):
            def __init__(self, code=200):
                super().__init__(b'{"models": []}')
                self.status = code

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            requests.append((req, timeout))
            key = req.get_header("X-goog-api-key")
            outcome = status_by_key.get(key, 403)
            if isinstance(outcome, Exception):
                raise outcome
            if outcome == 200:
                return _Resp(200)
            raise agy.urllib.error.HTTPError(req.full_url, outcome, "err", {}, io.BytesIO(b"{}"))

        return requests, fake_urlopen

    def _latest_manifest(self):
        import json
        dirs = sorted(p for p in self.setup_dir.iterdir() if p.is_dir())
        self.assertTrue(dirs)
        mf = dirs[-1] / "manifest.json"
        return mf, json.loads(mf.read_text(encoding="utf-8"))

    def test_plan_mode_offered_when_missing_absent_when_present_and_makes_no_network_call(self):
        import json
        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append(cmd)
            if cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            return subprocess.CompletedProcess(cmd, 44, "", "not found")

        # Missing key -> offered, no network call and no `-w` secret lookup
        before_setup_entries = sorted(p.name for p in self.setup_dir.iterdir())
        with patch.object(agy, "_run", side_effect=fake_run):
            code, out, err = self.run_main("setup")
        self.assertEqual(code, 0, err)
        self.assertIn("api-key", out.lower().replace("gemini api key", "api-key"))
        self.assertIn("find an existing Gemini API key", out)
        self.assertIn("delete the Keychain item setup created", out)
        self._assert_security_argv_safe(recorded)
        for cmd in recorded:
            if cmd and cmd[0] == "security":
                self.assertNotIn("-w", cmd)
        self.assertEqual(sorted(p.name for p in self.setup_dir.iterdir()), before_setup_entries)

        # Present key -> absent via attribute-only lookup (never `-w`)
        recorded_present = []

        def fake_run_present(cmd, timeout=10, env=None, input=None):
            recorded_present.append(cmd)
            if cmd == ["security", "find-generic-password", "-s", "gemini-api-key", "-a", "testuser"]:
                return subprocess.CompletedProcess(cmd, 0, '"acct"<blob>="testuser"\n', "")
            return subprocess.CompletedProcess(cmd, 44, "", "")

        with patch.object(agy, "_run", side_effect=fake_run_present):
            code2, out2, err2 = self.run_main("setup")
        self.assertEqual(code2, 0, err2)
        self.assertIn("no actions needed", out2)
        for cmd in recorded_present:
            if cmd and cmd[0] == "security":
                self.assertNotIn("-w", cmd)
        self._assert_no_secret_leaked(out2 + err2, self.KEY_1)

        # doctor attribute-only check never passes `-w` either
        recorded_doc = []

        def fake_run_doc(cmd, **_kw):
            recorded_doc.append(cmd)
            if cmd and cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            if cmd == ["security", "find-generic-password", "-s", "gemini-api-key", "-a", "testuser"]:
                return subprocess.CompletedProcess(cmd, 0, '"acct"<blob>="testuser"\n', "")
            return subprocess.CompletedProcess(cmd, 44, "", "")

        with patch.object(agy, "_run", side_effect=fake_run_doc):
            checks = agy._doctor_api()
        self.assertEqual(checks[0]["level"], "OK")
        self.assertEqual(len(recorded_doc), 1)
        self.assertNotIn("-w", recorded_doc[0])

    def test_getpass_warning_aborts_without_reading(self):
        import getpass as _getpass
        import warnings as _warnings
        read_called = []

        def fake_getpass(prompt=""):
            _warnings.warn("Can not control echo on the terminal.", _getpass.GetPassWarning)
            read_called.append(True)
            return self.KEY_1

        with patch("builtins.input", side_effect=["n"]), \
             patch("getpass.getpass", side_effect=fake_getpass):
            buf = io.StringIO()
            err_buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err_buf):
                val, reason = agy._prompt_paste_api_key()
        self.assertIsNone(val)
        self.assertEqual(reason, "aborted")
        self.assertEqual(read_called, [])
        self.assertIn("refusing to read API key", err_buf.getvalue())

    def test_source_parsing_references_skipped_and_deduped(self):
        (self.home / ".gemini").mkdir(parents=True)
        (self.home / ".gemini" / ".env").write_text(
            f'export GEMINI_API_KEY="{self.KEY_2}" # from gemini env\n'
            f"GOOGLE_API_KEY='{self.KEY_1}'\n"
            'GEMINI_API_KEY="too-short"\n',
            encoding="utf-8",
        )
        (self.home / ".env").write_text(
            f"GEMINI_API_KEY={self.KEY_2} # duplicate of gemini/.env\n"
            "GOOGLE_API_KEY=$OTHER_VAR\n",
            encoding="utf-8",
        )
        (self.home / ".zshrc").write_text(
            "export GEMINI_API_KEY=$(security find-generic-password -w)\n"
            "export GOOGLE_API_KEY=`cat ~/.secret`\n"
            f'export GEMINI_API_KEY="{self.KEY_3}" # real zshrc key\n',
            encoding="utf-8",
        )
        (self.home / ".profile").write_text(
            f"GOOGLE_API_KEY={self.KEY_BAD}#inlinecomment\n",
            encoding="utf-8",
        )

        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append(cmd)
            if cmd == ["security", "find-generic-password", "-s", "GEMINI_API_KEY", "-w"]:
                return subprocess.CompletedProcess(cmd, 0, self.KEY_BAD + "\n", "")
            if cmd == ["security", "find-generic-password", "-s", "GEMINI_API_KEY"]:
                return subprocess.CompletedProcess(cmd, 0, '    "acct"<blob>="otheracct"\n', "")
            return subprocess.CompletedProcess(cmd, 44, "", "not found")

        with patch.dict(os.environ, {"GEMINI_API_KEY": self.KEY_1}), \
             patch.object(agy, "_run", side_effect=fake_run):
            cands = agy._discover_api_key_candidates()

        self._assert_security_argv_safe(recorded, self.KEY_1, self.KEY_2, self.KEY_3, self.KEY_BAD)
        # Deduped by value in exact source order: env wins over .gemini/.env, .gemini/.env over .env, .profile over Keychain
        self.assertEqual(
            [(c["key"], c["source"]) for c in cands],
            [
                (self.KEY_1, "env GEMINI_API_KEY"),
                (self.KEY_2, "~/.gemini/.env line 1"),
                (self.KEY_3, "~/.zshrc line 3"),
                (self.KEY_BAD, "~/.profile line 1"),
            ],
        )

    def test_validation_mapping_uses_header_never_url(self):
        reqs, fake_urlopen = self._make_urlopen_mock({
            self.KEY_1: 200,
            self.KEY_2: 400,
            self.KEY_BAD: 403,
            self.KEY_3: TimeoutError("timed out"),
        })
        with patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen):
            self.assertEqual(agy._validate_api_key(self.KEY_1), "valid")
            self.assertEqual(agy._validate_api_key(self.KEY_2), "invalid")
            self.assertEqual(agy._validate_api_key(self.KEY_BAD), "invalid")
            self.assertEqual(agy._validate_api_key(self.KEY_3), "unknown")

        for req, timeout in reqs:
            self.assertEqual(req.full_url, f"{agy.API_BASE}/models?pageSize=1")
            self.assertEqual(timeout, 10)
            self.assertTrue(req.get_header("X-goog-api-key"))
            for k in (self.KEY_1, self.KEY_2, self.KEY_BAD, self.KEY_3):
                self.assertNotIn(k, req.full_url)

    def test_flow_one_valid_stored_and_undo_deletes(self):
        (self.home / ".zshrc").write_text(f'export GEMINI_API_KEY="{self.KEY_1}"\n', encoding="utf-8")
        keychain = {}
        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append((cmd, input))
            if cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            if cmd == ["security", "-i"]:
                self.assertIn(f"add-generic-password -U -s gemini-api-key -a testuser -w {self.KEY_1}\n", input)
                keychain[("gemini-api-key", "testuser")] = self.KEY_1
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                svc = cmd[3]
                acct = cmd[cmd.index("-a") + 1] if "-a" in cmd else None
                val = keychain.get((svc, acct))
                if val is not None:
                    return subprocess.CompletedProcess(cmd, 0, val + "\n" if "-w" in cmd else '"acct"<blob>="testuser"\n', "")
                return subprocess.CompletedProcess(cmd, 44, "", "not found")
            if cmd[:3] == ["security", "delete-generic-password", "-s"]:
                svc = cmd[3]
                acct = cmd[cmd.index("-a") + 1]
                keychain.pop((svc, acct), None)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(f"unexpected _run: {cmd}")

        _, fake_urlopen = self._make_urlopen_mock({self.KEY_1: 200})
        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["y", "y", "y"]):
            code, out, err = self.run_main("setup", "--apply")

        self.assertEqual(code, 0, err)
        self._assert_no_secret_leaked(out + err, self.KEY_1)
        self._assert_security_argv_safe([c for c, _ in recorded], self.KEY_1)
        self.assertEqual(keychain[("gemini-api-key", "testuser")], self.KEY_1)
        self.assertIn(agy._key_fingerprint(self.KEY_1), out)
        self.assertIn("~/.zshrc line 1", out)

        mf_path, mf = self._latest_manifest()
        self._assert_no_secret_leaked(mf_path.read_text(encoding="utf-8"), self.KEY_1)
        change = mf["actions"][0]["changes"][0]
        self.assertEqual(change, {
            "kind": "keychain-item",
            "service": "gemini-api-key",
            "account": "testuser",
            "replaced": False,
            "fingerprint": agy._key_fingerprint(self.KEY_1),
        })

        # Undo deletes item when replaced is False
        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            ucode, uout, uerr = self.run_main("setup", "--undo")
        self.assertEqual(ucode, 0, uerr)
        self.assertNotIn(("gemini-api-key", "testuser"), keychain)
        self.assertIn("deleted Keychain item", uout)
        self._assert_no_secret_leaked(uout + uerr, self.KEY_1)

    def test_unsafe_account_name_aborts_before_any_store(self):
        os.environ["AGY_API_KEY_ACCOUNT"] = "bad name -w x"
        (self.home / ".zshrc").write_text(f'export GEMINI_API_KEY="{self.KEY_1}"\n', encoding="utf-8")
        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append(cmd)
            if cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            return subprocess.CompletedProcess(cmd, 44, "", "not found")

        _, fake_urlopen = self._make_urlopen_mock({self.KEY_1: 200})
        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["y", "y", "y"]):
            code, out, err = self.run_main("setup", "--apply")
        self.assertEqual(code, 1)
        self.assertIn("unsafe Keychain account name", err)
        self.assertNotIn(["security", "-i"], recorded)
        self._assert_no_secret_leaked(out + err, self.KEY_1)

    def test_flow_several_valid_pick_2(self):
        (self.home / ".env").write_text(
            f"GEMINI_API_KEY={self.KEY_1}\nGOOGLE_API_KEY={self.KEY_2}\n",
            encoding="utf-8",
        )
        keychain = {}
        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append((cmd, input))
            if cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            if cmd == ["security", "-i"]:
                keychain[("gemini-api-key", "testuser")] = input.strip().split()[-1]
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                svc = cmd[3]
                acct = cmd[cmd.index("-a") + 1] if "-a" in cmd else None
                val = keychain.get((svc, acct))
                if val is not None:
                    return subprocess.CompletedProcess(cmd, 0, val + "\n", "")
                return subprocess.CompletedProcess(cmd, 44, "", "not found")
            raise AssertionError(f"unexpected _run: {cmd}")

        _, fake_urlopen = self._make_urlopen_mock({self.KEY_1: 200, self.KEY_2: 200})
        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["y", "y", "2"]):
            code, out, err = self.run_main("setup", "--apply")

        self.assertEqual(code, 0, err)
        self.assertEqual(keychain[("gemini-api-key", "testuser")], self.KEY_2)
        self._assert_no_secret_leaked(out + err, self.KEY_1, self.KEY_2)
        self._assert_security_argv_safe([c for c, _ in recorded], self.KEY_1, self.KEY_2)

    def test_flow_none_valid_paste_valid_and_no_scan_goes_to_paste(self):
        keychain = {}
        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append((cmd, input))
            if cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            if cmd == ["security", "-i"]:
                keychain[("gemini-api-key", "testuser")] = input.strip().split()[-1]
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                svc = cmd[3]
                acct = cmd[cmd.index("-a") + 1] if "-a" in cmd else None
                val = keychain.get((svc, acct))
                if val is not None:
                    return subprocess.CompletedProcess(cmd, 0, val + "\n", "")
                return subprocess.CompletedProcess(cmd, 44, "", "")
            raise AssertionError(f"unexpected _run: {cmd}")

        # 1) Scan finds only an invalid key -> paste valid
        (self.home / ".env").write_text(f"GEMINI_API_KEY={self.KEY_BAD}\n", encoding="utf-8")
        _, fake_urlopen = self._make_urlopen_mock({self.KEY_BAD: 403, self.KEY_1: 200})
        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch.object(agy.sys, "platform", "darwin"), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["y", "y", "n"]), \
             patch("getpass.getpass", return_value=self.KEY_1):
            code, out, err = self.run_main("setup", "--apply")
        self.assertEqual(code, 0, err)
        self.assertIn("https://aistudio.google.com/apikey", out)
        self.assertEqual(keychain[("gemini-api-key", "testuser")], self.KEY_1)
        self._assert_no_secret_leaked(out + err, self.KEY_BAD, self.KEY_1)
        self._assert_security_argv_safe([c for c, _ in recorded], self.KEY_BAD, self.KEY_1)

        # 2) Answer "n" to scan -> goes straight to paste without scanning .env or validating KEY_BAD
        keychain.clear()
        recorded.clear()
        reqs, fake_urlopen2 = self._make_urlopen_mock({self.KEY_2: 200})
        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen2), \
             patch.object(agy.sys, "platform", "linux"), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["y", "n"]), \
             patch("getpass.getpass", return_value=self.KEY_2):
            code2, out2, err2 = self.run_main("setup", "--apply")
        self.assertEqual(code2, 0, err2)
        self.assertEqual(len(reqs), 1)  # only pasted KEY_2 validated, never KEY_BAD
        self.assertEqual(keychain[("gemini-api-key", "testuser")], self.KEY_2)
        self._assert_no_secret_leaked(out2 + err2, self.KEY_BAD, self.KEY_2)

    def test_new_dotted_key_format_is_accepted(self):
        # Newer AI Studio keys carry a "." after a short prefix; classic keys still pass, and
        # nothing that could split or extend the `security -i` line is accepted.
        dotted = "AQ.FakeNewFormatKeyBody_0123456789-abcdefghijklmnopq"
        self.assertTrue(agy._is_valid_api_key_format(dotted))
        self.assertTrue(agy._is_valid_api_key_format(self.KEY_1))
        for bad in ("AQ.FakeNewFormat Key_0123456789", 'AQ.FakeNewFormat"Key_0123456789',
                    "AQ.FakeNewFormat$Key_0123456789", "AQ.FakeNewFormat\nKey_012345678", "short.key"):
            self.assertFalse(agy._is_valid_api_key_format(bad), bad)

        keychain = {}
        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append((cmd, input))
            if cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            if cmd == ["security", "-i"]:
                keychain[("gemini-api-key", "testuser")] = input.strip().split()[-1]
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                svc = cmd[3]
                acct = cmd[cmd.index("-a") + 1] if "-a" in cmd else None
                val = keychain.get((svc, acct))
                if val is not None:
                    return subprocess.CompletedProcess(cmd, 0, val + "\n", "")
                return subprocess.CompletedProcess(cmd, 44, "", "")
            raise AssertionError(f"unexpected _run: {cmd}")

        _, fake_urlopen = self._make_urlopen_mock({dotted: 200})
        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch.object(agy.sys, "platform", "linux"), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["y", "n"]), \
             patch("getpass.getpass", return_value=dotted + "\n"):
            code, out, err = self.run_main("setup", "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(keychain[("gemini-api-key", "testuser")], dotted)
        self._assert_no_secret_leaked(out + err, dotted)
        self._assert_security_argv_safe([c for c, _ in recorded], dotted)

    def test_flow_paste_invalid_twice_skips_and_stores_nothing(self):
        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append(cmd)
            if cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                return subprocess.CompletedProcess(cmd, 44, "", "")
            raise AssertionError(f"unexpected _run (must not store): {cmd}")

        _, fake_urlopen = self._make_urlopen_mock({self.KEY_BAD: 401})
        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch.object(agy.sys, "platform", "linux"), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", side_effect=["y", "n"]), \
             patch("getpass.getpass", side_effect=["short", self.KEY_BAD]):
            code, out, err = self.run_main("setup", "--apply")

        self.assertEqual(code, 0, err)
        self.assertIn("skipped", out)
        self._assert_no_secret_leaked(out + err, self.KEY_BAD)
        self.assertNotIn(["security", "-i"], recorded)
        _, mf = self._latest_manifest()
        self.assertFalse(mf["actions"][0]["applied"])
        self.assertEqual(mf["actions"][0]["changes"], [])

    def test_undo_replaced_true_prints_cannot_restore_and_does_not_delete(self):
        import json
        run_dir = self.setup_dir / "20261115T000000Z"
        run_dir.mkdir(parents=True)
        (run_dir / "manifest.json").write_text(json.dumps({
            "version": 1,
            "created": "2026-11-15T00:00:00Z",
            "agy_rev": "abc1234",
            "actions": [{
                "id": "api-key",
                "title": "configure a Gemini API key",
                "applied": True,
                "changes": [{
                    "kind": "keychain-item",
                    "service": "gemini-api-key",
                    "account": "testuser",
                    "replaced": True,
                }],
            }],
            "backups": [],
            "undone": None,
        }), encoding="utf-8")

        recorded = []

        def fake_run(cmd, timeout=10, env=None, input=None):
            recorded.append(cmd)
            raise AssertionError(f"must not call _run on replaced=True undo: {cmd}")

        with patch.object(agy, "_run", side_effect=fake_run), \
             patch.object(agy.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="y"):
            code, out, err = self.run_main("setup", "--undo")

        self.assertEqual(code, 0, err)
        self.assertEqual(recorded, [])
        self.assertIn("the previous Keychain value cannot be restored (setup never stores secrets); left as is", out)

    def test_already_stored_records_nothing_and_darwin_open_browser_and_replaced_apply(self):
        # 1) Already stored in agy's own slot -> records applied=False, no security -i
        (self.home / ".env").write_text(f"GEMINI_API_KEY={self.KEY_1}\n", encoding="utf-8")
        keychain = {("gemini-api-key", "testuser"): self.KEY_1}
        recorded = []

        def fake_subproc_run(cmd, **kwargs):
            recorded.append((cmd, kwargs.get("input")))
            if cmd[:2] == ["git", "-C"]:
                return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
            if cmd == ["security", "-i"]:
                keychain[("gemini-api-key", "testuser")] = kwargs["input"].strip().split()[-1]
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                svc = cmd[3]
                acct = cmd[cmd.index("-a") + 1] if "-a" in cmd else None
                val = keychain.get((svc, acct))
                if val is not None:
                    return subprocess.CompletedProcess(cmd, 0, val + "\n", "")
                return subprocess.CompletedProcess(cmd, 44, "", "")
            if cmd[:2] == ["open", agy._AISTUDIO_APIKEY_URL]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(f"unexpected subprocess.run: {cmd}")

        _, fake_urlopen = self._make_urlopen_mock({self.KEY_1: 200, self.KEY_2: 200})
        # Use _apply_api_key directly when slot already holds KEY_1
        with patch.object(agy.subprocess, "run", side_effect=fake_subproc_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch("builtins.input", side_effect=["y", "y"]):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ok, changes, err = agy._apply_api_key()
        self.assertTrue(ok)
        self.assertEqual(changes, [])
        self.assertEqual(err, "skipped")
        self.assertIn("already stored", buf.getvalue())
        self.assertNotIn(["security", "-i"], [c for c, _ in recorded])

        # 2) Existing different value in agy's slot + darwin open browser -> replaced=True
        keychain[("gemini-api-key", "testuser")] = "old-different-value-placeholder"
        recorded.clear()
        with patch.object(agy.subprocess, "run", side_effect=fake_subproc_run), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch.object(agy.sys, "platform", "darwin"), \
             patch("builtins.input", side_effect=["n", "y"]), \
             patch("getpass.getpass", return_value=self.KEY_2):
            buf2 = io.StringIO()
            with contextlib.redirect_stdout(buf2):
                ok2, changes2, err2 = agy._apply_api_key()
        self.assertTrue(ok2)
        self.assertEqual(err2, "")
        self.assertEqual(changes2, [{
            "kind": "keychain-item",
            "service": "gemini-api-key",
            "account": "testuser",
            "replaced": True,
            "fingerprint": agy._key_fingerprint(self.KEY_2),
        }])
        self.assertIn(["open", agy._AISTUDIO_APIKEY_URL], [c for c, _ in recorded])
        self._assert_security_argv_safe([c for c, _ in recorded], self.KEY_2)
        self._assert_no_secret_leaked(buf2.getvalue(), self.KEY_2)

    def test_api_key_lookup_error_aborts_readback_cleans_up_and_undo_checks_fingerprint(self):
        # 1) Lookup error rc != 0 and != 44 aborts before storing
        _, fake_urlopen = self._make_urlopen_mock({self.KEY_1: 200})

        def fail_lookup(cmd, **_kw):
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                return subprocess.CompletedProcess(cmd, 36, "", "keychain locked")
            raise AssertionError(f"unexpected subprocess.run: {cmd}")

        with patch.object(agy.subprocess, "run", side_effect=fail_lookup), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch("builtins.input", side_effect=["n", "n"]), \
             patch("getpass.getpass", return_value=self.KEY_1):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ok, changes, err = agy._apply_api_key()
        self.assertFalse(ok)
        self.assertEqual(changes, [])
        self.assertIn("failed to inspect Keychain", err)

        # 2) Store succeeds (rc 0) for new item, readback fails, rollback deletes created item
        deleted = []

        def fake_readback_fail_del_ok(cmd, **_kw):
            if cmd == ["security", "-i"]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                return subprocess.CompletedProcess(cmd, 44, "", "")
            if cmd[:3] == ["security", "delete-generic-password", "-s"]:
                deleted.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(f"unexpected subprocess.run: {cmd}")

        with patch.object(agy.subprocess, "run", side_effect=fake_readback_fail_del_ok), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch("builtins.input", side_effect=["n", "n"]), \
             patch("getpass.getpass", return_value=self.KEY_1):
            buf2 = io.StringIO()
            with contextlib.redirect_stdout(buf2):
                ok2, changes2, err2 = agy._apply_api_key()
        self.assertFalse(ok2)
        self.assertEqual(changes2, [])
        self.assertIn("could not be verified", err2)
        self.assertEqual(deleted, [["security", "delete-generic-password", "-s", "gemini-api-key", "-a", "testuser"]])

        # 3) If delete-on-rollback fails, the created keychain-item stays recorded with fingerprint
        def fake_readback_fail_del_fail(cmd, **_kw):
            if cmd == ["security", "-i"]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:3] == ["security", "find-generic-password", "-s"]:
                return subprocess.CompletedProcess(cmd, 44, "", "")
            if cmd[:3] == ["security", "delete-generic-password", "-s"]:
                return subprocess.CompletedProcess(cmd, 1, "", "delete failed")
            raise AssertionError(f"unexpected subprocess.run: {cmd}")

        recorded_partial = []
        with patch.object(agy.subprocess, "run", side_effect=fake_readback_fail_del_fail), \
             patch.object(agy.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch("builtins.input", side_effect=["n", "n"]), \
             patch("getpass.getpass", return_value=self.KEY_1):
            buf3 = io.StringIO()
            with contextlib.redirect_stdout(buf3):
                ok3, _, err3 = agy._apply_api_key(changes=recorded_partial)
        self.assertFalse(ok3)
        self.assertIn("could not be verified", err3)
        self.assertEqual(len(recorded_partial), 1)
        self.assertEqual(recorded_partial[0]["fingerprint"], agy._key_fingerprint(self.KEY_1))

        # 4) Undo with mismatched Keychain value refuses deletion and never prints the value
        other_secret = "AIzaSyDifferentSecretValue0000000000000"
        del_calls = []

        def fake_undo_mismatch(cmd, **_kw):
            if cmd == ["security", "find-generic-password", "-s", "gemini-api-key", "-a", "testuser", "-w"]:
                return subprocess.CompletedProcess(cmd, 0, other_secret + "\n", "")
            if cmd[:3] == ["security", "delete-generic-password", "-s"]:
                del_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(f"unexpected subprocess.run: {cmd}")

        with patch.object(agy.subprocess, "run", side_effect=fake_undo_mismatch):
            buf4 = io.StringIO()
            with contextlib.redirect_stdout(buf4):
                agy._undo_change({
                    "kind": "keychain-item",
                    "service": "gemini-api-key",
                    "account": "testuser",
                    "replaced": False,
                    "fingerprint": agy._key_fingerprint(self.KEY_1),
                })
        msg = buf4.getvalue()
        self.assertIn("changed since setup", msg)
        self.assertEqual(del_calls, [])
        self._assert_no_secret_leaked(msg, other_secret)


if __name__ == "__main__":
    unittest.main(verbosity=2)
