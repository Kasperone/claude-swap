"""Windows Credential Manager mode: detection and the switch refusal.

Detection runs on any OS against fakes (env vars, configs under tmp_path, a
stubbed target enumeration). The ``real_credman`` tests run only on the
GitHub Actions Windows runner (CSWAP_CI_CREDMAN=1): they create a throwaway
generic credential with a fake value, in Bun.secrets' "<service>/<account>"
form, and remove it again. Fake credentials only.
"""

from __future__ import annotations

import json
import os
import sys
import types
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import windows_credman
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.exceptions import SwitchError
from claude_swap.models import Platform
from claude_swap.session import keychain_service_name
from claude_swap.switcher import ClaudeAccountSwitcher

# Captured before conftest's block_real_credman stubs the module attribute.
REAL_ENUMERATE = windows_credman._enumerate_targets

DESIGN = {"accessToken": "fake-design-at"}
LIVE = json.dumps({"claudeAiOauth": {"accessToken": "fake-1"}, "designOauth": DESIGN})
TARGET = json.dumps({"claudeAiOauth": {"accessToken": "fake-2"}})

real_credman = pytest.mark.skipif(
    not (sys.platform == "win32" and os.environ.get("CSWAP_CI_CREDMAN") == "1"),
    reason="writes a throwaway Credential Manager entry; Windows CI only",
)


def _on(monkeypatch, platform: str) -> None:
    """The module's view of sys.platform only (never the global sys)."""
    monkeypatch.setattr(windows_credman, "sys", types.SimpleNamespace(platform=platform))


def _targets(monkeypatch, *names: str) -> list[str]:
    """Stub the enumeration with ``names`` and pretend to be on Windows."""
    seen: list[str] = []

    def fake(pattern: str) -> list[str]:
        seen.append(pattern)
        prefix = pattern.rstrip("*")
        return [n for n in names if n.startswith(prefix)]

    monkeypatch.setattr(windows_credman, "_enumerate_targets", fake)
    _on(monkeypatch, "win32")
    return seen


def _flag(path: Path, value) -> None:
    path.write_text(json.dumps({"cachedGrowthBookFeatures": {"tengu_windows_credman": value}}))


class TestDetect:
    def test_plain_file_mode(self, temp_home, monkeypatch):
        _targets(monkeypatch)
        _flag(temp_home / ".claude.json", False)
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None

    def test_no_config_at_all(self, temp_home, monkeypatch):
        _targets(monkeypatch)
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None

    def test_env_var_opts_in(self, temp_home, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE_FORCE_WINDOWS_CREDMAN", "1")
        mode = windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE])
        assert mode.state == windows_credman.ACTIVE
        assert "CLAUDE_CODE_FORCE_WINDOWS_CREDMAN=1" in mode.reason

    def test_env_var_other_value_is_not_an_opt_in(self, temp_home, monkeypatch):
        _targets(monkeypatch)
        monkeypatch.setenv("CLAUDE_CODE_FORCE_WINDOWS_CREDMAN", "true")
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None

    def test_cached_flag_opts_in(self, temp_home):
        _flag(temp_home / ".claude.json", True)
        mode = windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE])
        assert mode.state == windows_credman.ACTIVE
        assert "tengu_windows_credman" in mode.reason

    def test_flag_read_from_the_legacy_config_when_non_empty(self, temp_home, monkeypatch):
        _targets(monkeypatch)
        _flag(temp_home / ".claude" / ".config.json", True)
        _flag(temp_home / ".claude.json", False)
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]).state == "active"

        (temp_home / ".claude" / ".config.json").write_text("")
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None

    def test_flag_read_from_the_profile_config(self, temp_home, monkeypatch):
        _targets(monkeypatch)
        profile = temp_home / "work"
        profile.mkdir()
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(profile))
        _flag(temp_home / ".claude.json", True)  # the default profile's: ignored
        assert windows_credman.detect([keychain_service_name(str(profile))]) is None
        _flag(profile / ".claude.json", True)
        assert windows_credman.detect([keychain_service_name(str(profile))]).state == "active"

    def test_unparseable_config_counts_as_off_like_claude_code(self, temp_home, monkeypatch):
        _targets(monkeypatch)
        (temp_home / ".claude.json").write_text('{"cachedGrowthBookFeatures": {"tengu_wi')
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None

    def test_unreadable_config_is_ambiguous(self, temp_home, monkeypatch):
        _targets(monkeypatch)
        (temp_home / ".claude.json").mkdir()  # exists, cannot be read as a file
        mode = windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE])
        assert mode.state == windows_credman.AMBIGUOUS
        assert "could not be read" in mode.reason

    @pytest.mark.parametrize("account", ["user", "claude-code-user", "user#m"])
    def test_entry_without_opt_in_is_ambiguous(self, temp_home, monkeypatch, account):
        seen = _targets(monkeypatch, f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/{account}")
        mode = windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE])
        assert mode.state == windows_credman.AMBIGUOUS
        assert seen == [f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/*"]

    def test_another_profiles_entry_is_not_this_profiles(self, temp_home, monkeypatch):
        other = keychain_service_name(str(temp_home / "elsewhere"))
        _targets(monkeypatch, f"{other}/user", "Claude Code/user")
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None

    def test_enumeration_failure_does_not_block(self, temp_home, monkeypatch):
        def broken(pattern):
            raise OSError("advapi32 unavailable")

        monkeypatch.setattr(windows_credman, "_enumerate_targets", broken)
        _on(monkeypatch, "win32")
        assert windows_credman.entry_present([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None

    def test_not_windows_never_enumerates(self, monkeypatch):
        _on(monkeypatch, "linux")
        with patch.object(windows_credman, "_enumerate_targets", side_effect=AssertionError):
            assert windows_credman.entry_present([CLAUDE_CODE_KEYCHAIN_SERVICE]) is None

    def test_module_has_no_way_to_read_or_change_entries(self):
        source = Path(windows_credman.__file__).read_text(encoding="utf-8")
        for api in ("CredReadW", "CredWriteW", "CredDeleteW", "CredentialBlob"):
            assert api not in source


def _switcher(platform: Platform) -> ClaudeAccountSwitcher:
    sw = ClaudeAccountSwitcher()
    sw.platform = platform
    sw._setup_directories()
    sw._init_sequence_file()
    data = sw._get_sequence_data()
    for num, token in (("1", LIVE), ("2", TARGET)):
        email = f"{num}@x.com"
        sw._write_account_credentials(num, email, token)
        sw._write_account_config(num, email, json.dumps({
            "oauthAccount": {"emailAddress": email, "accountUuid": f"u{num}"}}))
        data["accounts"][num] = {
            "email": email, "uuid": f"u{num}", "organizationUuid": "",
            "organizationName": "", "added": "2024-01-01T00:00:00Z",
        }
    data["sequence"] = [1, 2]
    data["activeAccountNumber"] = 1
    sw._write_json(sw.sequence_file, data)
    return sw


@pytest.fixture
def windows(temp_home, monkeypatch):
    monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.WINDOWS))
    cred = temp_home / ".claude" / ".credentials.json"
    cred.write_text(LIVE)
    (temp_home / ".claude.json").write_text(json.dumps({
        "oauthAccount": {"emailAddress": "1@x.com", "accountUuid": "u1"}}))
    return cred


def _enable_flag(home: Path) -> None:
    cfg = home / ".claude.json"
    data = json.loads(cfg.read_text())
    data["cachedGrowthBookFeatures"] = {"tengu_windows_credman": True}
    cfg.write_text(json.dumps(data))


class TestSwitchOnWindows:
    def test_not_detected_switches(self, windows):
        _switcher(Platform.WINDOWS).switch_to("2", json_output=True)
        written = json.loads(windows.read_text())
        assert written == {"claudeAiOauth": {"accessToken": "fake-2"}, "designOauth": DESIGN}

    def test_detected_refuses_and_changes_nothing(self, windows, temp_home):
        _enable_flag(temp_home)
        sw = _switcher(Platform.WINDOWS)
        seq_before = sw.sequence_file.read_text()

        with pytest.raises(SwitchError) as exc:
            sw.switch_to("2", json_output=True)

        msg = str(exc.value)
        assert "is using Windows Credential Manager" in msg
        assert "tengu_windows_credman" in msg
        assert str(windows) in msg and "--ignore-credman" in msg
        assert "CSWAP_IGNORE_CREDMAN=1" in msg
        assert windows.read_text() == LIVE
        assert sw.sequence_file.read_text() == seq_before

    def test_env_opt_in_refuses_bare_switch_too(self, windows, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE_FORCE_WINDOWS_CREDMAN", "1")
        with pytest.raises(SwitchError, match="CLAUDE_CODE_FORCE_WINDOWS_CREDMAN=1"):
            _switcher(Platform.WINDOWS).switch(json_output=True)
        assert windows.read_text() == LIVE

    def test_ambiguous_refuses(self, windows, monkeypatch):
        _targets(monkeypatch, f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/user")
        with pytest.raises(SwitchError, match="may be using Windows Credential Manager"):
            _switcher(Platform.WINDOWS).switch_to("2", json_output=True)
        assert windows.read_text() == LIVE

    def test_override_attribute_switches(self, windows, temp_home):
        _enable_flag(temp_home)
        sw = _switcher(Platform.WINDOWS)
        sw.ignore_credman = True
        sw.switch_to("2", json_output=True)
        assert json.loads(windows.read_text())["claudeAiOauth"]["accessToken"] == "fake-2"

    def test_override_env_switches(self, windows, temp_home, monkeypatch):
        _enable_flag(temp_home)
        monkeypatch.setenv("CSWAP_IGNORE_CREDMAN", "1")
        _switcher(Platform.WINDOWS).switch_to("2", json_output=True)
        assert json.loads(windows.read_text())["designOauth"] == DESIGN


class TestOtherPlatformsUnaffected:
    @pytest.mark.parametrize("platform", [Platform.LINUX, Platform.MACOS, Platform.WSL])
    def test_guard_is_a_no_op(self, temp_home, monkeypatch, platform):
        monkeypatch.setenv("CLAUDE_CODE_FORCE_WINDOWS_CREDMAN", "1")
        _flag(temp_home / ".claude.json", True)
        sw = ClaudeAccountSwitcher()
        sw.platform = platform
        with patch.object(windows_credman, "detect", side_effect=AssertionError):
            sw._refuse_windows_credman()

    def test_linux_switch_ignores_every_signal(self, temp_home, monkeypatch):
        monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.LINUX))
        monkeypatch.setenv("CLAUDE_CODE_FORCE_WINDOWS_CREDMAN", "1")
        _targets(monkeypatch, f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/user")
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(LIVE)
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "1@x.com", "accountUuid": "u1"},
            "cachedGrowthBookFeatures": {"tengu_windows_credman": True}}))

        _switcher(Platform.LINUX).switch_to("2", json_output=True)

        assert json.loads(cred.read_text()) == {
            "claudeAiOauth": {"accessToken": "fake-2"}, "designOauth": DESIGN}


class TestCli:
    def _run(self, argv, monkeypatch):
        from claude_swap import cli

        seen = {}

        def fake_switch_to(self, target, json_output=False, force=False):
            seen["ignore"] = self.ignore_credman
            return None

        monkeypatch.setattr(sys, "argv", ["cswap", *argv])
        monkeypatch.setattr(ClaudeAccountSwitcher, "switch_to", fake_switch_to)
        cli.main()
        return seen

    def test_flag_sets_the_override(self, temp_home, monkeypatch):
        assert self._run(["switch", "2", "--ignore-credman"], monkeypatch) == {"ignore": True}
        assert self._run(["switch", "2"], monkeypatch) == {"ignore": False}

    def test_flag_only_with_switch(self, temp_home, monkeypatch, capsys):
        with pytest.raises(SystemExit):
            self._run(["list", "--ignore-credman"], monkeypatch)
        assert "--ignore-credman can only be used with 'switch'" in capsys.readouterr().err


def _cred_api():
    import ctypes
    from ctypes import wintypes

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    def write(target: str, value: bytes) -> None:
        buf = ctypes.create_string_buffer(value, len(value))
        cred = CREDENTIALW(
            Type=1, TargetName=target, CredentialBlobSize=len(value),
            CredentialBlob=ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)),
            Persist=2, UserName="cswap-ci",
        )
        if not advapi32.CredWriteW(ctypes.byref(cred), 0):
            raise ctypes.WinError(ctypes.get_last_error())

    def delete(target: str) -> None:
        advapi32.CredDeleteW(target, 1, 0)

    return write, delete


@real_credman
class TestRealCredentialManager:
    """Against the runner's real Credential Manager, with throwaway entries."""

    @pytest.fixture
    def entry(self):
        write, delete = _cred_api()
        created: list[str] = []

        def make(target: str) -> None:
            write(target, b"fake-ci-value")
            created.append(target)

        yield make
        for target in created:
            delete(target)

    def test_enumeration_finds_exactly_this_service(self, entry):
        service = f"cswap-ci-{uuid.uuid4().hex[:8]}"
        assert REAL_ENUMERATE(f"{service}/*") == []
        entry(f"{service}/user")
        entry(f"{service}/user#m")
        entry(f"{service}-other/user")
        assert sorted(REAL_ENUMERATE(f"{service}/*")) == [f"{service}/user", f"{service}/user#m"]

    def test_entry_present_with_the_real_api(self, entry, monkeypatch):
        monkeypatch.setattr(windows_credman, "_enumerate_targets", REAL_ENUMERATE)
        service = f"cswap-ci-{uuid.uuid4().hex[:8]}"
        assert windows_credman.entry_present([service]) is False
        entry(f"{service}/user")
        assert windows_credman.entry_present([service]) is True

    def test_switch_refuses_on_a_real_claude_code_entry(self, entry, windows, monkeypatch):
        """A real entry in Claude Code's own service makes the switch refuse,
        and the entry is left exactly as it was."""
        monkeypatch.setattr(windows_credman, "_enumerate_targets", REAL_ENUMERATE)
        target = f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/cswap-ci-{uuid.uuid4().hex[:8]}"
        if REAL_ENUMERATE(f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/*"):
            pytest.skip("runner already has a Claude Code entry; never touch it")
        entry(target)

        with pytest.raises(SwitchError, match="may be using Windows Credential Manager"):
            _switcher(Platform.WINDOWS).switch_to("2", json_output=True)

        assert windows.read_text() == LIVE
        assert REAL_ENUMERATE(f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/*") == [target]
