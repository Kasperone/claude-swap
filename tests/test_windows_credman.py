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
from claude_swap.exceptions import SessionError, SwitchError
from claude_swap.models import Platform
from claude_swap.session import keychain_service_name
from claude_swap.switcher import ClaudeAccountSwitcher

# Captured before conftest's block_real_credman stubs the module attribute.
REAL_ENUMERATE = windows_credman._enumerate_targets

DESIGN = {"accessToken": "fake-design-at"}
DESIGN_2 = {"accessToken": "fake-design-2-at"}
LIVE = json.dumps({"claudeAiOauth": {"accessToken": "fake-1"}, "designOauth": DESIGN})
TARGET = json.dumps({"claudeAiOauth": {"accessToken": "fake-2"}, "designOauth": DESIGN_2})

real_credman = pytest.mark.skipif(
    not (sys.platform == "win32" and os.environ.get("CSWAP_CI_CREDMAN") == "1"),
    reason="writes a throwaway Credential Manager entry; Windows CI only",
)


def _on(monkeypatch, platform: str) -> None:
    """The module's view of sys.platform only (never the global sys)."""
    monkeypatch.setattr(windows_credman, "sys", types.SimpleNamespace(platform=platform))


def _targets(monkeypatch, *names: str, stamp: int = 1) -> list[str]:
    """Stub the enumeration with ``names`` (all last written at ``stamp``)
    and pretend to be on Windows."""
    seen: list[str] = []

    def fake(pattern: str) -> dict[str, int]:
        seen.append(pattern)
        prefix = pattern.rstrip("*")
        return {n: stamp for n in names if n.startswith(prefix)}

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

    def test_entry_ambiguity_carries_each_entrys_last_written(self, temp_home, monkeypatch):
        _targets(monkeypatch, f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/user",
                 f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/user#m", stamp=7)
        mode = windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE])
        assert mode.entries == (
            (f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/user", 7),
            (f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/user#m", 7),
        )
        _flag(temp_home / ".claude.json", True)  # an opt-in carries none
        assert windows_credman.detect([CLAUDE_CODE_KEYCHAIN_SERVICE]).entries == ()

    def test_briefly_unreadable_config_is_retried(self, temp_home, monkeypatch):
        """Claude Code rewriting its config can deny a read for a moment on
        Windows; that alone must not read as "maybe Credential Manager"."""
        _flag(temp_home / ".claude.json", False)
        monkeypatch.setattr(windows_credman, "_CONFIG_READ_RETRY_DELAY", 0)
        real = Path.read_text
        denied = []

        def read_text(self, *a, **kw):
            if self.name == ".claude.json" and not denied:
                denied.append(1)
                raise PermissionError("sharing violation")
            return real(self, *a, **kw)

        monkeypatch.setattr(Path, "read_text", read_text)
        assert windows_credman.detect([]) is None
        assert denied == [1]

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
        sw = _switcher(Platform.WINDOWS)
        sw.switch_to("2", json_output=True)
        written = json.loads(windows.read_text())
        # Each account keeps its own Design login.
        assert written == {
            "claudeAiOauth": {"accessToken": "fake-2"}, "designOauth": DESIGN_2}
        stored = json.loads(sw._read_account_credentials("1", "1@x.com"))
        assert stored["designOauth"] == DESIGN

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
        assert json.loads(windows.read_text())["designOauth"] == DESIGN_2


class TestStaleEntryAcknowledgment:
    """An entry with no opt-in in sight refuses once; overriding it records
    it as stale, and it refuses again only once Claude Code writes it."""

    ENTRY = f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/user"

    def test_override_accepts_the_same_entry_until_claude_code_writes_it(
        self, windows, monkeypatch
    ):
        _targets(monkeypatch, self.ENTRY, stamp=100)
        with pytest.raises(SwitchError, match="switch once with --ignore-credman"):
            _switcher(Platform.WINDOWS).switch_to("2", json_output=True)

        forced = _switcher(Platform.WINDOWS)
        forced.ignore_credman = True
        forced.switch_to("2", json_output=True)
        assert json.loads(windows.read_text())["designOauth"] == DESIGN_2

        # The same leftover, untouched: no override needed any more.
        _switcher(Platform.WINDOWS).switch_to("1", json_output=True)
        assert json.loads(windows.read_text())["designOauth"] == DESIGN

        # Claude Code wrote the entry: it is in use after all.
        _targets(monkeypatch, self.ENTRY, stamp=200)
        with pytest.raises(SwitchError, match="may be using Windows Credential Manager"):
            _switcher(Platform.WINDOWS).switch_to("2", json_output=True)
        assert json.loads(windows.read_text())["designOauth"] == DESIGN

    def test_a_new_entry_is_not_covered(self, windows, monkeypatch):
        _targets(monkeypatch, self.ENTRY, stamp=100)
        forced = _switcher(Platform.WINDOWS)
        forced.ignore_credman = True
        forced.switch_to("2", json_output=True)

        _targets(monkeypatch, self.ENTRY, f"{self.ENTRY}#m", stamp=100)
        with pytest.raises(SwitchError):
            _switcher(Platform.WINDOWS).switch_to("1", json_output=True)

    def test_an_opt_in_is_never_acknowledged(self, windows, temp_home):
        _enable_flag(temp_home)
        forced = _switcher(Platform.WINDOWS)
        forced.ignore_credman = True
        forced.switch_to("2", json_output=True)

        assert not (forced.backup_dir / windows_credman.ACK_FILE).exists()
        with pytest.raises(SwitchError, match="is using Windows Credential Manager"):
            _switcher(Platform.WINDOWS).switch_to("1", json_output=True)

    def test_background_refresh_leaves_a_credman_login_alone(
        self, windows, monkeypatch
    ):
        """cswap's usage pass would find no usable file login, restore the
        backup and POST its grant — the generation Claude Code may hold in
        Credential Manager. In that mode it defers instead."""
        from claude_swap import oauth

        login = json.dumps({"claudeAiOauth": {
            "accessToken": "fake-1", "refreshToken": "fake-rt-1",
            "expiresAt": 9999999999000}})
        windows.write_text(login)
        sw = _switcher(Platform.WINDOWS)
        sw._write_account_credentials("1", "1@x.com", login)
        _targets(monkeypatch, self.ENTRY, stamp=100)

        with (
            patch("claude_swap.oauth.try_fetch_usage_for_account",
                  return_value=oauth.UsageOutcome(None, "http-401")),
            patch("claude_swap.oauth.try_refresh_oauth_credentials",
                  return_value=oauth.RefreshOutcome(None, "refresh-failed")) as post,
        ):
            record = sw._fetch_active_usage("1", "1@x.com", login)

        assert not post.called, "POSTed the grant in Credential Manager mode"
        assert record.error == "http-401"
        assert windows.read_text() == login

        # Acknowledged as a leftover: the refresh runs again.
        (sw.backup_dir / windows_credman.ACK_FILE).write_text(
            json.dumps({self.ENTRY: 100}))
        with (
            patch("claude_swap.oauth.try_fetch_usage_for_account",
                  return_value=oauth.UsageOutcome(None, "http-401")),
            patch("claude_swap.oauth.try_refresh_oauth_credentials",
                  return_value=oauth.RefreshOutcome(None, "refresh-failed")) as post,
        ):
            sw._fetch_active_usage("1", "1@x.com", login)
        assert post.called


class _Launched(Exception):
    pass


@pytest.fixture
def run_session(windows, monkeypatch):
    """``cswap run 2`` on Windows up to the session setup (never execs)."""
    from claude_swap import session as session_mod

    sw = _switcher(Platform.WINDOWS)
    monkeypatch.setattr(session_mod.shutil, "which", lambda name: "claude")

    def setup(self, *a, **kw):
        raise _Launched()

    monkeypatch.setattr(session_mod.SessionManager, "setup_session", setup)
    profile = session_mod.session_dir_for(sw.backup_dir, "2", "2@x.com")
    return sw, session_mod.SessionManager(sw), profile


class TestSessionOnWindows:
    """`cswap run` refuses in Credential Manager mode: the session's login
    would move out of the profile file cswap seeds and captures."""

    def test_not_detected_runs(self, run_session):
        _sw, manager, _profile = run_session
        with pytest.raises(_Launched):
            manager.run("2", [])

    def test_env_opt_in_refuses(self, run_session, monkeypatch):
        _sw, manager, profile = run_session
        monkeypatch.setenv("CLAUDE_CODE_FORCE_WINDOWS_CREDMAN", "1")
        with pytest.raises(SessionError) as exc:
            manager.run("2", [])
        assert "is using Windows Credential Manager" in str(exc.value)
        assert "CSWAP_IGNORE_CREDMAN=1" in str(exc.value)
        assert not profile.exists()

    def test_default_profile_flag_refuses(self, run_session, temp_home):
        _sw, manager, _profile = run_session
        _enable_flag(temp_home)
        with pytest.raises(SessionError, match="tengu_windows_credman"):
            manager.run("2", [])

    def test_session_profile_flag_refuses(self, run_session):
        _sw, manager, profile = run_session
        profile.mkdir(parents=True)
        _flag(profile / ".claude.json", True)
        with pytest.raises(SessionError, match="tengu_windows_credman"):
            manager.run("2", [])

    def test_session_profile_entry_refuses(self, run_session, monkeypatch):
        _sw, manager, profile = run_session
        _targets(monkeypatch, f"{keychain_service_name(str(profile))}/user")
        with pytest.raises(SessionError, match="may be using Windows Credential Manager"):
            manager.run("2", [])

    def test_default_profile_entry_alone_runs(self, run_session, monkeypatch):
        # A default-profile entry says nothing about the session's own store.
        _sw, manager, _profile = run_session
        _targets(monkeypatch, f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/user")
        with pytest.raises(_Launched):
            manager.run("2", [])

    def test_override_runs(self, run_session, monkeypatch):
        sw, manager, _profile = run_session
        monkeypatch.setenv("CLAUDE_CODE_FORCE_WINDOWS_CREDMAN", "1")
        sw.ignore_credman = True
        with pytest.raises(_Launched):
            manager.run("2", [])

    def test_override_accepts_a_leftover_profile_entry_until_it_changes(
        self, run_session, monkeypatch
    ):
        sw, manager, profile = run_session
        entry = f"{keychain_service_name(str(profile))}/user"
        _targets(monkeypatch, entry, stamp=5)
        with pytest.raises(SessionError, match="running once with the override"):
            manager.run("2", [])
        sw.ignore_credman = True
        with pytest.raises(_Launched):
            manager.run("2", [])
        sw.ignore_credman = False
        with pytest.raises(_Launched):
            manager.run("2", [])
        _targets(monkeypatch, entry, stamp=6)
        with pytest.raises(SessionError):
            manager.run("2", [])

    def test_other_platforms_unaffected(self, run_session, monkeypatch):
        sw, manager, _profile = run_session
        monkeypatch.setenv("CLAUDE_CODE_FORCE_WINDOWS_CREDMAN", "1")
        sw.platform = Platform.LINUX
        with pytest.raises(_Launched):
            manager.run("2", [])


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
            "claudeAiOauth": {"accessToken": "fake-2"}, "designOauth": DESIGN_2}


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
        assert REAL_ENUMERATE(f"{service}/*") == {}
        entry(f"{service}/user")
        entry(f"{service}/user#m")
        entry(f"{service}-other/user")
        assert sorted(REAL_ENUMERATE(f"{service}/*")) == [f"{service}/user", f"{service}/user#m"]

    def test_last_written_is_read_and_moves_on_a_rewrite(self, entry):
        import time

        service = f"cswap-ci-{uuid.uuid4().hex[:8]}"
        entry(f"{service}/user")
        (first,) = REAL_ENUMERATE(f"{service}/*").values()
        assert first > 0
        time.sleep(0.05)
        entry(f"{service}/user")  # what Claude Code does on each refresh
        (second,) = REAL_ENUMERATE(f"{service}/*").values()
        assert second > first

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
        assert list(REAL_ENUMERATE(f"{CLAUDE_CODE_KEYCHAIN_SERVICE}/*")) == [target]

    def test_run_refuses_on_a_real_profile_entry(self, entry, run_session, monkeypatch):
        """A real entry for the session profile's own service makes `cswap
        run` refuse before the profile is created; the entry is untouched."""
        monkeypatch.setattr(windows_credman, "_enumerate_targets", REAL_ENUMERATE)
        _sw, manager, profile = run_session
        target = f"{keychain_service_name(str(profile))}/cswap-ci-{uuid.uuid4().hex[:8]}"
        entry(target)

        with pytest.raises(SessionError, match="may be using Windows Credential Manager"):
            manager.run("2", [])

        assert not profile.exists()
        assert list(REAL_ENUMERATE(f"{keychain_service_name(str(profile))}/*")) == [target]
