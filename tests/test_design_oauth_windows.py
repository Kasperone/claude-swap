"""``designOauth`` on the Windows path: plaintext file backend.

Claude Code 2.1.306 on Windows stores credentials in ``<secure-storage
dir>\\.credentials.json`` unless Credential Manager is opted into
(``CLAUDE_CODE_FORCE_WINDOWS_CREDMAN=1`` or the cached ``tengu_windows_credman``
flag), which cswap does not support. Every test forces ``Platform.WINDOWS`` so
any runner exercises the same path; the ``real_windows`` tests need the real
OS semantics (open handles block a replace). Fake credentials only, everything
under tmp_path.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import fsutil, macos_keychain
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.exceptions import CredentialWriteError
from claude_swap.models import Platform
from claude_swap.paths import get_credentials_path
from claude_swap.session import SessionManager
from claude_swap.switcher import KEYRING_SERVICE, ClaudeAccountSwitcher

from tests.test_design_oauth_linux import (
    API_KEY,
    DESIGN,
    OTHER,
    _identity,
    _login,
    _swap,
    _trio,
)
from tests.test_design_oauth_profiles import _seed_slot

real_windows = pytest.mark.skipif(
    sys.platform != "win32", reason="real Windows file-sharing semantics"
)


@pytest.fixture(autouse=True)
def windows_host(monkeypatch):
    """Module-level helpers ask the host OS through Platform.detect(); the
    switcher instances get Platform.WINDOWS."""
    monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.WINDOWS))


@pytest.fixture(autouse=True)
def no_keychain(monkeypatch):
    """Any Keychain call on the Windows path is a bug."""

    def boom(*args, **kwargs):
        raise AssertionError("Keychain touched on the Windows path")

    for name in ("get_password", "set_password", "delete_password", "item_exists"):
        monkeypatch.setattr(macos_keychain, name, boom)


def _windows() -> ClaudeAccountSwitcher:
    sw = ClaudeAccountSwitcher()
    sw.platform = Platform.WINDOWS
    return sw


def _sharing_violation(winerror: int) -> OSError:
    err = PermissionError(13, "The process cannot access the file")
    err.winerror = winerror  # set by the OS on Windows only
    return err


class TestDefaultProfile:
    def test_credentials_path_is_under_the_user_profile(self, temp_home):
        assert get_credentials_path() == temp_home / ".claude" / ".credentials.json"

    def test_swap_trio(self, temp_home):
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))
        _trio(_windows(), cred)

    def test_writes_are_atomic(self, temp_home):
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))
        sw = _windows()

        with patch.object(fsutil.os, "replace", wraps=fsutil.os.replace) as rep:
            _swap(sw, _login("fake-target"))
            _swap(sw, _login("fake-target2", designOauth=OTHER))

        targets = [Path(c.args[1]) for c in rep.call_args_list]
        assert targets.count(cred) == 2  # each write a rename, never in place
        assert sorted(p.name for p in cred.parent.iterdir()) == [".credentials.json"]

    def test_api_key_switch_records_the_key_in_the_global_config(self, temp_home):
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _windows()._write_credentials(API_KEY)

        cfg = json.loads((temp_home / ".claude.json").read_text())
        assert cfg["primaryApiKey"] == API_KEY
        assert not cred.exists()  # designOauth goes with the outgoing login

    def test_add_remove_purge_leave_the_file_and_claude_codes_credman(self, temp_home):
        """Purge sweeps cswap's legacy ``claude-code`` keyring entries on
        Windows; Claude Code's own Credential Manager entry is a different
        service and must survive."""
        keyring = sys.modules["keyring"]  # the conftest fake
        keyring.set_password(CLAUDE_CODE_KEYCHAIN_SERVICE, "user", "fake-credman")
        assert KEYRING_SERVICE != CLAUDE_CODE_KEYCHAIN_SERVICE
        cred = temp_home / ".claude" / ".credentials.json"
        live = _login("fake-live", designOauth=DESIGN)
        cred.write_text(live)
        _identity(temp_home / ".claude", temp_home / ".claude.json")
        sw = _windows()

        sw.add_account()
        assert "a@x.com" in json.dumps(sw._get_sequence_data()["accounts"])
        assert cred.read_text() == live

        with patch("builtins.input", return_value="y"):
            sw.remove_account("1")
        assert cred.read_text() == live

        sw.add_account()
        with patch("builtins.input", return_value="y"):
            sw.purge()
        assert cred.read_text() == live
        assert keyring.get_password(CLAUDE_CODE_KEYCHAIN_SERVICE, "user") == "fake-credman"


class TestTransientSharingViolations:
    """Defender/the indexer briefly lock a freshly written file; the replace
    is retried on those codes only, and a lasting failure keeps the old file."""

    @pytest.fixture(autouse=True)
    def win32_retry_rules(self, monkeypatch):
        monkeypatch.setattr(fsutil, "sys", types.SimpleNamespace(platform="win32"))
        monkeypatch.setattr(fsutil.time, "sleep", lambda _s: None)

    @pytest.mark.parametrize("winerror", [5, 32, 33])
    def test_retried_swap_writes_the_targets_design(self, temp_home, monkeypatch, winerror):
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))
        real_replace = fsutil.os.replace
        calls = []

        def flaky(src, dst):
            calls.append(dst)
            if len(calls) <= 2:
                raise _sharing_violation(winerror)
            real_replace(src, dst)

        monkeypatch.setattr(fsutil.os, "replace", flaky)
        _swap(_windows(), _login("fake-target", designOauth=OTHER))

        assert len(calls) == 3
        assert json.loads(cred.read_text()) == {
            "claudeAiOauth": {"accessToken": "fake-target"},
            "designOauth": OTHER,
        }
        assert sorted(p.name for p in cred.parent.iterdir()) == [".credentials.json"]

    def test_lasting_failure_raises_and_keeps_the_old_file(self, temp_home, monkeypatch):
        cred = temp_home / ".claude" / ".credentials.json"
        live = _login("fake-live", designOauth=DESIGN)
        cred.write_text(live)

        def locked(src, dst):
            raise _sharing_violation(32)

        monkeypatch.setattr(fsutil.os, "replace", locked)
        sw = _windows()
        with pytest.raises(CredentialWriteError):
            _swap(sw, _login("fake-target"))
        with pytest.raises(CredentialWriteError):
            sw._write_credentials(API_KEY)

        assert cred.read_text() == live
        assert sorted(p.name for p in cred.parent.iterdir()) == [".credentials.json"]

    def test_api_key_switch_with_only_the_credentials_file_locked(
        self, temp_home, monkeypatch
    ):
        """The key lands in the config and the login file is unlinked (no
        rename needed): designOauth goes with the outgoing login, as on every
        API-key switch."""
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))
        real_replace = fsutil.os.replace

        def cred_locked(src, dst):
            if Path(dst) == cred:
                raise _sharing_violation(32)
            real_replace(src, dst)

        monkeypatch.setattr(fsutil.os, "replace", cred_locked)
        _windows()._write_credentials(API_KEY)

        cfg = json.loads((temp_home / ".claude.json").read_text())
        assert cfg["primaryApiKey"] == API_KEY
        assert not cred.exists()
        assert sorted(p.name for p in cred.parent.iterdir()) == []


class TestEnvVarProfile:
    def test_swap_trio_touches_only_the_profile_file(self, temp_home, monkeypatch):
        profile = temp_home / "profiles" / "work"
        profile.mkdir(parents=True)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(profile))
        default = temp_home / ".claude" / ".credentials.json"
        default.write_text(_login("fake-default", designOauth={"accessToken": "d"}))
        before = default.read_text()
        cred = profile / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _trio(_windows(), cred)

        assert default.read_text() == before

    def test_secure_storage_dir_holds_the_active_file(self, temp_home, monkeypatch):
        secure = temp_home / "secure"
        secure.mkdir()
        monkeypatch.setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", str(secure))
        config = temp_home / ".claude" / ".credentials.json"
        config.write_text(_login("fake-config-home"))
        before = config.read_text()
        cred = secure / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _trio(_windows(), cred)

        assert config.read_text() == before


class TestSessionProfile:
    def test_reseed_keeps_profile_design(self, temp_home):  # same account's
        sw = _windows()
        _seed_slot(sw, _login("fake-backup", designOauth={"accessToken": "stale"}))
        session_dir = sw.backup_dir / "sessions" / "1-a-x-com"
        session_dir.mkdir(parents=True)
        cred = session_dir / ".credentials.json"
        cred.write_text(_login("fake-old-profile", designOauth=DESIGN))

        SessionManager(sw)._bootstrap(session_dir, "1", "a@x.com", "")

        seeded = json.loads(cred.read_text())
        assert seeded["claudeAiOauth"] == {"accessToken": "fake-backup"}
        assert seeded["designOauth"] == DESIGN


@real_windows
class TestRealWindowsFileSharing:
    def test_open_reader_does_not_lose_design_oauth(self, temp_home):
        """A handle opened without FILE_SHARE_DELETE (Python's default open)
        blocks the replace: the swap fails loudly and the old file, with its
        designOauth, stays intact. Node (Claude Code) opens files with
        FILE_SHARE_DELETE, so its reads never block a swap."""
        cred = temp_home / ".claude" / ".credentials.json"
        live = _login("fake-live", designOauth=DESIGN)
        cred.write_text(live)
        sw = _windows()

        with open(cred, encoding="utf-8"):
            with patch.object(fsutil.time, "sleep", lambda _s: None):
                with pytest.raises(CredentialWriteError):
                    _swap(sw, _login("fake-target"))

        assert cred.read_text() == live
        assert sorted(p.name for p in cred.parent.iterdir()) == [".credentials.json"]

        _swap(sw, _login("fake-target", designOauth=OTHER))  # handle closed
        assert json.loads(cred.read_text())["designOauth"] == OTHER

    def test_api_key_switch_under_an_open_reader_keeps_the_file(self, temp_home):
        """The held handle blocks the unlink, so the file survives and the key
        still lands in the config — upstream's best-effort removal."""
        cred = temp_home / ".claude" / ".credentials.json"
        live = _login("fake-live", designOauth=DESIGN)
        cred.write_text(live)

        with open(cred, encoding="utf-8"):
            with patch.object(fsutil.time, "sleep", lambda _s: None):
                _windows()._write_credentials(API_KEY)

        cfg = json.loads((temp_home / ".claude.json").read_text())
        assert cfg["primaryApiKey"] == API_KEY
        assert cred.read_text() == live

    def test_trio_on_real_ntfs(self, temp_home):
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))
        _trio(_windows(), cred)
