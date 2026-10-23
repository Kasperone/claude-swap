"""``designOauth`` on the Linux path: plaintext file backend, no secret store.

Claude Code on Linux stores credentials only in ``<secure-storage
dir>/.credentials.json`` (2.1.306 storage kinds: keychain, plaintext,
windows-credman — no libsecret); cswap never calls a Keychain here. Every test
forces ``Platform.LINUX`` so the macOS runner exercises the same path. Fake
credentials only, everything under tmp_path.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import macos_keychain
from claude_swap.models import Platform
from claude_swap.session import SessionManager
from claude_swap.switcher import ClaudeAccountSwitcher

from tests.test_design_oauth_profiles import _seed_slot

API_KEY = "sk-ant-api03-" + "a1b2c3d4e5" * 4
DESIGN = {"accessToken": "fake-design-at", "refreshToken": "fake-design-rt"}
OTHER = {"accessToken": "fake-other-at", "refreshToken": "fake-other-rt"}

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file modes"
)


def _login(token: str, **extra) -> str:
    return json.dumps({"claudeAiOauth": {"accessToken": token}, **extra})


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture(autouse=True)
def linux_host(monkeypatch):
    """Module-level helpers (capture reads, session profiles) ask the host OS
    through Platform.detect(); the switcher instances get Platform.LINUX."""
    monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.LINUX))


@pytest.fixture
def no_keychain(monkeypatch):
    """Any Keychain call on the Linux path is a bug."""

    def boom(*args, **kwargs):
        raise AssertionError("Keychain touched on the Linux path")

    for name in ("get_password", "set_password", "delete_password", "item_exists"):
        monkeypatch.setattr(macos_keychain, name, boom)


def _linux() -> ClaudeAccountSwitcher:
    sw = ClaudeAccountSwitcher()
    sw.platform = Platform.LINUX
    return sw


def _swap(sw: ClaudeAccountSwitcher, target: str) -> None:
    live = sw._read_credentials()
    sw._write_credentials(sw._prepare_credentials_for_activation(target, live))


def _trio(sw: ClaudeAccountSwitcher, cred: Path) -> None:
    """OAuth -> OAuth -> API key -> OAuth -> OAuth: each activation carries the
    target's own designOauth, or none, and never the outgoing account's."""
    _swap(sw, _login("fake-target", designOauth=OTHER))
    assert json.loads(cred.read_text())["designOauth"] == OTHER

    _swap(sw, API_KEY)
    assert not cred.exists()
    assert sw._read_credentials() == API_KEY

    _swap(sw, _login("fake-target2"))
    assert json.loads(cred.read_text()) == {
        "claudeAiOauth": {"accessToken": "fake-target2"}
    }

    _swap(sw, _login("fake-target3", designOauth=DESIGN))
    assert json.loads(cred.read_text())["designOauth"] == DESIGN


def _identity(config_home: Path, global_config: Path) -> None:
    config_home.mkdir(parents=True, exist_ok=True)
    global_config.write_text(json.dumps({
        "oauthAccount": {
            "emailAddress": "a@x.com",
            "accountUuid": "u1",
            "organizationUuid": "",
            "organizationName": "",
        }
    }))


@pytest.mark.usefixtures("no_keychain")
class TestDefaultProfile:
    def test_swap_trio(self, temp_home):
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))
        _trio(_linux(), cred)

    @posix_only
    def test_every_write_is_0600_and_atomic(self, temp_home):
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))
        os.chmod(cred, 0o644)
        sw = _linux()

        before = cred.stat().st_ino
        _swap(sw, _login("fake-target"))
        assert _mode(cred) == 0o600
        after_oauth = cred.stat().st_ino

        _swap(sw, _login("fake-target2", designOauth=OTHER))
        assert _mode(cred) == 0o600

        # A rename publishes each write (new inode), never a truncate-in-place,
        # and no temp file is left behind.
        assert before != after_oauth != cred.stat().st_ino
        assert sorted(p.name for p in cred.parent.iterdir()) == [".credentials.json"]

    def test_api_key_switch_records_the_key_in_the_global_config(self, temp_home):
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _linux()._write_credentials(API_KEY)

        cfg = json.loads((temp_home / ".claude.json").read_text())
        assert cfg["primaryApiKey"] == API_KEY

    def test_add_remove_purge_leave_the_file(self, temp_home):
        cred = temp_home / ".claude" / ".credentials.json"
        live = _login("fake-live", designOauth=DESIGN)
        cred.write_text(live)
        _identity(temp_home / ".claude", temp_home / ".claude.json")
        sw = _linux()

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


@pytest.mark.usefixtures("no_keychain")
class TestEnvVarProfile:
    @pytest.fixture
    def profile(self, temp_home, monkeypatch) -> Path:
        path = temp_home / "profiles" / "work"
        path.mkdir(parents=True)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(path))
        return path

    def test_swap_trio_touches_only_the_profile_file(self, profile, temp_home):
        default = temp_home / ".claude" / ".credentials.json"
        default.write_text(_login("fake-default", designOauth={"accessToken": "d"}))
        before = default.read_text()
        cred = profile / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _trio(_linux(), cred)

        assert default.read_text() == before

    def test_add_remove_purge_leave_the_profile_file(self, profile):
        cred = profile / ".credentials.json"
        live = _login("fake-live", designOauth=DESIGN)
        cred.write_text(live)
        _identity(profile, profile / ".claude.json")
        sw = _linux()

        sw.add_account()
        assert "a@x.com" in json.dumps(sw._get_sequence_data()["accounts"])
        with patch("builtins.input", return_value="y"):
            sw.remove_account("1")
            sw.purge()
        assert cred.read_text() == live


@pytest.mark.usefixtures("no_keychain")
class TestSecureStorageDirOverride:
    """Claude Code's plaintext file follows CLAUDE_SECURESTORAGE_CONFIG_DIR."""

    def test_defined_dir_holds_the_active_file(self, temp_home, monkeypatch):
        secure = temp_home / "secure"
        secure.mkdir()
        monkeypatch.setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", str(secure))
        config = temp_home / ".claude" / ".credentials.json"
        config.write_text(_login("fake-config-home"))
        before = config.read_text()
        cred = secure / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _trio(_linux(), cred)

        assert config.read_text() == before

    def test_defined_empty_means_the_default_dir(self, temp_home, monkeypatch):
        profile = temp_home / "profiles" / "work"
        profile.mkdir(parents=True)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(profile))
        monkeypatch.setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", "")
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _trio(_linux(), cred)

        assert not (profile / ".credentials.json").exists()


@pytest.mark.usefixtures("no_keychain")
class TestSessionProfile:
    @posix_only
    def test_reseed_keeps_profile_design_and_is_0600(self, temp_home):
        sw = _linux()
        _seed_slot(sw, _login("fake-backup", designOauth={"accessToken": "stale"}))
        session_dir = sw.backup_dir / "sessions" / "1-a-x-com"
        session_dir.mkdir(parents=True)
        cred = session_dir / ".credentials.json"
        cred.write_text(_login("fake-old-profile", designOauth=DESIGN))

        SessionManager(sw)._bootstrap(session_dir, "1", "a@x.com", "")

        seeded = json.loads(cred.read_text())
        assert seeded["claudeAiOauth"] == {"accessToken": "fake-backup"}
        assert seeded["designOauth"] == DESIGN
        assert _mode(cred) == 0o600

    def test_reseed_does_not_touch_the_default_file(self, temp_home):
        default = temp_home / ".claude" / ".credentials.json"
        default.write_text(_login("fake-default", designOauth={"accessToken": "d"}))
        before = default.read_text()
        sw = _linux()
        _seed_slot(sw, _login("fake-backup"))

        SessionManager(sw)._bootstrap(
            sw.backup_dir / "sessions" / "1-a-x-com", "1", "a@x.com", ""
        )

        assert default.read_text() == before
