"""Per-account ``designOauth``: full switches, sessions and the one-time migration.

Every slot and session profile owns its own Claude Design login; nothing
crosses accounts. File backend with ``Platform.LINUX`` forced (the Windows and
macOS modules re-run the scenarios on their backends). Fake credentials only,
everything under tmp_path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import macos_keychain, migrations
from claude_swap import session as session_mod
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE, design_fingerprint
from claude_swap.exceptions import MigrationIncomplete
from claude_swap.models import Platform
from claude_swap.session import SessionManager, keychain_service_name, session_dir_for
from claude_swap.switcher import ClaudeAccountSwitcher

from tests.test_design_oauth_macos import keychain  # noqa: F401

API_KEY = "sk-ant-api03-" + "a1b2c3d4e5" * 4
D1 = {"accessToken": "fake-d1-at", "refreshToken": "fake-d1-rt", "expiresAt": 2000}
D1_OLD = {"accessToken": "fake-d1-old", "refreshToken": "fake-d1-rt", "expiresAt": 1000}
D2 = {"accessToken": "fake-d2-at", "refreshToken": "fake-d2-rt", "expiresAt": 2000}
D3 = {"accessToken": "fake-d3-at", "refreshToken": "fake-d3-rt", "expiresAt": 2000}
D4 = {"accessToken": "fake-d4-at", "refreshToken": "fake-d4-rt", "expiresAt": 2000}
TOKENS = ("fake-d1", "fake-d2", "fake-d3", "fake-d4", "fake-login")


def _login(num: str, design: dict | None = None, expires: int = 5000) -> str:
    blob: dict = {
        "claudeAiOauth": {
            "accessToken": f"fake-login-{num}-at",
            "refreshToken": f"fake-login-{num}-rt",
            "expiresAt": expires,
        }
    }
    if design is not None:
        blob["designOauth"] = design
    return json.dumps(blob)


def _email(num: str) -> str:
    return f"user{num}@x.com"


def _design(creds: str | None) -> dict | None:
    return json.loads(creds).get("designOauth") if creds else None


def _platform(monkeypatch, platform: Platform) -> ClaudeAccountSwitcher:
    monkeypatch.setattr(Platform, "detect", staticmethod(lambda: platform))
    sw = ClaudeAccountSwitcher()
    sw.platform = platform
    return sw


def _set_identity(home: Path, num: str) -> None:
    path = home / ".claude.json"
    cfg = json.loads(path.read_text()) if path.exists() else {}
    cfg["oauthAccount"] = {"emailAddress": _email(num), "accountUuid": f"u{num}"}
    path.write_text(json.dumps(cfg))


def _roster(
    sw: ClaudeAccountSwitcher, home: Path, backups: dict[str, str], active: str
) -> None:
    """Seed OAuth slots with the given backups; slot ``active`` is logged in
    (its backup is also the live credential)."""
    sw._setup_directories()
    sw._init_sequence_file()
    data = sw._get_sequence_data()
    for num, creds in backups.items():
        sw._write_account_credentials(num, _email(num), creds)
        sw._write_account_config(num, _email(num), json.dumps({
            "oauthAccount": {"emailAddress": _email(num), "accountUuid": f"u{num}"}
        }))
        data["accounts"][num] = {
            "email": _email(num), "uuid": f"u{num}", "organizationUuid": "",
            "organizationName": "", "added": "2024-01-01T00:00:00Z",
        }
    data["sequence"] = [int(n) for n in backups]
    data["activeAccountNumber"] = int(active)
    sw._write_json(sw.sequence_file, data)
    _set_identity(home, active)
    sw._write_credentials(backups[active])


def _backup(sw: ClaudeAccountSwitcher, num: str) -> str:
    return sw._read_account_credentials(num, _email(num))


@pytest.fixture
def linux(temp_home, monkeypatch) -> ClaudeAccountSwitcher:
    def boom(*args, **kwargs):
        raise AssertionError("Keychain touched on the Linux path")

    for name in ("get_password", "set_password", "delete_password", "item_exists"):
        monkeypatch.setattr(macos_keychain, name, boom)
    return _platform(monkeypatch, Platform.LINUX)


def _live_file(home: Path) -> Path:
    return home / ".claude" / ".credentials.json"


class TestSwitchMatrix:
    """``switch_to`` end to end: capture of the outgoing account, activation of
    the target's own copy, and no fallback for a slot without one."""

    def test_each_account_keeps_its_own(self, linux, temp_home):
        sw = linux
        _roster(sw, temp_home, {"1": _login("1", D1), "2": _login("2", D2),
                                "3": _login("3")}, active="1")
        live = _live_file(temp_home)

        sw.switch_to("2", json_output=True)
        assert _design(live.read_text()) == D2
        assert _design(_backup(sw, "1")) == D1

        sw.switch_to("1", json_output=True)
        assert _design(live.read_text()) == D1
        assert _design(_backup(sw, "2")) == D2

        sw.switch_to("3", json_output=True)
        assert _design(live.read_text()) is None  # no fallback to D1
        assert _design(_backup(sw, "1")) == D1

    def test_design_login_on_the_default_is_captured_into_that_slot(
        self, linux, temp_home
    ):
        sw = linux
        _roster(sw, temp_home, {"1": _login("1", D1), "2": _login("2")}, active="1")
        sw.switch_to("2", json_output=True)
        live = _live_file(temp_home)
        # /design-login while account 2 is the default login.
        blob = json.loads(live.read_text())
        live.write_text(json.dumps({**blob, "designOauth": D2}))

        sw.switch_to("1", json_output=True)
        assert _design(_backup(sw, "2")) == D2
        assert _design(live.read_text()) == D1

        sw.switch_to("2", json_output=True)
        assert _design(live.read_text()) == D2

    def test_api_key_slot_has_none_and_oauth_gets_its_own_back(
        self, linux, temp_home
    ):
        sw = linux
        _roster(sw, temp_home, {"1": _login("1", D1)}, active="1")
        sw.add_account_from_token(API_KEY, slot=4)
        live = _live_file(temp_home)

        sw.switch_to("4", json_output=True)
        assert not live.exists()
        assert sw._read_credentials() == API_KEY
        assert _design(_backup(sw, "1")) == D1

        # /design-login while the key is active: not a login, never the key
        # slot's, never carried to the next OAuth account.
        live.write_text(json.dumps({"designOauth": D4}))
        assert sw._read_credentials() == API_KEY
        sw.switch_to("1", json_output=True)
        assert _design(live.read_text()) == D1
        assert sw._read_account_credentials("4", "api-key-4@token.local") == API_KEY


class TestSwitchMatrixWindows(TestSwitchMatrix):
    @pytest.fixture
    def linux(self, temp_home, monkeypatch):  # the Windows file backend
        return _platform(monkeypatch, Platform.WINDOWS)
