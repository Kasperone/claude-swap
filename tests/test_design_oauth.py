"""``designOauth`` (Claude Design login) survives every cswap credential path.

Fake credentials only, all under the ``temp_home`` fixture's tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap.credentials import (
    SHARED_CREDENTIAL_KEYS,
    merge_shared_credential_fields,
    shared_credential_fields,
)
from claude_swap.switcher import ClaudeAccountSwitcher

API_KEY = "sk-ant-api03-" + "a1b2c3d4e5" * 4
DESIGN = {"accessToken": "fake-design-at", "refreshToken": "fake-design-rt"}


def _cred_file(home: Path) -> Path:
    return home / ".claude" / ".credentials.json"


def _live(home: Path, **extra) -> str:
    blob = json.dumps({"claudeAiOauth": {"accessToken": "fake-live"}, **extra})
    _cred_file(home).write_text(blob)
    return blob


def _seed_account(switcher: ClaudeAccountSwitcher, num: str = "1") -> None:
    switcher._setup_directories()
    switcher._init_sequence_file()
    data = switcher._get_sequence_data()
    data["accounts"][num] = {
        "email": "a@x.com",
        "uuid": "u1",
        "organizationUuid": "",
        "organizationName": "",
        "added": "2024-01-01T00:00:00Z",
    }
    data["sequence"] = [int(num)]
    switcher._write_json(switcher.sequence_file, data)


def test_design_oauth_is_machine_shared():
    assert "designOauth" in SHARED_CREDENTIAL_KEYS


class TestSwap:
    def test_live_design_oauth_wins_over_stale_slot_copy(self):
        target = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-target"},
            "designOauth": {"accessToken": "stale"},
        })
        live = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-live"},
            "designOauth": DESIGN,
        })
        merged = json.loads(
            merge_shared_credential_fields(target, shared_credential_fields(live))
        )
        assert merged["designOauth"] == DESIGN
        assert merged["claudeAiOauth"] == {"accessToken": "fake-target"}

    def test_design_oauth_carried_to_slot_that_never_had_it(self):
        target = json.dumps({"claudeAiOauth": {"accessToken": "fake-target"}})
        live = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-live"},
            "designOauth": DESIGN,
        })
        merged = json.loads(
            merge_shared_credential_fields(target, shared_credential_fields(live))
        )
        assert merged["designOauth"] == DESIGN

    def test_oauth_swap_writes_design_oauth_to_credentials_file(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        live = _live(temp_home, designOauth=DESIGN)
        target = json.dumps({"claudeAiOauth": {"accessToken": "fake-target"}})

        switcher._write_credentials(
            switcher._prepare_credentials_for_activation(target, live)
        )

        written = json.loads(_cred_file(temp_home).read_text())
        assert written["designOauth"] == DESIGN
        assert written["claudeAiOauth"] == {"accessToken": "fake-target"}

    def test_api_key_swap_keeps_design_oauth_and_drops_login(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        _live(temp_home, designOauth=DESIGN)

        switcher._write_credentials(API_KEY)

        assert json.loads(_cred_file(temp_home).read_text()) == {
            "designOauth": DESIGN
        }

    def test_api_key_swap_without_design_oauth_still_removes_file(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        _live(temp_home)

        switcher._write_credentials(API_KEY)

        assert not _cred_file(temp_home).exists()

    def test_api_key_swap_with_unreadable_file_removes_it(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        _cred_file(temp_home).write_text("not json")

        switcher._write_credentials(API_KEY)

        assert not _cred_file(temp_home).exists()


class TestAddRemovePurge:
    def test_add_account_leaves_live_design_oauth(self, temp_home, monkeypatch):
        switcher = ClaudeAccountSwitcher()
        switcher._setup_directories()
        live = _live(temp_home, designOauth=DESIGN)
        (temp_home / ".claude.json").write_text(json.dumps({
            "oauthAccount": {
                "emailAddress": "a@x.com",
                "accountUuid": "u1",
                "organizationUuid": "",
                "organizationName": "",
            }
        }))
        monkeypatch.setattr("builtins.input", lambda *a, **k: "y")
        try:
            switcher.add_account()
        except SystemExit:
            pass
        assert json.loads(_cred_file(temp_home).read_text())[
            "designOauth"
        ] == DESIGN
        assert _cred_file(temp_home).read_text() == live

    def test_remove_account_leaves_live_design_oauth(self, temp_home, monkeypatch):
        switcher = ClaudeAccountSwitcher()
        _seed_account(switcher)
        live = _live(temp_home, designOauth=DESIGN)
        monkeypatch.setattr("builtins.input", lambda *a, **k: "y")

        switcher.remove_account("1")

        assert _cred_file(temp_home).read_text() == live

    def test_purge_leaves_live_design_oauth(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        _seed_account(switcher)
        live = _live(temp_home, designOauth=DESIGN)

        with patch("builtins.input", return_value="y"):
            switcher.purge()

        assert _cred_file(temp_home).read_text() == live
