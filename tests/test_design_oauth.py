"""``designOauth`` (Claude Design login) is account-owned, like the login.

Each slot carries its own; a switch activates the target slot's copy (or none)
and never hands the live account's copy to another account. Fake credentials
only, all under the ``temp_home`` fixture's tmp_path.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from claude_swap.credentials import (
    ACCOUNT_CREDENTIAL_KEYS,
    SHARED_CREDENTIAL_KEYS,
    design_fingerprint,
    is_login_less,
    merge_shared_credential_fields,
    newer_design_oauth,
    shared_credential_fields,
    with_design_oauth,
)
from claude_swap.switcher import ClaudeAccountSwitcher

API_KEY = "sk-ant-api03-" + "a1b2c3d4e5" * 4
DESIGN = {"accessToken": "fake-design-at", "refreshToken": "fake-design-rt"}
OTHER = {"accessToken": "fake-other-at", "refreshToken": "fake-other-rt"}


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


def test_design_oauth_is_account_owned():
    assert "designOauth" in ACCOUNT_CREDENTIAL_KEYS
    assert "cloudSessionsOauth" in ACCOUNT_CREDENTIAL_KEYS
    assert "designOauth" not in SHARED_CREDENTIAL_KEYS
    assert "cloudSessionsOauth" not in SHARED_CREDENTIAL_KEYS


class TestHelpers:
    def test_fingerprint_is_short_and_never_the_token(self):
        fp = design_fingerprint(DESIGN)
        assert len(fp) == 12
        assert "fake" not in fp
        assert fp != design_fingerprint(OTHER)
        assert design_fingerprint(None) is None
        # Same refresh token, rotated access token: same family.
        assert fp == design_fingerprint({**DESIGN, "accessToken": "rotated"})

    def test_newer_design_oauth_orders_by_expiry(self):
        old = {**DESIGN, "expiresAt": 1}
        new = {**DESIGN, "expiresAt": 2}
        assert newer_design_oauth(old, new) is new
        assert newer_design_oauth(new, old) is new
        assert newer_design_oauth(DESIGN, OTHER) is DESIGN  # tie: first
        assert newer_design_oauth(None, OTHER) is OTHER
        assert newer_design_oauth(DESIGN, None) is DESIGN
        assert newer_design_oauth({"expiresAt": "x"}, new)["expiresAt"] == "x"

    def test_with_design_oauth_sets_and_removes(self):
        login = json.dumps({"claudeAiOauth": {"accessToken": "a"}})
        with_design = with_design_oauth(login, DESIGN)
        assert json.loads(with_design)["designOauth"] == DESIGN
        assert "designOauth" not in json.loads(with_design_oauth(with_design, None))
        assert with_design_oauth(login, None) == login
        assert with_design_oauth(API_KEY, DESIGN) == API_KEY

    def test_design_only_blob_is_login_less(self):
        assert is_login_less(json.dumps({"designOauth": DESIGN}))
        assert is_login_less(json.dumps({"cloudSessionsOauth": {}, "mcpOAuth": {}}))
        assert not is_login_less(json.dumps({"claudeAiOauth": {}, "designOauth": {}}))
        assert not is_login_less(json.dumps({"somethingNew": 1}))


class TestSwap:
    def test_target_slot_keeps_its_own_design_oauth(self):
        target = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-target"},
            "designOauth": OTHER,
        })
        live = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-live"},
            "designOauth": DESIGN,
        })
        merged = json.loads(
            merge_shared_credential_fields(target, shared_credential_fields(live))
        )
        assert merged["designOauth"] == OTHER
        assert merged["claudeAiOauth"] == {"accessToken": "fake-target"}

    def test_slot_without_design_oauth_gets_no_fallback(self):
        target = json.dumps({"claudeAiOauth": {"accessToken": "fake-target"}})
        live = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-live"},
            "designOauth": DESIGN,
            "cloudSessionsOauth": {"accessToken": "fake-cloud"},
        })
        merged = json.loads(
            merge_shared_credential_fields(target, shared_credential_fields(live))
        )
        assert "designOauth" not in merged
        assert "cloudSessionsOauth" not in merged

    def test_oauth_swap_writes_only_the_targets_design_oauth(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        live = _live(temp_home, designOauth=DESIGN)
        target = json.dumps({"claudeAiOauth": {"accessToken": "fake-target"}})

        switcher._write_credentials(
            switcher._prepare_credentials_for_activation(target, live)
        )

        written = json.loads(_cred_file(temp_home).read_text())
        assert "designOauth" not in written
        assert written["claudeAiOauth"] == {"accessToken": "fake-target"}

    def test_api_key_swap_drops_login_and_design_oauth(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        _live(temp_home, designOauth=DESIGN)

        switcher._write_credentials(API_KEY)

        assert not _cred_file(temp_home).exists()

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
    def test_add_account_captures_the_live_design_oauth(self, temp_home):
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
        switcher.add_account()

        assert "a@x.com" in json.dumps(switcher._get_sequence_data()["accounts"])
        assert _cred_file(temp_home).read_text() == live
        stored = switcher._read_account_credentials("1", "a@x.com")
        assert json.loads(stored)["designOauth"] == DESIGN

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


class TestLoginLessBlobs:
    """What Claude Code writes while a managed key is active must not mask the
    key, and only its shared fields cross to the next OAuth account."""

    def test_active_read_sees_through_design_only_file(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        switcher._write_credentials(API_KEY)
        # /design-login while the key is active.
        _cred_file(temp_home).write_text(json.dumps({"designOauth": DESIGN}))

        assert switcher._read_credentials() == API_KEY

    def test_api_key_to_oauth_does_not_carry_design_oauth(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        switcher._write_credentials(API_KEY)
        _cred_file(temp_home).write_text(json.dumps({"designOauth": DESIGN}))

        target = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-target"},
            "designOauth": OTHER,
        })
        switcher._write_credentials(
            switcher._prepare_credentials_for_activation(
                target, switcher._read_credentials()
            )
        )

        written = json.loads(_cred_file(temp_home).read_text())
        assert written["designOauth"] == OTHER
        assert written["claudeAiOauth"] == {"accessToken": "fake-target"}

    def test_login_less_blob_carries_shared_keys_only(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        switcher._write_credentials(API_KEY)
        # Claude Code rewrites the whole blob, e.g. after an MCP authorisation.
        mcp = {"server": {"refreshToken": "fake-mcp"}}
        _cred_file(temp_home).write_text(
            json.dumps({"designOauth": DESIGN, "mcpOAuth": mcp})
        )

        assert switcher._read_credentials() == API_KEY

        target = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-target"},
            "mcpOAuth": {"server": {"refreshToken": "stale"}},
        })
        switcher._write_credentials(
            switcher._prepare_credentials_for_activation(
                target, switcher._read_credentials()
            )
        )
        written = json.loads(_cred_file(temp_home).read_text())
        assert "designOauth" not in written
        assert written["mcpOAuth"] == mcp
        assert written["claudeAiOauth"] == {"accessToken": "fake-target"}

    def test_login_less_blob_without_a_key_is_still_live_state(self, temp_home):
        # Upstream's behaviour: with no managed key, the login-less blob is
        # what the switch composes shared fields from.
        switcher = ClaudeAccountSwitcher()
        blob = json.dumps({"mcpOAuth": {"server": {"refreshToken": "current"}}})
        _cred_file(temp_home).write_text(blob)

        assert switcher._read_credentials() == blob

    def test_capture_never_takes_a_login_less_blob_for_a_login(self, temp_home):
        from claude_swap.session import read_config_dir_credentials

        profile = temp_home / "p"
        profile.mkdir()
        (profile / ".credentials.json").write_text(json.dumps({
            "designOauth": DESIGN,
            "mcpOAuth": {"server": {"refreshToken": "x"}},
        }))

        assert read_config_dir_credentials(str(profile)) is None

    def test_stale_login_file_is_not_a_residue_source(self, temp_home):
        switcher = ClaudeAccountSwitcher()
        _live(temp_home, designOauth={"accessToken": "stale-file-copy"})
        target = json.dumps({
            "claudeAiOauth": {"accessToken": "fake-target"},
            "designOauth": DESIGN,
        })

        assert switcher._prepare_credentials_for_activation(target, None) == target
