"""API-key accounts keep their own Claude Design login.

``/design-login`` while a managed API key is active saves a Design login into
Claude Code's OAuth store, next to the key and with no claude.ai login there.
The key's slot keeps it beside its raw-key backup: a switch away captures the
newer generation, activating the key writes it back. File backend on Linux and
Windows, macOS with the fake ``security`` (the real Keychain in CI through
``test_design_oauth_macos_real``). Fake credentials only.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import macos_keychain, migrations, transfer
from claude_swap.credentials import (
    CLAUDE_CODE_KEYCHAIN_SERVICE,
    SECURITY_SERVICE,
    CredentialStore,
    is_login_less,
)
from claude_swap.exceptions import CredentialError, CredentialWriteError, SwitchError
from claude_swap.models import Platform

from tests.claude_code_sim import FileStore, KeychainStore
from tests.test_design_oauth_macos import keychain  # noqa: F401
from tests.test_design_oauth_per_account import (
    API_KEY,
    D1,
    D2,
    D4,
    D5,
    _applied,
    _backup,
    _bootstrap,
    _design,
    _email,
    _login,
    _platform,
    _roster,
    linux,  # noqa: F401
)

KEY_SLOT = "4"
KEY_EMAIL = "api-key-4@token.local"
KEY2 = "sk-ant-api03-" + "f6g7h8i9j0" * 4
KEY2_EMAIL = "api-key-5@token.local"
MCP = {"server": {"refreshToken": "fake-mcp-rt"}}
D4_NEW = {"accessToken": "fake-d4-new-at", "refreshToken": "fake-d4-new-rt",
          "expiresAt": 9000}
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


def _entry(path: Path, email: str) -> dict:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    return next(a for a in envelope["accounts"] if a["email"] == email)


class KeyDesignScenarios:
    """Subclasses provide ``sw`` and say where Claude Code keeps its store."""

    def live_store(self, home: Path):
        return FileStore(home / ".claude")

    def forget_key_designs(self, sw) -> None:
        """Hook: a real Keychain keeps items from earlier tests."""

    @pytest.fixture
    def store(self, sw, temp_home):
        """Accounts 1 and 2 (OAuth, own Design logins D1/D2; 1 is logged in)
        and the API key in slot 4, which has no Design login yet."""
        _roster(sw, temp_home, {"1": _login("1", D1), "2": _login("2", D2)},
                active="1")
        self.forget_key_designs(sw)
        sw.add_account_from_token(API_KEY, slot=4)
        return self.live_store(temp_home)

    def key_design(self, sw, slot: str = KEY_SLOT, email: str = KEY_EMAIL):
        design, readable = sw._store.read_key_design(slot, email)
        assert readable
        return design

    def key_active_with(self, sw, store, design: dict) -> None:
        """Activate the key, then ``/design-login`` saves ``design``."""
        sw.switch_to(KEY_SLOT, json_output=True)
        store.write({**store.read(), "designOauth": design})

    # -- switching -----------------------------------------------------------

    def test_the_key_keeps_its_own_design_login(self, sw, store):
        sw.switch_to(KEY_SLOT, json_output=True)
        assert sw._read_credentials() == API_KEY
        assert store.read() == {}  # account 1's went with its login
        store.write({"designOauth": D4})  # /design-login while the key is active

        sw.switch_to("1", json_output=True)
        assert store.read()["designOauth"] == D1
        assert self.key_design(sw) == D4
        assert sw._read_account_credentials(KEY_SLOT, KEY_EMAIL) == API_KEY

        sw.switch_to(KEY_SLOT, json_output=True)
        assert store.read() == {"designOauth": D4}
        assert sw._read_credentials() == API_KEY

        sw.switch_to("2", json_output=True)
        assert store.read()["designOauth"] == D2
        assert _design(_backup(sw, "1")) == D1
        sw.switch_to(KEY_SLOT, json_output=True)
        assert store.read() == {"designOauth": D4}

    def test_key_to_key_each_keeps_its_own(self, sw, store):
        sw.add_account_from_token(KEY2, slot=5)
        self.key_active_with(sw, store, D4)

        sw.switch_to("5", json_output=True)
        assert store.read() == {}
        assert sw._read_credentials() == KEY2
        store.write({"designOauth": D5})

        sw.switch_to(KEY_SLOT, json_output=True)
        assert store.read() == {"designOauth": D4}
        assert self.key_design(sw, "5", KEY2_EMAIL) == D5
        sw.switch_to("5", json_output=True)
        assert store.read() == {"designOauth": D5}

    def test_shared_fields_stay_with_the_machine(self, sw, store):
        store.write({**store.read(), "mcpOAuth": MCP})  # authorised as account 1
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)

        sw.switch_to(KEY_SLOT, json_output=True)
        assert store.read() == {"mcpOAuth": MCP, "designOauth": D4}

        sw.switch_to("2", json_output=True)
        live = store.read()
        assert live["mcpOAuth"] == MCP
        assert live["designOauth"] == D2

    def test_a_newer_live_generation_is_captured(self, sw, store):
        self.key_active_with(sw, store, D4)
        sw.switch_to("1", json_output=True)
        sw.switch_to(KEY_SLOT, json_output=True)
        store.write({"designOauth": D4_NEW})  # Claude Code refreshed it

        sw.switch_to("1", json_output=True)
        assert self.key_design(sw) == D4_NEW

    def test_a_stored_newer_generation_is_not_replaced(self, sw, store):
        self.key_active_with(sw, store, D4)
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4_NEW)

        sw.switch_to("1", json_output=True)
        assert self.key_design(sw) == D4_NEW

    def test_an_emptied_store_does_not_shadow_the_key(self, sw, store):
        self.key_active_with(sw, store, D4)
        sw.switch_to("1", json_output=True)
        sw.switch_to(KEY_SLOT, json_output=True)
        # Claude Code dropped a rejected Design login, leaving an empty blob.
        store.write({})
        assert sw._read_credentials() == API_KEY

        sw.switch_to("1", json_output=True)
        assert sw._read_account_credentials(KEY_SLOT, KEY_EMAIL) == API_KEY
        assert self.key_design(sw) == D4  # nothing newer was live

    def test_an_unreadable_live_store_stops_the_switch(self, sw, store):
        self.key_active_with(sw, store, D4)
        unreadable = patch.object(
            CredentialStore, "peek_key_live_design", lambda self: (None, False)
        )
        with unreadable, pytest.raises(SwitchError):
            sw.switch_to("1", json_output=True)

        assert store.read() == {"designOauth": D4}
        assert sw._read_credentials() == API_KEY
        assert sw._get_sequence_data()["activeAccountNumber"] == 4
        assert self.key_design(sw) is None

    def test_an_unreadable_stored_copy_activates_the_key_without_it(self, sw, store):
        self.key_active_with(sw, store, D4)
        sw.switch_to("1", json_output=True)
        unreadable = patch.object(
            CredentialStore, "read_key_design", lambda self, n, e: (None, False)
        )
        with unreadable:
            sw.switch_to(KEY_SLOT, json_output=True)
        assert store.read() == {}
        assert sw._read_credentials() == API_KEY

        sw.switch_to("1", json_output=True)
        assert self.key_design(sw) == D4  # still stored for the next activation

    def test_a_failed_switch_puts_the_key_and_its_design_back(self, sw, store):
        self.key_active_with(sw, store, D4)
        store.write({**store.read(), "mcpOAuth": MCP})
        config_path = Path(sw._get_claude_config_path())
        real = sw._write_json

        def failing(path, data):
            if Path(path) == config_path:
                raise OSError("fake: config write failed")
            return real(path, data)

        with patch.object(sw, "_write_json", side_effect=failing):
            with pytest.raises(SwitchError):
                sw.switch_to("1", json_output=True)

        assert sw._read_credentials() == API_KEY
        assert store.read() == {"designOauth": D4, "mcpOAuth": MCP}
        assert self.key_design(sw) == D4

    def test_a_failed_design_write_still_clears_the_outgoing_login(self, sw, store):
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        real = CredentialStore._write_oauth_credentials

        def refuse_login_less(self, credentials):
            if is_login_less(credentials):
                raise CredentialWriteError("fake: store write failed")
            return real(self, credentials)

        with patch.object(CredentialStore, "_write_oauth_credentials", refuse_login_less):
            sw.switch_to(KEY_SLOT, json_output=True)

        assert store.read() == {}  # account 1's login is gone, nothing shadows the key
        assert sw._read_credentials() == API_KEY
        assert self.key_design(sw) == D4

    def test_forced_reactivation_keeps_the_newer_live_copy(self, sw, store):
        self.key_active_with(sw, store, D4)
        sw.switch_to("1", json_output=True)
        sw.switch_to(KEY_SLOT, json_output=True)
        store.write({"designOauth": D4_NEW})

        sw.switch_to(KEY_SLOT, json_output=True, force=True)
        assert store.read() == {"designOauth": D4_NEW}
        assert self.key_design(sw) == D4_NEW

    def test_forced_reactivation_proceeds_when_the_copy_fails(self, sw, store):
        """--force rewrites the live login even when the safety copy fails;
        so it does when the key's Design login cannot be kept."""
        self.key_active_with(sw, store, D4)
        unreadable = patch.object(
            CredentialStore, "peek_key_live_design", lambda self: (None, False)
        )
        with unreadable:
            result = sw.switch_to(KEY_SLOT, json_output=True, force=True)
        assert any("Design login" in w for w in result["warnings"])
        assert sw._read_credentials() == API_KEY

    # -- slot lifecycle ------------------------------------------------------

    def test_remove_drops_it(self, sw, store):
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        sw.remove_account(KEY_SLOT, assume_yes=True)
        assert sw._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (None, True)

    def test_swap_and_move_carry_it(self, sw, store):
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)

        sw.swap_accounts(KEY_SLOT, "2")  # the key to slot 2, account 2 to slot 4
        assert self.key_design(sw, "2", KEY_EMAIL) == D4
        assert sw._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (None, True)
        assert sw._store.read_key_design(KEY_SLOT, _email("2")) == (None, True)

        sw.move_account("2", "7")
        assert self.key_design(sw, "7", KEY_EMAIL) == D4
        assert sw._store.read_key_design("2", KEY_EMAIL) == (None, True)

        sw.switch_to("7", json_output=True)
        assert store.read() == {"designOauth": D4}

    def test_a_failed_swap_restores_it(self, sw, store):
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        real = sw._write_json

        def failing(path, data):
            if Path(path) == Path(sw.sequence_file):
                raise OSError("fake: commit failed")
            return real(path, data)

        with patch.object(sw, "_write_json", side_effect=failing):
            with pytest.raises(OSError):
                sw.swap_accounts(KEY_SLOT, "2")

        assert self.key_design(sw) == D4
        assert sw._store.read_key_design("2", KEY_EMAIL) == (None, True)

    def test_a_same_email_swap_trades_them(self, sw, store):
        """Two keys under one email (different organizations): their storage
        keys overlap, so the swap stages both Design logins."""
        data = sw._get_sequence_data()
        data["accounts"]["5"] = {**data["accounts"][KEY_SLOT], "organizationUuid": "org-5"}
        data["sequence"] = sorted({*data["sequence"], 5})
        sw._write_json(sw.sequence_file, data)
        sw._write_account_credentials("5", KEY_EMAIL, KEY2)
        sw._write_account_config("5", KEY_EMAIL, json.dumps(
            {"oauthAccount": {"emailAddress": KEY_EMAIL, "organizationUuid": "org-5"}}
        ))
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        sw._store.write_key_design("5", KEY_EMAIL, D5)

        sw.swap_accounts(KEY_SLOT, "5")
        assert sw._read_account_credentials("5", KEY_EMAIL) == API_KEY
        assert self.key_design(sw, "5", KEY_EMAIL) == D4
        assert self.key_design(sw, KEY_SLOT, KEY_EMAIL) == D5
        assert not list(sw.credentials_dir.glob(".swap-staging-*"))

    def test_add_token_keeps_it_and_takes_it_along(self, sw, store):
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        sw.add_account_from_token(API_KEY, email=KEY_EMAIL)  # renewed in place
        assert self.key_design(sw) == D4

        sw.add_account_from_token(API_KEY, email=KEY_EMAIL, slot=7, assume_yes=True)
        assert self.key_design(sw, "7", KEY_EMAIL) == D4
        assert sw._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (None, True)

    def test_purge_removes_it(self, sw, store):
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        with patch("builtins.input", return_value="y"):
            sw.purge()
        assert sw._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (None, True)

    def test_only_a_full_export_carries_it(self, sw, store, tmp_path):
        self.key_active_with(sw, store, D4)  # live only, the key is active
        slim, full = tmp_path / "slim.cswap", tmp_path / "full.cswap"
        transfer.export_accounts(sw, str(slim))
        transfer.export_accounts(sw, str(full), full=True)
        assert "designOauth" not in _entry(slim, KEY_EMAIL)
        assert _entry(full, KEY_EMAIL)["designOauth"] == D4

        sw.switch_to("1", json_output=True)
        sw.remove_account(KEY_SLOT, assume_yes=True)
        transfer.import_accounts(sw, str(full))
        assert self.key_design(sw) == D4

        # An older or slim export never replaces a newer stored copy.
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4_NEW)
        transfer.import_accounts(sw, str(full), force=True)
        assert self.key_design(sw) == D4_NEW
        transfer.import_accounts(sw, str(slim), force=True)
        assert self.key_design(sw) == D4_NEW

    # -- one-time migration --------------------------------------------------

    def test_migration_removes_another_accounts_copy(self, sw, store):
        sw.switch_to(KEY_SLOT, json_output=True)
        # The old machine-shared rule left account 1's copy next to the key.
        store.write({"designOauth": D1, "mcpOAuth": MCP})

        assert migrations.migrate_design_oauth_api_key_residue(sw) is True
        assert migrations.KEY_RESIDUE_MIGRATION_ID in _applied(sw)
        assert store.read() == {"mcpOAuth": MCP}
        assert sw._read_credentials() == API_KEY

        sw.switch_to("1", json_output=True)
        assert self.key_design(sw) is None
        assert _design(_backup(sw, "1")) == D1

    def test_migration_removes_a_copy_held_by_a_session_profile(self, sw, store):
        session_dir = _bootstrap(sw, "2")
        (session_dir / ".credentials.json").write_text(_login("2", D5))
        sw.switch_to(KEY_SLOT, json_output=True)
        store.write({"designOauth": D5})

        assert migrations.migrate_design_oauth_api_key_residue(sw) is True
        assert store.read() == {}
        assert sw._read_credentials() == API_KEY

    def test_migration_keeps_the_keys_own(self, sw, store):
        self.key_active_with(sw, store, D4)

        assert migrations.migrate_design_oauth_api_key_residue(sw) is True
        assert store.read() == {"designOauth": D4}
        sw.switch_to("1", json_output=True)
        assert self.key_design(sw) == D4

    def test_migration_waits_for_an_unreadable_backup(self, sw, store):
        sw.switch_to(KEY_SLOT, json_output=True)
        store.write({"designOauth": D1})
        unreadable = patch.object(
            type(sw), "_read_account_credentials_ex", lambda self, n, e: ("", True)
        )
        with unreadable:
            migrations.run_migrations(sw)
        assert migrations.KEY_RESIDUE_MIGRATION_ID not in _applied(sw)
        assert store.read() == {"designOauth": D1}

        migrations.run_migrations(sw)
        assert migrations.KEY_RESIDUE_MIGRATION_ID in _applied(sw)
        assert store.read() == {}


class TestKeyDesignLinux(KeyDesignScenarios):
    @pytest.fixture
    def sw(self, linux):  # noqa: F811
        return linux


class TestKeyDesignWindows(KeyDesignScenarios):
    @pytest.fixture
    def sw(self, temp_home, monkeypatch):
        return _platform(monkeypatch, Platform.WINDOWS)


@pytest.mark.no_keychain_fake
@pytest.mark.skipif(sys.platform == "win32", reason="fake security is a POSIX script")
class TestKeyDesignMacOS(KeyDesignScenarios):
    """The key in the "Claude Code" item, its Design login in the
    "Claude Code-credentials" item, the stored copy in cswap's own service."""

    @pytest.fixture
    def sw(self, temp_home, keychain, monkeypatch):  # noqa: F811
        return _platform(monkeypatch, Platform.MACOS)

    def live_store(self, home):
        return KeychainStore(home / ".claude", CLAUDE_CODE_KEYCHAIN_SERVICE)

    def forget_key_designs(self, sw) -> None:
        for slot in ("2", "4", "5", "7"):
            for email in (KEY_EMAIL, KEY2_EMAIL, _email("2")):
                sw._store.delete_key_design(slot, email)

    def test_it_is_kept_in_the_keychain(self, sw, store):
        self.key_active_with(sw, store, D4)
        sw.switch_to("1", json_output=True)

        item = macos_keychain.get_password(SECURITY_SERVICE, f"design-4-{KEY_EMAIL}")
        assert json.loads(item) == {"designOauth": D4}
        assert not sw._store._key_design_path(KEY_SLOT, KEY_EMAIL).exists()


class TestKeyDesignStore:
    """The stored copy itself, file backend."""

    def test_roundtrip_under_its_own_name(self, linux, temp_home):  # noqa: F811
        store = linux._store
        store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        assert store.read_key_design(KEY_SLOT, KEY_EMAIL) == (D4, True)
        # A distinct prefix: no email turns it into a backup or .prev name.
        assert sorted(p.name for p in linux.credentials_dir.iterdir()) == [
            f".design-4-{KEY_EMAIL}.enc"
        ]
        store.write_key_design(KEY_SLOT, KEY_EMAIL, None)
        assert store.read_key_design(KEY_SLOT, KEY_EMAIL) == (None, True)
        assert not list(linux.credentials_dir.iterdir())

    def test_a_corrupt_file_reads_as_none(self, linux, temp_home):  # noqa: F811
        linux._setup_directories()
        linux._store._key_design_path(KEY_SLOT, KEY_EMAIL).write_text("!!!!")
        assert linux._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (None, True)

    @posix_only
    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads anything")
    def test_an_unreadable_file_is_not_absent(self, linux, temp_home):  # noqa: F811
        linux._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        path = linux._store._key_design_path(KEY_SLOT, KEY_EMAIL)
        path.chmod(0)
        try:
            assert linux._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (None, False)
        finally:
            path.chmod(0o600)

    def test_a_strict_delete_that_cannot_clear_raises(self, linux, temp_home):  # noqa: F811
        linux._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        with patch.object(Path, "unlink", side_effect=PermissionError("fake")):
            with pytest.raises(CredentialError):
                linux._store.delete_key_design(KEY_SLOT, KEY_EMAIL, strict=True)
            linux._store.delete_key_design(KEY_SLOT, KEY_EMAIL)  # best effort: logs
        assert linux._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (D4, True)

    def test_an_empty_store_holds_no_login(self):
        assert is_login_less("{}")
        assert not is_login_less(API_KEY)


@pytest.mark.no_keychain_fake
@pytest.mark.skipif(sys.platform == "win32", reason="fake security is a POSIX script")
class TestKeyDesignStoreMacOS:
    @pytest.fixture
    def sw(self, temp_home, keychain, monkeypatch):  # noqa: F811
        return _platform(monkeypatch, Platform.MACOS)

    def test_a_file_written_while_the_keychain_failed_wins(self, sw):
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        payload = json.dumps({"designOauth": D4_NEW})
        sw._setup_directories()
        sw._store._key_design_path(KEY_SLOT, KEY_EMAIL).write_text(
            base64.b64encode(payload.encode()).decode()
        )
        assert sw._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (D4_NEW, True)

    def test_a_failed_keychain_write_falls_back_to_a_file(self, sw, monkeypatch):
        def refuse(*args):
            raise macos_keychain.KeychainError("fake: write refused")

        monkeypatch.setattr(macos_keychain, "set_password", refuse)
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)
        assert sw._store._key_design_path(KEY_SLOT, KEY_EMAIL).exists()
        assert sw._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (D4, True)

    def test_a_failed_read_leaves_the_routing_alone(self, sw, monkeypatch):
        sw._store.write_key_design(KEY_SLOT, KEY_EMAIL, D4)

        def fail(*args):
            raise macos_keychain.KeychainError("fake: read failed")

        monkeypatch.setattr(macos_keychain, "get_password", fail)
        assert sw._store.read_key_design(KEY_SLOT, KEY_EMAIL) == (None, False)
        # The switch's rollback snapshot of the store next to the key, too.
        assert sw._store.peek_login_less() is None
        assert sw._store._use_keychain()

    def test_activating_the_key_leaves_no_login_in_any_item(
        self, sw, keychain, temp_home, monkeypatch  # noqa: F811
    ):
        """CLAUDE_CONFIG_DIR naming the default profile: two OAuth items
        (Claude Code's hashed one and the legacy unsuffixed one). Writing the
        key's Design login must not leave the outgoing login in the other."""
        from claude_swap.credentials import login_less_blob
        from claude_swap.session import keychain_service_name

        config_dir = str(temp_home / ".claude")
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", config_dir)
        hashed = keychain_service_name(config_dir)
        for service in (hashed, CLAUDE_CODE_KEYCHAIN_SERVICE):
            keychain.put(service, _login("1", D1))

        sw._store._write_credentials(API_KEY, login_less_blob({}, D4))

        assert keychain.get_json(hashed) == {"designOauth": D4}
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None
