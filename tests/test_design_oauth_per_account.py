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
D5 = {"accessToken": "fake-d5-at", "refreshToken": "fake-d5-rt", "expiresAt": 3000}
D5_OLD = {"accessToken": "fake-d5-old", "refreshToken": "fake-d5-rt", "expiresAt": 1000}
TOKENS = ("fake-d1", "fake-d2", "fake-d3", "fake-d4", "fake-d5", "fake-login")


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


@pytest.fixture
def run_env(linux, temp_home, monkeypatch):
    """Account 1 is the default login with D1; account 2 has no Design login."""
    sw = linux
    _roster(sw, temp_home, {"1": _login("1", D1), "2": _login("2")}, active="1")
    session_dir = session_dir_for(sw.backup_dir, "2", _email("2"))
    return sw, session_dir


def _bootstrap(sw: ClaudeAccountSwitcher, num: str) -> Path:
    session_dir = session_dir_for(sw.backup_dir, num, _email(num))
    SessionManager(sw)._bootstrap(session_dir, num, _email(num), "")
    return session_dir


def _profile_blob(session_dir: Path) -> dict:
    return json.loads((session_dir / ".credentials.json").read_text())


class TestSessions:
    """``cswap run --require-session``: the profile keeps its own Design
    login, is never seeded with another account's, and a /design-login there
    goes into that account's slot only."""

    def test_new_profile_gets_no_other_accounts_design(self, run_env, temp_home):
        sw, _ = run_env
        session_dir = _bootstrap(sw, "2")
        assert "designOauth" not in _profile_blob(session_dir)
        assert _design(_live_file(temp_home).read_text()) == D1

    def test_new_profile_gets_its_own_slots_design(self, run_env):
        sw, _ = run_env
        sw._store._write_account_credentials("2", _email("2"), _login("2", D2))
        assert _profile_blob(_bootstrap(sw, "2"))["designOauth"] == D2

    def test_design_login_in_session_is_captured_into_its_slot_only(
        self, run_env, temp_home
    ):
        sw, session_dir = run_env
        _bootstrap(sw, "2")
        (session_dir / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": _email("2"), "accountUuid": "u2"}
        }))
        default_before = _live_file(temp_home).read_text()
        # /design-login inside the session: Claude Code writes the profile.
        blob = _profile_blob(session_dir)
        (session_dir / ".credentials.json").write_text(
            json.dumps({**blob, "designOauth": D2})
        )

        assert sw._adopt_session_credential("2", _email("2"), "") is False
        assert _design(_backup(sw, "2")) == D2
        assert json.loads(_backup(sw, "2"))["claudeAiOauth"] == blob["claudeAiOauth"]
        assert _live_file(temp_home).read_text() == default_before
        assert _design(_backup(sw, "1")) == D1

        # Through the default and back: each account still has its own.
        sw.switch_to("2", json_output=True)
        assert _design(_live_file(temp_home).read_text()) == D2
        sw.switch_to("1", json_output=True)
        assert _design(_live_file(temp_home).read_text()) == D1
        assert _design(_backup(sw, "2")) == D2

    def test_rotated_profile_adoption_keeps_the_newer_design(self, run_env):
        sw, session_dir = run_env
        sw._store._write_account_credentials("2", _email("2"), _login("2", D2))
        _bootstrap(sw, "2")
        (session_dir / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": _email("2"), "accountUuid": "u2"}
        }))
        # The session refreshed its login; its profile lacks the newer Design
        # login the backup got meanwhile.
        newer = {**D2, "accessToken": "fake-d2-newer", "expiresAt": 9000}
        rotated = json.loads(_login("2", expires=9000))
        rotated["claudeAiOauth"]["refreshToken"] = "fake-login-2-rt-next"
        (session_dir / ".credentials.json").write_text(json.dumps(rotated))
        sw._store._write_account_credentials("2", _email("2"), _login("2", newer))

        assert sw._adopt_session_credential("2", _email("2"), "") is True
        stored = json.loads(_backup(sw, "2"))
        assert stored["claudeAiOauth"]["refreshToken"] == "fake-login-2-rt-next"
        assert stored["designOauth"] == newer

    def test_older_profile_design_is_not_adopted(self, run_env):
        sw, session_dir = run_env
        sw._store._write_account_credentials("2", _email("2"), _login("2", D2))
        _bootstrap(sw, "2")
        (session_dir / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": _email("2"), "accountUuid": "u2"}
        }))
        blob = _profile_blob(session_dir)
        (session_dir / ".credentials.json").write_text(
            json.dumps({**blob, "designOauth": {**D2, "expiresAt": 1}})
        )

        assert sw._adopt_session_design("2", _email("2"), "") is False
        assert _design(_backup(sw, "2")) == D2

    def test_design_of_a_drifted_profile_is_not_adopted(self, run_env):
        sw, session_dir = run_env
        _bootstrap(sw, "2")
        # An in-session /login re-pointed the profile at another account.
        (session_dir / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "someone@else.com", "accountUuid": "z"}
        }))
        blob = _profile_blob(session_dir)
        (session_dir / ".credentials.json").write_text(
            json.dumps({**blob, "designOauth": D3})
        )

        sw._adopt_session_credential("2", _email("2"), "")
        assert _design(_backup(sw, "2")) is None

    def test_live_profile_is_not_adopted(self, run_env, monkeypatch):
        sw, session_dir = run_env
        _bootstrap(sw, "2")
        blob = _profile_blob(session_dir)
        (session_dir / ".credentials.json").write_text(
            json.dumps({**blob, "designOauth": D2})
        )
        monkeypatch.setattr(session_mod, "profile_is_quiescent", lambda d: False)

        assert sw._adopt_session_credential("2", _email("2"), "") is None
        assert _design(_backup(sw, "2")) is None

    def test_reseed_keeps_the_sessions_design(self, run_env):
        sw, session_dir = run_env
        _bootstrap(sw, "2")
        blob = _profile_blob(session_dir)
        (session_dir / ".credentials.json").write_text(
            json.dumps({**blob, "designOauth": D2})
        )
        assert _profile_blob(_bootstrap(sw, "2"))["designOauth"] == D2

    def test_reseed_takes_the_newer_generation(self, run_env):
        sw, session_dir = run_env
        newer = {**D2, "accessToken": "fake-d2-newer", "expiresAt": 9000}
        sw._store._write_account_credentials("2", _email("2"), _login("2", newer))
        session_dir.mkdir(parents=True)
        (session_dir / ".credentials.json").write_text(_login("2", D2))
        assert _profile_blob(_bootstrap(sw, "2"))["designOauth"] == newer

    def test_remove_and_purge_drop_the_session_design_only(
        self, run_env, temp_home
    ):
        sw, session_dir = run_env
        _bootstrap(sw, "2")
        blob = _profile_blob(session_dir)
        (session_dir / ".credentials.json").write_text(
            json.dumps({**blob, "designOauth": D2})
        )
        live_before = _live_file(temp_home).read_text()

        with patch("builtins.input", return_value="y"):
            sw.remove_account("2")
        assert not session_dir.exists()
        assert _live_file(temp_home).read_text() == live_before

        with patch("builtins.input", return_value="y"):
            sw.purge()
        assert _live_file(temp_home).read_text() == live_before


def _profile(sw: ClaudeAccountSwitcher, num: str, creds: str) -> Path:
    session_dir = session_dir_for(sw.backup_dir, num, _email(num))
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / ".credentials.json").write_text(creds)
    return session_dir


def _identity_file(session_dir: Path, num: str) -> None:
    (session_dir / ".claude.json").write_text(json.dumps({
        "oauthAccount": {"emailAddress": _email(num), "accountUuid": f"u{num}"}
    }))


def _applied(sw: ClaudeAccountSwitcher) -> dict:
    return migrations._load_applied(sw)


class MigrationScenarios:
    """Shared migration scenarios; subclasses provide ``sw`` and ``live_put``
    (where the live credential is stored) for one backend."""

    def live_put(self, sw, home: Path, creds: str) -> None:
        raise NotImplementedError

    def live_get(self, sw, home: Path) -> str | None:
        raise NotImplementedError

    def profile_put(self, sw, num: str, creds: str) -> Path:
        return _profile(sw, num, creds)

    def profile_blob(self, session_dir: Path) -> dict:
        return json.loads(session_dir_creds(session_dir))

    def _shared_era(self, sw, home: Path) -> None:
        """What the old machine-shared rule left behind: the live D1 snapshot
        in every slot it was captured into, and one account's own D3."""
        _roster(sw, home, {
            "1": _login("1", D1_OLD),
            "2": _login("2", D1_OLD),
            "3": _login("3", D3),
            "4": _login("4"),
        }, active="1")
        self.live_put(sw, home, _login("1", D1))

    def test_live_copy_goes_to_the_active_slot_others_dropped(
        self, sw, temp_home, caplog, capsys
    ):
        self._shared_era(sw, temp_home)
        live_before = self.live_get(sw, temp_home)
        caplog.set_level("INFO", logger="claude-swap")

        assert migrations.migrate_design_oauth_per_account(sw) is True

        assert _design(_backup(sw, "1")) == D1
        assert _design(_backup(sw, "2")) is None
        assert _design(_backup(sw, "3")) == D3
        assert _design(_backup(sw, "4")) is None
        # Logins untouched.
        for num in ("1", "2", "3", "4"):
            assert json.loads(_backup(sw, num))["claudeAiOauth"]["accessToken"] == (
                f"fake-login-{num}-at"
            )
        assert self.live_get(sw, temp_home) == live_before  # never written
        # Fingerprints only, never a token.
        out = caplog.text + capsys.readouterr().err
        assert design_fingerprint(D1) in caplog.text
        for token in TOKENS:
            assert token not in out

    def test_retained_prev_generation_of_a_dropped_copy_is_removed(
        self, sw, temp_home
    ):
        self._shared_era(sw, temp_home)
        migrations.migrate_design_oauth_per_account(sw)
        assert sw._store._read_previous_backup("2", _email("2")) in ("", None)

    def test_session_profiles(self, sw, temp_home):
        self._shared_era(sw, temp_home)
        p2 = self.profile_put(sw, "2", _login("2", D1_OLD, expires=7000))
        p3 = self.profile_put(sw, "3", _login("3", D3))
        p4 = self.profile_put(sw, "4", _login("4", D4))

        assert migrations.migrate_design_oauth_per_account(sw) is True

        # Account 2's profile: another account's copy removed, login kept.
        blob2 = self.profile_blob(p2)
        assert "designOauth" not in blob2
        assert blob2["claudeAiOauth"]["expiresAt"] == 7000
        # Account 3's own copy kept; account 4's own adopted into its slot.
        assert self.profile_blob(p3)["designOauth"] == D3
        assert self.profile_blob(p4)["designOauth"] == D4
        assert _design(_backup(sw, "4")) == D4

    def test_live_profile_is_marked_then_stripped_once_quiescent(
        self, sw, temp_home, monkeypatch
    ):
        self._shared_era(sw, temp_home)
        p2 = self.profile_put(sw, "2", _login("2", D1_OLD))
        _identity_file(p2, "2")
        monkeypatch.setattr(session_mod, "profile_is_quiescent", lambda d: False)

        # A running session no longer defers the migration: it completes.
        assert migrations.migrate_design_oauth_per_account(sw) is True
        migrations.run_migrations(sw)
        assert migrations.DESIGN_MIGRATION_ID in _applied(sw)
        assert _design(_backup(sw, "2")) is None
        # Not rewritten under the running claude, but ignored from now on.
        assert self.profile_blob(p2)["designOauth"] == D1_OLD
        assert session_mod._profile_design_oauth(p2) is None
        assert session_mod.foreign_design_fingerprints(p2) == {design_fingerprint(D1)}

        # The session exits: the next adoption strips it, marker gone.
        monkeypatch.setattr(session_mod, "profile_is_quiescent", lambda d: True)
        sw._adopt_session_credential("2", _email("2"), "")
        assert "designOauth" not in self.profile_blob(p2)
        assert not session_mod.foreign_design_marker_for(p2).exists()
        assert _design(_backup(sw, "2")) is None

    def test_marked_profile_keeps_a_design_login_of_its_own_made_since(
        self, sw, temp_home, monkeypatch
    ):
        self._shared_era(sw, temp_home)
        p2 = self.profile_put(sw, "2", _login("2", D1_OLD))
        _identity_file(p2, "2")
        monkeypatch.setattr(session_mod, "profile_is_quiescent", lambda d: False)
        migrations.migrate_design_oauth_per_account(sw)
        # /design-login inside the still-running session: account 2's own.
        self.profile_put(sw, "2", _login("2", D2))

        monkeypatch.setattr(session_mod, "profile_is_quiescent", lambda d: True)
        sw._adopt_session_credential("2", _email("2"), "")

        assert self.profile_blob(p2)["designOauth"] == D2
        assert _design(_backup(sw, "2")) == D2

    def test_idempotent(self, sw, temp_home):
        self._shared_era(sw, temp_home)
        self.profile_put(sw, "2", _login("2", D1_OLD))
        migrations.migrate_design_oauth_per_account(sw)
        before = {n: _backup(sw, n) for n in ("1", "2", "3", "4")}

        assert migrations.migrate_design_oauth_per_account(sw) is True
        assert {n: _backup(sw, n) for n in ("1", "2", "3", "4")} == before

    def test_duplicate_goes_to_the_active_account(self, sw, temp_home):
        _roster(sw, temp_home, {
            "1": _login("1", D5_OLD),
            "2": _login("2", D5),
            "3": _login("3", D3),
        }, active="1")
        self.live_put(sw, temp_home, _login("1"))

        migrations.migrate_design_oauth_per_account(sw)

        assert _design(_backup(sw, "1")) == D5  # its newest generation
        assert _design(_backup(sw, "2")) is None
        assert _design(_backup(sw, "3")) == D3

    def test_duplicate_goes_to_the_most_recent_capture(self, sw, temp_home):
        _roster(sw, temp_home, {
            "1": _login("1"),
            "2": _login("2", D5_OLD),
            "3": _login("3", D5),
        }, active="1")

        migrations.migrate_design_oauth_per_account(sw)

        assert _design(_backup(sw, "1")) is None
        assert _design(_backup(sw, "2")) is None
        assert _design(_backup(sw, "3")) == D5

    def test_ambiguous_duplicate_is_kept_everywhere_with_a_warning(
        self, sw, temp_home, caplog
    ):
        _roster(sw, temp_home, {
            "1": _login("1"),
            "2": _login("2", D5),
            "3": _login("3", D5),
        }, active="1")
        p3 = self.profile_put(sw, "3", _login("3", D5))
        caplog.set_level("INFO", logger="claude-swap")
        before = {n: _backup(sw, n) for n in ("1", "2", "3")}

        assert migrations.migrate_design_oauth_per_account(sw) is True

        assert {n: _backup(sw, n) for n in ("1", "2", "3")} == before
        assert self.profile_blob(p3)["designOauth"] == D5
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert any(design_fingerprint(D5) in r.getMessage() for r in warnings)
        for token in TOKENS:
            assert token not in caplog.text

    def test_duplicate_in_profiles_of_accounts_with_their_own_is_kept(
        self, sw, temp_home
    ):
        # Both accounts already own another family: neither can take D5
        # without losing its own, so nothing is removed.
        _roster(sw, temp_home, {
            "1": _login("1"),
            "2": _login("2", D2),
            "3": _login("3", D3),
        }, active="1")
        p2 = self.profile_put(sw, "2", _login("2", D5))
        p3 = self.profile_put(sw, "3", _login("3", D5))

        migrations.migrate_design_oauth_per_account(sw)

        assert _design(_backup(sw, "2")) == D2
        assert _design(_backup(sw, "3")) == D3
        assert self.profile_blob(p2)["designOauth"] == D5
        assert self.profile_blob(p3)["designOauth"] == D5

    def test_unmanaged_live_login_goes_to_the_active_account(self, sw, temp_home):
        self._shared_era(sw, temp_home)
        _set_identity(temp_home, "9")  # not a managed account
        migrations.migrate_design_oauth_per_account(sw)
        # The roster's active slot holds the family: it keeps the newest (live).
        assert _design(_backup(sw, "1")) == D1
        assert _design(_backup(sw, "2")) is None
        assert _design(_backup(sw, "3")) == D3

    def test_one_shot_even_with_a_live_session(self, sw, temp_home, monkeypatch):
        self._shared_era(sw, temp_home)
        self.profile_put(sw, "2", _login("2", D1_OLD))
        monkeypatch.setattr(session_mod, "profile_is_quiescent", lambda d: False)
        calls = []
        real = migrations._assign_design_oauth
        monkeypatch.setattr(
            migrations, "_assign_design_oauth",
            lambda *a: (calls.append(1), real(*a))[1],
        )

        for _ in range(3):
            migrations.run_migrations(sw)

        assert calls == [1]
        assert migrations.DESIGN_MIGRATION_ID in _applied(sw)
        state = sw.backup_dir / ".migrations.json"
        assert json.loads(state.read_text())["applied"][migrations.DESIGN_MIGRATION_ID]
        assert not list(sw.backup_dir.glob("*.tmp"))  # atomic write, no leftovers

    def test_already_recorded_under_the_lock_runs_nothing(self, sw, temp_home, monkeypatch):
        self._shared_era(sw, temp_home)
        migrations._mark_applied(sw, migrations.DESIGN_MIGRATION_ID)
        monkeypatch.setattr(
            migrations, "_assign_design_oauth",
            lambda *a: pytest.fail("ran although recorded"),
        )
        # Called directly, as a second process that waited for the lock would.
        assert migrations.migrate_design_oauth_per_account(sw) is True
        assert _design(_backup(sw, "2")) == D1_OLD

    def test_version_bump_runs_it_again(self, sw, temp_home, monkeypatch):
        self._shared_era(sw, temp_home)
        migrations.run_migrations(sw)
        # A copy appears after the first run (e.g. restored from a backup).
        sw._store._write_account_credentials("2", _email("2"), _login("2", D1_OLD))
        migrations.run_migrations(sw)
        assert _design(_backup(sw, "2")) == D1_OLD  # recorded: not re-run

        bumped = f"design_oauth_per_account.v{migrations.DESIGN_MIGRATION_VERSION + 1}"
        monkeypatch.setattr(migrations, "DESIGN_MIGRATION_ID", bumped)
        monkeypatch.setattr(migrations, "MIGRATIONS", [
            (i, f) if f is not migrations.migrate_design_oauth_per_account
            else (bumped, f)
            for i, f in migrations.MIGRATIONS
        ])
        migrations.run_migrations(sw)
        assert bumped in _applied(sw)
        assert _design(_backup(sw, "2")) is None


def session_dir_creds(session_dir: Path) -> str:
    return (session_dir / ".credentials.json").read_text()


class TestMigrationLinux(MigrationScenarios):
    @pytest.fixture
    def sw(self, linux):
        return linux

    def live_put(self, sw, home, creds):
        _live_file(home).write_text(creds)

    def live_get(self, sw, home):
        return _live_file(home).read_text()

    def test_api_key_live_goes_to_the_most_recent_capture(self, sw, temp_home):
        self._shared_era(sw, temp_home)
        sw.add_account_from_token(API_KEY, slot=5)
        sw.switch_to("5", json_output=True)
        # The old rule left a design-only residue next to the key.
        _live_file(temp_home).write_text(json.dumps({"designOauth": D1}))

        migrations.migrate_design_oauth_per_account(sw)

        # The key owns none; slot 1 captured the newest generation last.
        assert _design(_backup(sw, "1")) == D1
        assert _design(_backup(sw, "2")) is None
        assert _design(_backup(sw, "3")) == D3
        assert sw._read_account_credentials("5", "api-key-5@token.local") == API_KEY
        assert json.loads(_live_file(temp_home).read_text()) == {"designOauth": D1}

    def test_unreadable_live_store_defers(self, sw, temp_home, monkeypatch):
        self._shared_era(sw, temp_home)
        before = {n: _backup(sw, n) for n in ("1", "2", "3", "4")}
        monkeypatch.setattr(
            type(sw._store), "live_design_oauth", lambda self: (None, False)
        )

        migrations.run_migrations(sw)

        assert migrations.DESIGN_MIGRATION_ID not in _applied(sw)
        assert {n: _backup(sw, n) for n in ("1", "2", "3", "4")} == before

    def test_runs_once_at_construction(self, sw, temp_home, monkeypatch):
        self._shared_era(sw, temp_home)
        _platform(monkeypatch, Platform.LINUX)  # constructs: runs migrations
        assert migrations.DESIGN_MIGRATION_ID in _applied(sw)
        assert _design(_backup(sw, "2")) is None

    def test_fresh_install_is_not_marked(self, sw):
        assert migrations.migrate_design_oauth_per_account(sw) is False


class TestMigrationWindows(MigrationScenarios):
    @pytest.fixture
    def sw(self, temp_home, monkeypatch):
        def boom(*args, **kwargs):
            raise AssertionError("Keychain touched on the Windows path")

        for name in ("get_password", "set_password", "delete_password", "item_exists"):
            monkeypatch.setattr(macos_keychain, name, boom)
        return _platform(monkeypatch, Platform.WINDOWS)

    def live_put(self, sw, home, creds):
        _live_file(home).write_text(creds)

    def live_get(self, sw, home):
        return _live_file(home).read_text()


class TestSwitchMatrixWindows(TestSwitchMatrix):
    @pytest.fixture
    def linux(self, temp_home, monkeypatch):  # the Windows file backend
        return _platform(monkeypatch, Platform.WINDOWS)


@pytest.mark.no_keychain_fake
@pytest.mark.skipif(sys.platform == "win32", reason="fake security is a POSIX script")
class TestMigrationMacOS(MigrationScenarios):
    """The live login in the Keychain item, session profiles in their hashed
    items (Claude Code migrates the plaintext seed there on first write)."""

    @pytest.fixture
    def sw(self, temp_home, keychain, monkeypatch):  # noqa: F811
        self.keychain = keychain
        return _platform(monkeypatch, Platform.MACOS)

    def live_put(self, sw, home, creds):
        self.keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, creds)

    def live_get(self, sw, home):
        return self.keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE)

    def profile_put(self, sw, num, creds):
        # An older plaintext seed next to the newer hashed item.
        session_dir = _profile(sw, num, _login(num, D1_OLD, expires=1))
        self.keychain.put(keychain_service_name(session_dir), creds)
        return session_dir

    def profile_blob(self, session_dir):
        item = self.keychain.get(keychain_service_name(session_dir))
        return json.loads(item) if item else json.loads(session_dir_creds(session_dir))

    def test_stripped_profile_moves_to_the_plaintext_seed(self, sw, temp_home):
        self._shared_era(sw, temp_home)
        p2 = self.profile_put(sw, "2", _login("2", D1_OLD, expires=7000))

        migrations.migrate_design_oauth_per_account(sw)

        # The hashed item is gone (cswap never writes one); the seed carries
        # the profile's own login generation without the foreign copy.
        assert self.keychain.get(keychain_service_name(p2)) is None
        seed = json.loads(session_dir_creds(p2))
        assert "designOauth" not in seed
        assert seed["claudeAiOauth"]["expiresAt"] == 7000

    def test_design_login_in_session_item_is_captured_into_its_slot(
        self, sw, temp_home
    ):
        _roster(sw, temp_home, {"1": _login("1", D1), "2": _login("2")}, active="1")
        session_dir = _bootstrap(sw, "2")
        (session_dir / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": _email("2"), "accountUuid": "u2"}
        }))
        # /design-login inside the session lands in the profile's hashed item.
        blob = json.loads(session_dir_creds(session_dir))
        self.keychain.put(
            keychain_service_name(session_dir), json.dumps({**blob, "designOauth": D2})
        )
        live_before = self.keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE)

        sw._adopt_session_credential("2", _email("2"), "")

        assert _design(_backup(sw, "2")) == D2
        assert self.keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == live_before
        # A re-seed keeps it, from the item, into the plaintext seed.
        assert json.loads(session_dir_creds(_bootstrap(sw, "2")))["designOauth"] == D2


D2_NEWER = {**D2, "accessToken": "fake-d2-newer", "expiresAt": 9000}
D2_OLDER = {**D2, "accessToken": "fake-d2-older", "expiresAt": 1}


class SessionFreshnessScenarios:
    """A session profile's Design login is never dropped or overwritten by an
    older copy when cswap invalidates, re-seeds or cleans the profile up.
    Subclasses say where Claude Code keeps the profile's credential."""

    def profile_write(self, session_dir: Path, creds: str) -> None:
        (session_dir / ".credentials.json").write_text(creds)

    def _setup(self, sw, home, backup_design=D2, profile_design=D2_NEWER):
        _roster(sw, home, {"1": _login("1", D1), "2": _login("2", backup_design)},
                active="1")
        session_dir = _bootstrap(sw, "2")
        _identity_file(session_dir, "2")
        blob = json.loads(session_dir_creds(session_dir))
        blob["designOauth"] = profile_design
        self.profile_write(session_dir, json.dumps(blob))
        return session_dir

    def test_backup_rewrite_keeps_the_newer_session_design(self, sw, temp_home):
        session_dir = self._setup(sw, temp_home)
        # e.g. account 2 re-captured from the default login: the switcher's
        # writer invalidates the quiescent profile afterwards.
        sw._write_account_credentials("2", _email("2"), _login("2", D2))

        assert _design(_backup(sw, "2")) == D2_NEWER
        assert not (session_dir / ".credentials.json").exists()
        # The re-seed carries it back.
        assert json.loads(session_dir_creds(_bootstrap(sw, "2")))["designOauth"] == (
            D2_NEWER
        )

    def test_older_session_design_never_overwrites_the_backup(self, sw, temp_home):
        self._setup(sw, temp_home, backup_design=D2, profile_design=D2_OLDER)
        sw._write_account_credentials("2", _email("2"), _login("2", D2))
        assert _design(_backup(sw, "2")) == D2

    def test_stale_marked_profile_still_keeps_its_newer_design(self, sw, temp_home):
        session_dir = self._setup(sw, temp_home)
        session_mod.mark_session_stale(session_dir)

        sw._invalidate_session_credentials("2", _email("2"))

        assert _design(_backup(sw, "2")) == D2_NEWER

    def test_failed_validation_cleanup_keeps_the_newer_design(self, sw, temp_home):
        session_dir = self._setup(sw, temp_home, backup_design=None)

        SessionManager(sw)._cleanup_failed_session(session_dir, "2", _email("2"), "")

        assert not session_dir.exists()
        assert _design(_backup(sw, "2")) == D2_NEWER

    def test_reseed_never_takes_an_older_backup_copy(self, sw, temp_home):
        session_dir = self._setup(sw, temp_home, backup_design=D2_OLDER)
        assert json.loads(session_dir_creds(_bootstrap(sw, "2")))["designOauth"] == (
            D2_NEWER
        )
        del session_dir

    def test_marked_foreign_copy_is_never_carried(self, sw, temp_home):
        session_dir = self._setup(sw, temp_home, backup_design=None,
                                  profile_design=D1)
        session_mod.mark_foreign_design(session_dir, design_fingerprint(D1))

        sw._write_account_credentials("2", _email("2"), _login("2"))

        assert _design(_backup(sw, "2")) is None
        assert not session_mod.foreign_design_marker_for(session_dir).exists()

    def test_backup_one_family_profile_another_is_compared_by_expiry(
        self, sw, temp_home
    ):
        # A fresh /design-login in the session (new family, later expiry).
        fresh = {**D3, "expiresAt": 9500}
        self._setup(sw, temp_home, backup_design=D2, profile_design=fresh)
        assert sw._adopt_session_credential("2", _email("2"), "") is False
        assert _design(_backup(sw, "2")) == fresh


class TestSessionFreshnessLinux(SessionFreshnessScenarios):
    @pytest.fixture
    def sw(self, linux):
        return linux


class TestSessionFreshnessWindows(SessionFreshnessScenarios):
    @pytest.fixture
    def sw(self, temp_home, monkeypatch):
        return _platform(monkeypatch, Platform.WINDOWS)


@pytest.mark.no_keychain_fake
@pytest.mark.skipif(sys.platform == "win32", reason="fake security is a POSIX script")
class TestSessionFreshnessMacOS(SessionFreshnessScenarios):
    """Claude Code keeps the session's rotated blob in the hashed item."""

    @pytest.fixture
    def sw(self, temp_home, keychain, monkeypatch):  # noqa: F811
        self.keychain = keychain
        return _platform(monkeypatch, Platform.MACOS)

    def profile_write(self, session_dir, creds):
        self.keychain.put(keychain_service_name(session_dir), creds)
