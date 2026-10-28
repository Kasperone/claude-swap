"""Per-account ``designOauth``: full switches and sessions.

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

from claude_swap import macos_keychain
from claude_swap import session as session_mod
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.models import Platform
from claude_swap.session import SessionManager, keychain_service_name, session_dir_for
from claude_swap.switcher import ClaudeAccountSwitcher


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

    def test_unreadable_key_never_backs_up_the_login_less_blob(
        self, linux, temp_home, monkeypatch
    ):
        # With the key unreadable, the active read answers the login-less blob
        # beside it; the switch must not file it as the key slot's backup.
        sw = linux
        _roster(sw, temp_home, {"1": _login("1", D1)}, active="1")
        sw.add_account_from_token(API_KEY, slot=4)
        sw.switch_to("4", json_output=True)
        _live_file(temp_home).write_text(json.dumps({"designOauth": D4}))
        monkeypatch.setattr(type(sw._store), "_read_managed_key", lambda self: "")

        sw.switch_to("1", json_output=True)

        assert sw._read_account_credentials("4", "api-key-4@token.local") == API_KEY
        assert _design(_live_file(temp_home).read_text()) == D1


class TestActiveRefreshLiveWrite:
    """cswap's refresh of the default login from the slot backup: the live
    write takes the shared fields from the live store, and the Design login
    Claude Code holds there now."""

    def test_backup_sourced_refresh_keeps_live_mcp_and_design(
        self, linux, temp_home
    ):
        from claude_swap import oauth

        sw = linux
        mcp_stale, mcp_current = {"srv": "stale"}, {"srv": "current"}
        backup = {**json.loads(_login("1", D1)), "mcpOAuth": mcp_stale}
        _roster(sw, temp_home, {"1": json.dumps(backup)}, active="1")
        # The live store holds an older, foreign-lineage generation, so the
        # refresh POSTs the backup's grant; its mcpOAuth is the current one.
        live_text = json.dumps({
            "claudeAiOauth": {
                "accessToken": "fake-login-1-at-old",
                "refreshToken": "fake-login-1-rt-old",
                "expiresAt": 4000,
            },
            "designOauth": D1,
            "mcpOAuth": mcp_current,
        })
        sw._write_credentials(live_text)
        live = _live_file(temp_home)
        newer = {**D1, "accessToken": "fake-d1-newer", "expiresAt": 9000}

        def refresh(creds, **_kw):
            blob = json.loads(creds)
            blob["claudeAiOauth"] = {
                "accessToken": "fake-login-1-at-posted",
                "refreshToken": "fake-login-1-rt-posted",
                "expiresAt": 99000,
            }
            return oauth.RefreshOutcome(json.dumps(blob), None)

        real_backup_write = sw._write_account_credentials

        def backup_write(*args):
            real_backup_write(*args)
            # Claude Code saves a Design refresh after the backup write and
            # before cswap's live write.
            live.write_text(json.dumps(
                {**json.loads(live.read_text()), "designOauth": newer}
            ))

        with (
            patch("claude_swap.oauth.try_refresh_oauth_credentials",
                  side_effect=refresh),
            patch("claude_swap.oauth.try_fetch_usage_for_account",
                  return_value=oauth.UsageOutcome({"five_hour": {"pct": 5}})),
            patch.object(sw, "_write_account_credentials",
                         side_effect=backup_write),
        ):
            record = sw._fetch_active_usage("1", _email("1"), live_text)

        assert record.error is None and record.sentinel is None, record
        written = json.loads(live.read_text())
        assert written["claudeAiOauth"]["refreshToken"] == "fake-login-1-rt-posted"
        assert written["mcpOAuth"] == mcp_current
        assert written["designOauth"] == newer


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


def session_dir_creds(session_dir: Path) -> str:
    return (session_dir / ".credentials.json").read_text()


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

    def test_invalidation_keeps_a_newer_design_whatever_the_slot_org(self, run_env):
        # Mid-swap the slot's record can still be the other account's (another
        # org): the profile's newer Design login is adopted all the same.
        sw, session_dir = run_env
        _bootstrap(sw, "2")
        (session_dir / ".claude.json").write_text(json.dumps({"oauthAccount": {
            "emailAddress": _email("2"), "accountUuid": "u2",
            "organizationUuid": "org-2",
        }}))
        (session_dir / ".credentials.json").write_text(_login("2", D2))
        data = sw._get_sequence_data()
        data["accounts"]["2"]["organizationUuid"] = "org-of-the-other-account"
        sw._write_json(sw.sequence_file, data)

        assert sw._invalidate_session_credentials("2", _email("2")) is True

        assert _design(_backup(sw, "2")) == D2
        assert not (session_dir / ".credentials.json").exists()

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


def _identity_file(session_dir: Path, num: str) -> None:
    (session_dir / ".claude.json").write_text(json.dumps({
        "oauthAccount": {"emailAddress": _email(num), "accountUuid": f"u{num}"}
    }))


class TestSwitchMatrixWindows(TestSwitchMatrix):
    @pytest.fixture
    def linux(self, temp_home, monkeypatch):  # the Windows file backend
        return _platform(monkeypatch, Platform.WINDOWS)


@pytest.mark.no_keychain_fake
@pytest.mark.skipif(sys.platform == "win32", reason="fake security is a POSIX script")
class TestSessionsMacOS:
    """A session's Design login in the profile's hashed Keychain item."""

    @pytest.fixture
    def sw(self, temp_home, keychain, monkeypatch):
        self.keychain = keychain
        return _platform(monkeypatch, Platform.MACOS)

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

    def test_reseed_never_carries_a_drifted_profiles_design(self, sw, temp_home):
        # In-session /login as another account, then /design-login: the
        # profile's Design login is that other account's.
        session_dir = self._setup(sw, temp_home, backup_design=None,
                                  profile_design=D3)
        (session_dir / ".claude.json").write_text(json.dumps({
            "oauthAccount": {"emailAddress": "someone@else.com", "accountUuid": "z"}
        }))

        seed = json.loads(session_dir_creds(_bootstrap(sw, "2")))

        assert "designOauth" not in seed
        sw._adopt_session_credential("2", _email("2"), "")
        assert _design(_backup(sw, "2")) is None

    def _rotate_profile_login(self, session_dir: Path, design: dict | None) -> None:
        """The session refreshed its login (a newer generation than the
        backup's), holding ``design``."""
        blob = json.loads(_login("2", design, expires=9000))
        blob["claudeAiOauth"]["refreshToken"] = "fake-login-2-rt-next"
        blob["claudeAiOauth"]["accessToken"] = "fake-login-2-at-next"
        self.profile_write(session_dir, json.dumps(blob))

    @staticmethod
    def _refresh(creds: str, **_kw):
        from claude_swap import oauth

        blob = json.loads(creds)
        blob["claudeAiOauth"] = {
            "accessToken": "fake-login-2-at-posted",
            "refreshToken": "fake-login-2-rt-posted",
            "expiresAt": 99000,
        }
        return oauth.RefreshOutcome(json.dumps(blob), None)

    def test_gate_resync_keeps_the_newer_backup_design(self, sw, temp_home):
        session_dir = self._setup(sw, temp_home, backup_design=D2_NEWER,
                                  profile_design=D2_OLDER)
        self._rotate_profile_login(session_dir, D2_OLDER)

        with patch("claude_swap.oauth.try_refresh_oauth_credentials",
                   side_effect=self._refresh):
            result = sw.consume_backup_grant("2", _email("2"), _backup(sw, "2"))

        stored = json.loads(_backup(sw, "2"))
        assert stored["claudeAiOauth"]["refreshToken"] == "fake-login-2-rt-posted"
        assert stored["designOauth"] == D2_NEWER
        assert _design(result.credentials) == D2_NEWER

    def test_gate_persist_keeps_a_design_written_during_the_post(self, sw, temp_home):
        _roster(sw, temp_home, {"1": _login("1", D1), "2": _login("2", D2)},
                active="1")

        def refresh(creds, **kw):
            # e.g. a session adoption in another process, under the lock,
            # while this POST is in flight: same login, newer Design login.
            sw._store._write_account_credentials(
                "2", _email("2"), _login("2", D2_NEWER)
            )
            return self._refresh(creds)

        with patch("claude_swap.oauth.try_refresh_oauth_credentials",
                   side_effect=refresh):
            result = sw.consume_backup_grant("2", _email("2"), _backup(sw, "2"))

        stored = json.loads(_backup(sw, "2"))
        assert stored["claudeAiOauth"]["refreshToken"] == "fake-login-2-rt-posted"
        assert stored["designOauth"] == D2_NEWER
        assert _design(result.credentials) == D2_NEWER

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
    def sw(self, temp_home, keychain, monkeypatch):
        self.keychain = keychain
        return _platform(monkeypatch, Platform.MACOS)

    def profile_write(self, session_dir, creds):
        self.keychain.put(keychain_service_name(session_dir), creds)

    def _unreadable_item(self, session_dir, monkeypatch):
        """Reading the profile's item fails (a denied or timed-out Keychain
        prompt), while deleting it would still succeed. Returns the real
        reader, to make it readable again."""
        service = keychain_service_name(session_dir)
        real = macos_keychain.get_password

        def get_password(svc, account):
            if svc == service:
                raise macos_keychain.KeychainError("fake: read refused")
            return real(svc, account)

        monkeypatch.setattr(macos_keychain, "get_password", get_password)
        self._real_get = real
        return real

    def _item_design(self, session_dir) -> dict | None:
        # Past the refusing reader: what the item really holds.
        value = self._real_get(
            keychain_service_name(session_dir), macos_keychain.keychain_account_name()
        )
        return json.loads(value).get("designOauth") if value else None

    def test_unreadable_item_survives_an_invalidation(self, sw, temp_home, monkeypatch):
        session_dir = self._setup(sw, temp_home)
        real = self._unreadable_item(session_dir, monkeypatch)

        # The backup is rewritten (e.g. a capture): the quiescent profile
        # would be invalidated, deleting its item.
        sw._write_account_credentials("2", _email("2"), _login("2", D2))

        assert self._item_design(session_dir) == D2_NEWER
        assert session_mod.is_session_stale(session_dir)
        assert _design(_backup(sw, "2")) == D2

        # Readable again: the next invalidation keeps it in the backup.
        monkeypatch.setattr(macos_keychain, "get_password", real)
        assert sw._invalidate_session_credentials("2", _email("2")) is True
        assert _design(_backup(sw, "2")) == D2_NEWER

    def test_unreadable_item_survives_a_reseed(self, sw, temp_home, monkeypatch):
        session_dir = self._setup(sw, temp_home, backup_design=D2_OLDER)
        self._unreadable_item(session_dir, monkeypatch)

        _bootstrap(sw, "2")

        assert self._item_design(session_dir) == D2_NEWER
        assert session_mod.is_session_stale(session_dir)

    def test_unreadable_item_survives_a_failed_validation_cleanup(
        self, sw, temp_home, monkeypatch
    ):
        session_dir = self._setup(sw, temp_home, backup_design=None)
        self._unreadable_item(session_dir, monkeypatch)

        SessionManager(sw)._cleanup_failed_session(session_dir, "2", _email("2"), "")

        assert session_dir.exists()
        assert self._item_design(session_dir) == D2_NEWER
        assert session_mod.is_session_stale(session_dir)
