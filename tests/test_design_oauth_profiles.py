"""``designOauth`` under a ``CLAUDE_CONFIG_DIR`` profile and a session profile.

Both file backend (Linux semantics) and the fake-``security`` Keychain backend
(hashed service name). Fake credentials only, everything under tmp_path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from claude_swap.models import Platform
from claude_swap.session import SessionManager, keychain_service_name
from claude_swap.switcher import ClaudeAccountSwitcher


API_KEY = "sk-ant-api03-" + "a1b2c3d4e5" * 4
DESIGN = {"accessToken": "fake-design-at", "refreshToken": "fake-design-rt"}
SESSION_DESIGN = {"accessToken": "fake-session-design-at"}
OTHER = {"accessToken": "fake-other-at", "refreshToken": "fake-other-rt"}

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="fake security is a POSIX script"
)


def _login(token: str, **extra) -> str:
    return json.dumps({"claudeAiOauth": {"accessToken": token}, **extra})


def _swap(sw: ClaudeAccountSwitcher, target: str) -> None:
    live = sw._read_credentials()
    sw._write_credentials(sw._prepare_credentials_for_activation(target, live))


def _write_identity(profile: Path) -> None:
    (profile / ".claude.json").write_text(json.dumps({
        "oauthAccount": {
            "emailAddress": "a@x.com",
            "accountUuid": "u1",
            "organizationUuid": "",
            "organizationName": "",
        }
    }))


class TestEnvVarProfileFile:
    def test_swap_trio_activates_each_targets_own_design_oauth(self, profile):
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.LINUX  # file backend, whatever the host
        cred = profile / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _swap(sw, _login("fake-target", designOauth=OTHER))
        assert json.loads(cred.read_text())["designOauth"] == OTHER

        _swap(sw, API_KEY)
        assert not cred.exists()
        assert sw._read_credentials() == API_KEY

        _swap(sw, _login("fake-target2"))
        written = json.loads(cred.read_text())
        assert "designOauth" not in written
        assert written["claudeAiOauth"] == {"accessToken": "fake-target2"}

    def test_default_profile_file_is_not_touched(self, profile, temp_home):
        default = temp_home / ".claude" / ".credentials.json"
        default.write_text(_login("fake-default", designOauth=DESIGN))
        before = default.read_text()
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.LINUX  # file backend, whatever the host
        (profile / ".credentials.json").write_text(_login("fake-live"))

        _swap(sw, API_KEY)

        assert default.read_text() == before

    def test_add_account_leaves_profile_file(self, profile):
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.LINUX  # file backend, whatever the host
        sw._setup_directories()
        live = _login("fake-live", designOauth=DESIGN)
        (profile / ".credentials.json").write_text(live)
        _write_identity(profile)

        sw.add_account()

        assert "a@x.com" in json.dumps(sw._get_sequence_data()["accounts"])
        assert (profile / ".credentials.json").read_text() == live


@posix_only
@pytest.mark.no_keychain_fake
class TestEnvVarProfileKeychain:
    """With CLAUDE_CONFIG_DIR set, the active item is claude's hashed service.
    Reads, writes and deletes all target it and nothing else: the default
    profile's unsuffixed item must stay byte-identical."""

    @pytest.fixture
    def sw(self, profile, keychain, monkeypatch):
        monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.MACOS))
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.MACOS
        return sw

    def test_swap_trio_activates_each_targets_own_design_in_the_hashed_item(
        self, sw, profile, keychain
    ):
        hashed = keychain_service_name(str(profile))
        keychain.put(hashed, _login("fake-live", designOauth=DESIGN))

        _swap(sw, _login("fake-target", designOauth=OTHER))
        item = keychain.get_json(hashed)
        assert item["designOauth"] == OTHER
        assert item["claudeAiOauth"] == {"accessToken": "fake-target"}

        _swap(sw, API_KEY)
        assert keychain.get(hashed) is None
        assert sw._read_credentials() == API_KEY

        _swap(sw, _login("fake-target2"))
        item = keychain.get_json(hashed)
        assert "designOauth" not in item
        assert item["claudeAiOauth"] == {"accessToken": "fake-target2"}

    def test_design_only_item_is_not_a_login_for_capture(self, sw, profile, keychain):
        from claude_swap.session import read_config_dir_credentials

        keychain.put(
            keychain_service_name(str(profile)), json.dumps({"designOauth": DESIGN})
        )
        # Claude Code reads the file only when the item is absent: an old
        # plaintext login behind the item is not the profile's login.
        (profile / ".credentials.json").write_text(_login("fake-stale-seed"))

        assert read_config_dir_credentials(str(profile)) is None

    def test_residual_read_failure_keeps_keychain_routing(self, sw, profile, keychain, monkeypatch):
        from claude_swap import macos_keychain

        def down(*args, **kwargs):
            raise macos_keychain.KeychainError("timed out")

        monkeypatch.setattr(macos_keychain, "get_password", down)
        assert sw._store.residual_shared_fields() is None
        assert sw._store._use_keychain()

    def test_add_account_leaves_hashed_item(self, sw, profile, keychain):
        sw._setup_directories()
        hashed = keychain_service_name(str(profile))
        live = _login("fake-live", designOauth=DESIGN)
        keychain.put(hashed, live)
        _write_identity(profile)

        sw.add_account()

        assert "a@x.com" in json.dumps(sw._get_sequence_data()["accounts"])
        assert keychain.get(hashed) == live


def _seed_slot(sw: ClaudeAccountSwitcher, creds: str) -> None:
    sw._setup_directories()
    sw._init_sequence_file()
    data = sw._get_sequence_data()
    data["accounts"]["1"] = {
        "email": "a@x.com",
        "uuid": "u1",
        "organizationUuid": "",
        "organizationName": "",
        "added": "2024-01-01T00:00:00Z",
    }
    data["sequence"] = [1]
    sw._write_json(sw.sequence_file, data)
    sw._write_account_credentials("1", "a@x.com", creds)
    sw._write_account_config("1", "a@x.com", json.dumps({
        "oauthAccount": {"emailAddress": "a@x.com", "accountUuid": "u1"},
    }))


class TestSessionProfileFile:
    """Re-seeding a session profile from backup keeps the newer of the
    account's two Design logins (the profile's on a tie): a /design-login
    inside the session is this account's."""

    def test_reseed_keeps_profile_design_oauth(self, temp_home):
        sw = ClaudeAccountSwitcher()
        _seed_slot(sw, _login("fake-backup", designOauth={"accessToken": "stale"}))
        mgr = SessionManager(sw)
        session_dir = sw.backup_dir / "sessions" / "1-a-x-com"
        session_dir.mkdir(parents=True)
        (session_dir / ".credentials.json").write_text(
            _login("fake-old-profile", designOauth=SESSION_DESIGN)
        )

        mgr._bootstrap(session_dir, "1", "a@x.com", "")

        seeded = json.loads((session_dir / ".credentials.json").read_text())
        assert seeded["claudeAiOauth"] == {"accessToken": "fake-backup"}
        assert seeded["designOauth"] == SESSION_DESIGN

    def test_first_seed_uses_backup_verbatim(self, temp_home):
        sw = ClaudeAccountSwitcher()
        backup = _login("fake-backup", designOauth=DESIGN)
        _seed_slot(sw, backup)
        session_dir = sw.backup_dir / "sessions" / "1-a-x-com"

        SessionManager(sw)._bootstrap(session_dir, "1", "a@x.com", "")

        assert (session_dir / ".credentials.json").read_text() == backup

    def test_reseed_without_profile_design_oauth_keeps_backup_copy(self, temp_home):
        sw = ClaudeAccountSwitcher()
        _seed_slot(sw, _login("fake-backup", designOauth=DESIGN))
        session_dir = sw.backup_dir / "sessions" / "1-a-x-com"
        session_dir.mkdir(parents=True)
        (session_dir / ".credentials.json").write_text(_login("fake-old-profile"))

        SessionManager(sw)._bootstrap(session_dir, "1", "a@x.com", "")

        seeded = json.loads((session_dir / ".credentials.json").read_text())
        assert seeded["designOauth"] == DESIGN


@posix_only
@pytest.mark.no_keychain_fake
class TestSessionProfileKeychain:
    def test_reseed_carries_hashed_item_design_oauth_into_seed(
        self, temp_home, keychain, monkeypatch
    ):
        monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.MACOS))
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.MACOS
        _seed_slot(sw, _login("fake-backup"))
        session_dir = sw.backup_dir / "sessions" / "1-a-x-com"
        session_dir.mkdir(parents=True)
        hashed = keychain_service_name(session_dir)
        keychain.put(hashed, _login("fake-rotated", designOauth=SESSION_DESIGN))

        SessionManager(sw)._bootstrap(session_dir, "1", "a@x.com", "")

        # The stale hashed item is gone (it would shadow the seed) and the
        # profile's Design login travelled into the plaintext seed.
        assert keychain.get(hashed) is None
        seeded = json.loads((session_dir / ".credentials.json").read_text())
        assert seeded["claudeAiOauth"] == {"accessToken": "fake-backup"}
        assert seeded["designOauth"] == SESSION_DESIGN


class TestDesignOnlyProfileReseed:
    """A re-seed keeps a designOauth-only profile blob, and
    an existing hashed item is authoritative over the older plaintext seed."""

    def test_design_only_profile_file_survives_reseed(self, temp_home):
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.LINUX
        _seed_slot(sw, _login("fake-backup"))
        session_dir = sw.backup_dir / "sessions" / "1-a-x-com"
        session_dir.mkdir(parents=True)
        (session_dir / ".credentials.json").write_text(
            json.dumps({"designOauth": SESSION_DESIGN})
        )

        SessionManager(sw)._bootstrap(session_dir, "1", "a@x.com", "")

        seeded = json.loads((session_dir / ".credentials.json").read_text())
        assert seeded["designOauth"] == SESSION_DESIGN

    @posix_only
    @pytest.mark.no_keychain_fake
    def test_hashed_item_without_design_beats_stale_seed(
        self, temp_home, keychain, monkeypatch
    ):
        monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.MACOS))
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.MACOS
        backup = _login("fake-backup")
        _seed_slot(sw, backup)
        session_dir = sw.backup_dir / "sessions" / "1-a-x-com"
        session_dir.mkdir(parents=True)
        (session_dir / ".credentials.json").write_text(
            _login("fake-old-seed", designOauth={"accessToken": "stale"})
        )
        keychain.put(keychain_service_name(session_dir), _login("fake-rotated"))

        SessionManager(sw)._bootstrap(session_dir, "1", "a@x.com", "")

        assert (session_dir / ".credentials.json").read_text() == backup
