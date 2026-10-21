"""``designOauth`` under a ``CLAUDE_CONFIG_DIR`` profile and a session profile.

Both file backend (Linux semantics) and the fake-``security`` Keychain backend
(hashed service name). Fake credentials only, everything under tmp_path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from claude_swap import macos_keychain
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.models import Platform
from claude_swap.session import SessionManager, keychain_service_name
from claude_swap.switcher import ClaudeAccountSwitcher

from tests.test_design_oauth_macos import ACCOUNT, keychain  # noqa: F401

API_KEY = "sk-ant-api03-" + "a1b2c3d4e5" * 4
DESIGN = {"accessToken": "fake-design-at", "refreshToken": "fake-design-rt"}
SESSION_DESIGN = {"accessToken": "fake-session-design-at"}

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="fake security is a POSIX script"
)


def _login(token: str, **extra) -> str:
    return json.dumps({"claudeAiOauth": {"accessToken": token}, **extra})


@pytest.fixture
def profile(temp_home, monkeypatch) -> Path:
    """An env-var profile: CLAUDE_CONFIG_DIR points away from ~/.claude."""
    path = temp_home / "profiles" / "work"
    path.mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(path))
    return path


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
    def test_swap_trio_keeps_design_oauth(self, profile):
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.LINUX  # file backend, whatever the host
        cred = profile / ".credentials.json"
        cred.write_text(_login("fake-live", designOauth=DESIGN))

        _swap(sw, _login("fake-target", designOauth={"accessToken": "stale"}))
        assert json.loads(cred.read_text())["designOauth"] == DESIGN

        _swap(sw, API_KEY)
        assert json.loads(cred.read_text()) == {"designOauth": DESIGN}
        assert sw._read_credentials() == API_KEY

        _swap(sw, _login("fake-target2"))
        written = json.loads(cred.read_text())
        assert written["designOauth"] == DESIGN
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
    def sw(self, profile, keychain, monkeypatch):  # noqa: F811
        monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.MACOS))
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.MACOS
        return sw

    def test_swap_trio_keeps_design_oauth_in_the_hashed_item(
        self, sw, profile, keychain  # noqa: F811
    ):
        hashed = keychain_service_name(str(profile))
        keychain.put(hashed, _login("fake-live", designOauth=DESIGN))

        _swap(sw, _login("fake-target", designOauth={"accessToken": "stale"}))
        item = keychain.get_json(hashed)
        assert item["designOauth"] == DESIGN
        assert item["claudeAiOauth"] == {"accessToken": "fake-target"}

        _swap(sw, API_KEY)
        assert keychain.get_json(hashed) == {"designOauth": DESIGN}
        assert sw._read_credentials() == API_KEY

        _swap(sw, _login("fake-target2"))
        item = keychain.get_json(hashed)
        assert item["designOauth"] == DESIGN
        assert item["claudeAiOauth"] == {"accessToken": "fake-target2"}

    def test_default_profile_item_is_never_touched(self, sw, profile, keychain):  # noqa: F811
        default_item = _login("fake-default", designOauth={"accessToken": "default"})
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, default_item)
        keychain.put(
            keychain_service_name(str(profile)),
            _login("fake-live", designOauth=DESIGN),
        )

        _swap(sw, _login("fake-target"))
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == default_item
        _swap(sw, API_KEY)
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == default_item
        _swap(sw, _login("fake-target2"))
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == default_item

    def test_other_profiles_hashed_item_is_never_touched(
        self, sw, profile, keychain, temp_home  # noqa: F811
    ):
        other = keychain_service_name(str(temp_home / "profiles" / "other"))
        other_item = _login("fake-other", designOauth={"accessToken": "other"})
        keychain.put(other, other_item)
        keychain.put(keychain_service_name(str(profile)), _login("fake-live"))

        _swap(sw, API_KEY)

        assert keychain.get(other) == other_item

    def test_no_item_is_created_in_the_default_service(self, sw, profile, keychain):  # noqa: F811
        keychain.put(
            keychain_service_name(str(profile)),
            _login("fake-live", designOauth=DESIGN),
        )

        _swap(sw, API_KEY)

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None

    def test_managed_key_uses_the_profiles_own_item(self, sw, profile, keychain):  # noqa: F811
        # Claude Code names the managed-key item like the credentials item
        # minus "-credentials": hashed under CLAUDE_CONFIG_DIR. The default
        # profile's "Claude Code" key must never be written or deleted.
        hashed_managed = keychain_service_name(str(profile)).replace("-credentials", "")
        default_key = "sk-ant-api03-" + "z9y8x7w6v5" * 4
        keychain.put("Claude Code", default_key)
        keychain.put(
            keychain_service_name(str(profile)),
            _login("fake-live", designOauth=DESIGN),
        )

        _swap(sw, API_KEY)
        assert keychain.get(hashed_managed) == API_KEY
        assert keychain.get("Claude Code") == default_key
        assert sw._read_credentials() == API_KEY

        _swap(sw, _login("fake-target"))
        assert keychain.get(hashed_managed) is None
        assert keychain.get("Claude Code") == default_key
        assert keychain.get_json(keychain_service_name(str(profile)))[
            "designOauth"
        ] == DESIGN

    def test_add_account_sees_the_profiles_own_managed_key_only(
        self, sw, profile, keychain  # noqa: F811
    ):
        from claude_swap.exceptions import CredentialReadError, ValidationError

        sw._setup_directories()
        _write_identity(profile)
        keychain.put("Claude Code", "sk-ant-api03-" + "z9y8x7w6v5" * 4)  # default's

        with pytest.raises(CredentialReadError):  # not the default profile's key
            sw.add_account()

        hashed_managed = keychain_service_name(str(profile)).replace("-credentials", "")
        keychain.put(hashed_managed, API_KEY)
        with pytest.raises(ValidationError):  # this profile's key: rejected as API key
            sw.add_account()

    def test_design_only_item_is_not_a_login_for_capture(self, sw, profile, keychain):  # noqa: F811
        from claude_swap.session import read_config_dir_credentials

        keychain.put(
            keychain_service_name(str(profile)), json.dumps({"designOauth": DESIGN})
        )

        assert read_config_dir_credentials(str(profile)) is None

    def test_add_account_leaves_hashed_item(self, sw, profile, keychain):  # noqa: F811
        sw._setup_directories()
        hashed = keychain_service_name(str(profile))
        live = _login("fake-live", designOauth=DESIGN)
        keychain.put(hashed, live)
        _write_identity(profile)

        sw.add_account()

        assert "a@x.com" in json.dumps(sw._get_sequence_data()["accounts"])
        assert keychain.get(hashed) == live


@posix_only
@pytest.mark.no_keychain_fake
class TestEnvVarNamingTheDefaultProfile:
    """CLAUDE_CONFIG_DIR=~/.claude: both the hashed and the legacy unsuffixed
    item are this profile's. The existing one is kept."""

    @pytest.fixture
    def sw(self, temp_home, keychain, monkeypatch):  # noqa: F811
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(temp_home / ".claude"))
        monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.MACOS))
        sw = ClaudeAccountSwitcher()
        sw.platform = Platform.MACOS
        return sw

    def test_legacy_unsuffixed_item_is_updated_in_place(
        self, sw, temp_home, keychain  # noqa: F811
    ):
        hashed = keychain_service_name(str(temp_home / ".claude"))
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live", designOauth=DESIGN)
        )

        _swap(sw, _login("fake-target"))
        item = keychain.get_json(CLAUDE_CODE_KEYCHAIN_SERVICE)
        assert item["designOauth"] == DESIGN
        assert item["claudeAiOauth"] == {"accessToken": "fake-target"}
        assert keychain.get(hashed) is None

        _swap(sw, API_KEY)
        assert keychain.get_json(CLAUDE_CODE_KEYCHAIN_SERVICE) == {
            "designOauth": DESIGN
        }

    def test_hashed_item_is_updated_in_place(self, sw, temp_home, keychain):  # noqa: F811
        hashed = keychain_service_name(str(temp_home / ".claude"))
        keychain.put(hashed, _login("fake-live", designOauth=DESIGN))

        _swap(sw, API_KEY)

        assert keychain.get_json(hashed) == {"designOauth": DESIGN}
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None


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
    """Re-seeding a session profile from backup must keep the profile's own
    designOauth: it logged into Claude Design inside that session."""

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
        self, temp_home, keychain, monkeypatch  # noqa: F811
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
