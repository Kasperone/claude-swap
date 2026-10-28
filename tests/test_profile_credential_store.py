"""cswap reads, writes and deletes the ACTIVE profile's credential store only.

- The plaintext file lives in Claude Code's secure-storage dir:
  ``CLAUDE_SECURESTORAGE_CONFIG_DIR`` when defined (empty meaning ``~/.claude``),
  else the config home.
- On macOS, under ``CLAUDE_CONFIG_DIR``, the OAuth item and the managed-key item
  are claude's hashed ones; the default profile's items are never touched.

The macOS cases run the real ``macos_keychain`` code against the fake
``security`` script (``keychain`` fixture). Fake credentials only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from claude_swap import macos_keychain
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.exceptions import CredentialReadError, ValidationError
from claude_swap.models import Platform
from claude_swap.session import keychain_service_name
from claude_swap.switcher import ClaudeAccountSwitcher

from tests.fake_keychain import ACCOUNT

API_KEY = "sk-ant-api03-" + "a1b2c3d4e5" * 4
DEFAULT_KEY = "sk-ant-api03-" + "z9y8x7w6v5" * 4

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="fake security is a POSIX script"
)


def _login(token: str) -> str:
    return json.dumps({"claudeAiOauth": {"accessToken": token}})


def _switcher(platform: Platform) -> ClaudeAccountSwitcher:
    sw = ClaudeAccountSwitcher()
    sw.platform = platform
    return sw


def _swap(sw: ClaudeAccountSwitcher, target: str) -> None:
    """The activation sequence ``_perform_switch`` runs."""
    live = sw._read_credentials()
    sw._write_credentials(sw._prepare_credentials_for_activation(target, live))


def _write_identity(config_dir: Path) -> None:
    (config_dir / ".claude.json").write_text(json.dumps({
        "oauthAccount": {
            "emailAddress": "a@x.com",
            "accountUuid": "u1",
            "organizationUuid": "",
            "organizationName": "",
        }
    }))


@posix_only
@pytest.mark.no_keychain_fake
def test_fake_security_roundtrip(keychain):
    macos_keychain.set_password("svc", ACCOUNT, '{"a": "b c"}')
    assert macos_keychain.get_password("svc", ACCOUNT) == '{"a": "b c"}'
    macos_keychain.delete_password("svc", ACCOUNT)
    assert macos_keychain.get_password("svc", ACCOUNT) is None


def test_account_name_falls_back_like_claude_code(monkeypatch):
    monkeypatch.setenv("USER", "dom\\user name")
    assert macos_keychain.keychain_account_name() == "claude-code-user"
    monkeypatch.setenv("USER", "ok.user-1_x")
    assert macos_keychain.keychain_account_name() == "ok.user-1_x"


@pytest.mark.parametrize("platform", [Platform.LINUX, Platform.WINDOWS])
class TestSecureStorageDir:
    """The plaintext store follows CLAUDE_SECURESTORAGE_CONFIG_DIR."""

    def test_defined_dir_holds_the_active_file(self, temp_home, monkeypatch, platform):
        secure = temp_home / "secure"
        secure.mkdir()
        monkeypatch.setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", str(secure))
        config_home_file = temp_home / ".claude" / ".credentials.json"
        config_home_file.write_text(_login("fake-config-home"))
        cred = secure / ".credentials.json"
        cred.write_text(_login("fake-live"))
        sw = _switcher(platform)

        _swap(sw, _login("fake-target"))
        assert json.loads(cred.read_text())["claudeAiOauth"]["accessToken"] == (
            "fake-target"
        )
        _swap(sw, API_KEY)
        assert not cred.exists()

        assert config_home_file.read_text() == _login("fake-config-home")

    def test_defined_empty_means_the_default_dir(self, temp_home, profile, monkeypatch, platform):
        monkeypatch.setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", "")
        cred = temp_home / ".claude" / ".credentials.json"
        cred.write_text(_login("fake-live"))

        _swap(_switcher(platform), _login("fake-target"))

        assert json.loads(cred.read_text())["claudeAiOauth"]["accessToken"] == (
            "fake-target"
        )
        assert not (profile / ".credentials.json").exists()


@posix_only
@pytest.mark.no_keychain_fake
class TestEnvVarProfileKeychain:
    """Under CLAUDE_CONFIG_DIR every Keychain read, write and delete targets
    claude's hashed items; the default profile's items stay byte-identical."""

    @pytest.fixture
    def sw(self, profile, keychain, monkeypatch):
        monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.MACOS))
        return _switcher(Platform.MACOS)

    def test_switch_writes_and_clears_the_hashed_item(self, sw, profile, keychain):
        hashed = keychain_service_name(str(profile))
        keychain.put(hashed, _login("fake-live"))

        _swap(sw, _login("fake-target"))
        assert keychain.get(hashed) == _login("fake-target")

        _swap(sw, API_KEY)
        assert keychain.get(hashed) is None
        assert sw._read_credentials() == API_KEY

    def test_default_profile_items_are_never_touched(self, sw, profile, keychain):
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-default"))
        keychain.put("Claude Code", DEFAULT_KEY)
        keychain.put(keychain_service_name(str(profile)), _login("fake-live"))

        for target in (_login("fake-target"), API_KEY, _login("fake-target2")):
            _swap(sw, target)
            assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == _login("fake-default")
            assert keychain.get("Claude Code") == DEFAULT_KEY

    def test_no_item_is_created_in_the_default_service(self, sw, profile, keychain):
        keychain.put(keychain_service_name(str(profile)), _login("fake-live"))

        _swap(sw, _login("fake-target"))

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None

    def test_other_profiles_item_is_never_touched(self, sw, profile, keychain, temp_home):
        other = keychain_service_name(str(temp_home / "profiles" / "other"))
        keychain.put(other, _login("fake-other"))
        keychain.put(keychain_service_name(str(profile)), _login("fake-live"))

        _swap(sw, API_KEY)

        assert keychain.get(other) == _login("fake-other")

    def test_managed_key_uses_the_profiles_own_item(self, sw, profile, keychain):
        # Claude Code names the managed-key item like the credentials item
        # minus "-credentials": hashed under CLAUDE_CONFIG_DIR.
        hashed_key = keychain_service_name(str(profile)).replace("-credentials", "")
        keychain.put(keychain_service_name(str(profile)), _login("fake-live"))

        _swap(sw, API_KEY)
        assert keychain.get(hashed_key) == API_KEY
        assert sw._read_credentials() == API_KEY

        _swap(sw, _login("fake-target"))
        assert keychain.get(hashed_key) is None

    def test_add_account_sees_the_profiles_own_managed_key_only(
        self, sw, profile, keychain
    ):
        sw._setup_directories()
        _write_identity(profile)
        keychain.put("Claude Code", DEFAULT_KEY)

        with pytest.raises(CredentialReadError):  # not the default profile's key
            sw.add_account()

        hashed_key = keychain_service_name(str(profile)).replace("-credentials", "")
        keychain.put(hashed_key, API_KEY)
        with pytest.raises(ValidationError):  # this profile's key: rejected as API key
            sw.add_account()


@posix_only
@pytest.mark.no_keychain_fake
class TestEnvVarNamingTheDefaultProfile:
    """CLAUDE_CONFIG_DIR=~/.claude: both claude's hashed item and the legacy
    unsuffixed one are this profile's. Whichever exists is updated in place."""

    @pytest.fixture
    def sw(self, temp_home, keychain, monkeypatch):
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(temp_home / ".claude"))
        monkeypatch.setattr(Platform, "detect", staticmethod(lambda: Platform.MACOS))
        return _switcher(Platform.MACOS)

    def test_legacy_unsuffixed_item_is_updated_in_place(self, sw, temp_home, keychain):
        hashed = keychain_service_name(str(temp_home / ".claude"))
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live"))

        _swap(sw, _login("fake-target"))
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == _login("fake-target")
        assert keychain.get(hashed) is None

        _swap(sw, API_KEY)
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None

    def test_hashed_item_is_updated_in_place(self, sw, temp_home, keychain):
        hashed = keychain_service_name(str(temp_home / ".claude"))
        keychain.put(hashed, _login("fake-live"))

        _swap(sw, _login("fake-target"))
        assert keychain.get(hashed) == _login("fake-target")
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None

        _swap(sw, API_KEY)
        assert keychain.get(hashed) is None
