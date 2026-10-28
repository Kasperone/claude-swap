"""``designOauth`` on the macOS Keychain path, against a FAKE ``security`` CLI.

``macos_keychain`` is pointed at an executable script that stores items in a JSON
file under tmp_path, so the real subprocess/argv/``-i`` stdin code runs without
touching any Keychain. Fake credentials only.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import patch

import pytest

from claude_swap import macos_keychain
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.models import Platform
from claude_swap.switcher import ClaudeAccountSwitcher


pytestmark = [
    pytest.mark.no_keychain_fake,
    pytest.mark.skipif(sys.platform == "win32", reason="fake security is a POSIX script"),
]

API_KEY = "sk-ant-api03-" + "a1b2c3d4e5" * 4
DESIGN = {"accessToken": "fake-design-at", "refreshToken": "fake-design-rt"}
OTHER = {"accessToken": "fake-other-at", "refreshToken": "fake-other-rt"}


@pytest.fixture
def switcher(temp_home, keychain) -> ClaudeAccountSwitcher:
    sw = ClaudeAccountSwitcher()
    sw.platform = Platform.MACOS
    return sw


def _login(token: str, **extra) -> str:
    return json.dumps({"claudeAiOauth": {"accessToken": token}, **extra})


def _swap(sw: ClaudeAccountSwitcher, target: str) -> None:
    """The activation sequence ``_perform_switch`` runs."""
    live = sw._read_credentials()
    sw._write_credentials(sw._prepare_credentials_for_activation(target, live))


class TestSwapOnKeychain:
    def test_oauth_to_oauth_activates_the_targets_own_design(self, switcher, keychain):
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live", designOauth=DESIGN)
        )
        _swap(switcher, _login("fake-target", designOauth=OTHER))

        item = keychain.get_json(CLAUDE_CODE_KEYCHAIN_SERVICE)
        assert item["designOauth"] == OTHER
        assert item["claudeAiOauth"] == {"accessToken": "fake-target"}

    def test_oauth_to_oauth_without_target_design_has_none(self, switcher, keychain):
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live", designOauth=DESIGN)
        )
        _swap(switcher, _login("fake-target"))

        assert "designOauth" not in keychain.get_json(CLAUDE_CODE_KEYCHAIN_SERVICE)

    def test_oauth_to_api_key_removes_login_and_design(self, switcher, keychain):
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live", designOauth=DESIGN)
        )
        _swap(switcher, API_KEY)

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None
        assert switcher._read_credentials() == API_KEY

    def test_oauth_to_api_key_without_design_oauth_removes_item(
        self, switcher, keychain
    ):
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live"))
        _swap(switcher, API_KEY)

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None

    def test_design_login_while_key_active_does_not_mask_or_cross(
        self, switcher, keychain
    ):
        _swap(switcher, API_KEY)
        # /design-login while the key is active.
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, json.dumps({"designOauth": DESIGN}))
        assert switcher._read_credentials() == API_KEY

        target = _login("fake-target")
        _swap(switcher, target)

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == target

    def test_login_less_item_shadows_a_stale_plaintext_login(
        self, switcher, keychain, temp_home
    ):
        # Claude Code reads the plaintext file only when the item is absent:
        # with a (login-less) item present, a leftover file login is not the
        # active credential.
        _swap(switcher, API_KEY)
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, json.dumps({"designOauth": DESIGN}))
        (temp_home / ".claude" / ".credentials.json").write_text(_login("fake-stale"))

        assert switcher._read_credentials() == API_KEY

        switcher._store._clear_managed_key()
        assert switcher._read_credentials() == json.dumps({"designOauth": DESIGN})

    def test_api_key_to_oauth_without_residue_is_verbatim(self, switcher, keychain):
        _swap(switcher, API_KEY)
        target = _login("fake-target")
        _swap(switcher, target)

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == target

    def test_stale_credentials_file_is_refreshed_with_the_targets_design(
        self, switcher, keychain, temp_home
    ):
        cred_file = temp_home / ".claude" / ".credentials.json"
        cred_file.write_text(_login("fake-old", designOauth=DESIGN))
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live", designOauth=DESIGN)
        )
        _swap(switcher, _login("fake-target", designOauth=OTHER))

        assert json.loads(cred_file.read_text())["designOauth"] == OTHER


class TestAddRemovePurgeOnKeychain:
    def _seed(self, sw, keychain):
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
        live = _login("fake-live", designOauth=DESIGN)
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, live)
        return live

    def test_add_account_leaves_live_item(self, switcher, keychain, temp_home):
        switcher._setup_directories()
        live = _login("fake-live", designOauth=DESIGN)
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, live)
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
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == live

    def test_remove_account_leaves_live_item(self, switcher, keychain, monkeypatch):
        live = self._seed(switcher, keychain)
        monkeypatch.setattr("builtins.input", lambda *a, **k: "y")
        switcher.remove_account("1")

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == live

    def test_purge_leaves_live_item(self, switcher, keychain):
        live = self._seed(switcher, keychain)
        with patch("builtins.input", return_value="y"):
            switcher.purge()

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == live


class TestKeychainWriteFailure:
    """The Keychain write fails, so cswap falls back to the file and deletes
    the Keychain item (it would shadow the file). The machine-shared fields
    the item holds travel into the file first; its designOauth does not — it
    belongs to the outgoing account."""

    @pytest.fixture
    def failing(self, switcher, keychain, monkeypatch):
        monkeypatch.setenv("FAKE_SECURITY_FAIL_ADD", "1")
        return switcher

    def test_shared_fields_move_into_file_design_does_not(
        self, failing, keychain, temp_home
    ):
        item = _login(
            "fake-live",
            designOauth=DESIGN,
            mcpOAuth={"server": {"refreshToken": "fake-mcp"}},
        )
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, item)

        failing._write_credentials(_login("fake-target"))

        written = json.loads((temp_home / ".claude" / ".credentials.json").read_text())
        assert written["claudeAiOauth"] == {"accessToken": "fake-target"}
        assert "designOauth" not in written
        assert written["mcpOAuth"] == {"server": {"refreshToken": "fake-mcp"}}
        # The stale item is gone so it cannot shadow the file.
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None

    def test_credentials_own_design_is_written(self, failing, keychain, temp_home):
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE,
            _login("fake-live", designOauth={"accessToken": "older"}),
        )
        incoming = _login("fake-target", designOauth=OTHER)

        failing._write_credentials(incoming)

        written = json.loads((temp_home / ".claude" / ".credentials.json").read_text())
        assert written["designOauth"] == OTHER

    def test_item_without_shared_fields_leaves_credentials_verbatim(
        self, failing, keychain, temp_home
    ):
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live", designOauth=DESIGN)
        )
        target = _login("fake-target")

        failing._write_credentials(target)

        assert (temp_home / ".claude" / ".credentials.json").read_text() == target

    def test_failed_write_with_unwritable_file_keeps_the_item(
        self, failing, keychain, temp_home, monkeypatch
    ):
        # Both stores refuse: the existing item must not be deleted.
        from claude_swap.exceptions import CredentialWriteError

        item = _login("fake-live", designOauth=DESIGN)
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, item)

        def boom(self, creds):
            raise OSError("disk full")

        monkeypatch.setattr(
            type(failing._store), "_write_active_credentials_file", boom
        )
        with pytest.raises(CredentialWriteError):
            failing._write_credentials(_login("fake-target"))

        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == item


class TestFileFallbackKeychainReads:
    """The file fallback reads the failed Keychain item once, and only then."""

    def test_graft_reads_once_and_only_after_a_failed_write(
        self, switcher, keychain, monkeypatch, temp_home
    ):
        mcp = {"server": {"refreshToken": "fake-mcp"}}
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE,
            _login("fake-live", designOauth=DESIGN, mcpOAuth=mcp),
        )
        monkeypatch.setenv("FAKE_SECURITY_FAIL_ADD", "1")
        reads = []
        real_get = macos_keychain.get_password
        monkeypatch.setattr(
            macos_keychain,
            "get_password",
            lambda svc, acct: (reads.append(svc), real_get(svc, acct))[1],
        )

        switcher._store._write_oauth_credentials(_login("fake-target"))

        assert reads == [CLAUDE_CODE_KEYCHAIN_SERVICE]
        written = json.loads((temp_home / ".claude" / ".credentials.json").read_text())
        assert written["mcpOAuth"] == mcp
        assert "designOauth" not in written

    def test_unreadable_item_is_read_once_without_retry(
        self, switcher, keychain, monkeypatch, temp_home
    ):
        monkeypatch.setenv("FAKE_SECURITY_FAIL_ADD", "1")
        reads = []

        def unreadable(svc, acct):
            reads.append(svc)
            raise macos_keychain.KeychainError("timed out")

        monkeypatch.setattr(macos_keychain, "get_password", unreadable)
        target = _login("fake-target")

        switcher._store._write_oauth_credentials(target)

        assert len(reads) == 1
        assert (temp_home / ".claude" / ".credentials.json").read_text() == target

    def test_no_keychain_read_when_already_known_unusable(
        self, switcher, keychain, monkeypatch
    ):
        keychain.put(
            CLAUDE_CODE_KEYCHAIN_SERVICE, _login("fake-live", designOauth=DESIGN)
        )
        switcher._store._pin_file_mode(residual_cleared=True)
        reads = []
        monkeypatch.setattr(
            macos_keychain,
            "get_password",
            lambda svc, acct: reads.append(svc),
        )

        switcher._store._write_oauth_credentials(_login("fake-target"))

        assert reads == []
