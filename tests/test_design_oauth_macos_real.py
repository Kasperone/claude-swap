"""``designOauth`` against the REAL macOS Keychain — GitHub Actions macOS only.

Re-runs the scenarios of ``test_design_oauth_macos`` with the real ``security``
CLI and the real ``macos_keychain`` wrapper, against a throwaway keychain the
workflow creates (``CSWAP_CI_KEYCHAIN``) with a password generated in CI. Fake
credentials only. Gated like the other Layer-2 tests (``GITHUB_ACTIONS`` and
darwin) plus that variable, so a developer running pytest locally never touches
a keychain.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from claude_swap import macos_keychain
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE

# The classes under test are shared with the fake-CLI module; only the
# ``keychain`` fixture below differs.
from tests.test_design_oauth_macos import (  # noqa: F401
    ACCOUNT,
    DESIGN,
    FakeKeychain,
    TestAddRemovePurgeOnKeychain,
    TestSwapOnKeychain,
    _login,
    switcher,
)
from tests.test_design_oauth_per_account import (  # noqa: F401
    TestMigrationMacOS,
)
from tests.test_design_oauth_profiles import (  # noqa: F401
    TestEnvVarNamingTheDefaultProfile,
    TestEnvVarProfileKeychain,
    TestSessionProfileKeychain,
    profile,
)

pytestmark = [
    pytest.mark.no_keychain_fake,
    pytest.mark.skipif(
        os.environ.get("GITHUB_ACTIONS") != "true"
        or sys.platform != "darwin"
        or not os.environ.get("CSWAP_CI_KEYCHAIN"),
        reason="Uses a throwaway keychain — GitHub Actions macOS only",
    ),
]

# Captured at import, before any fixture isolates $HOME.
REAL_HOME = os.environ.get("HOME", "")
REAL_SECURITY = Path(__file__).parent / "fixtures" / "real_security"
FAIL_ADD_SECURITY = Path(__file__).parent / "fixtures" / "real_security_fail_add"
MANAGED_SERVICE = "Claude Code"


class RealKeychain(FakeKeychain):
    def __init__(self):
        self.services: set[str] = set()

    def put(self, service: str, value: str) -> None:
        self.services.add(service)
        macos_keychain.set_password(service, ACCOUNT, value)

    def get(self, service: str) -> str | None:
        return macos_keychain.get_password(service, ACCOUNT)


@pytest.fixture
def keychain(monkeypatch) -> RealKeychain:
    monkeypatch.setenv("CSWAP_REAL_HOME", REAL_HOME)
    default = subprocess.run(
        [str(REAL_SECURITY), "default-keychain"], capture_output=True, text=True
    ).stdout.strip().strip('"')
    assert Path(default).resolve() == Path(os.environ["CSWAP_CI_KEYCHAIN"]).resolve(), (
        "default keychain is not the CI throwaway one"
    )
    monkeypatch.setenv("USER", ACCOUNT)
    monkeypatch.setattr(macos_keychain, "_SECURITY", str(REAL_SECURITY))
    kc = RealKeychain()
    yield kc
    # Cleanup of the seeded items. Items cswap created under per-test hashed
    # names stay until the job deletes the whole throwaway keychain.
    monkeypatch.setattr(macos_keychain, "_SECURITY", str(REAL_SECURITY))
    for service in {CLAUDE_CODE_KEYCHAIN_SERVICE, MANAGED_SERVICE} | kc.services:
        macos_keychain.delete_password(service, ACCOUNT)


def test_real_security_roundtrip_with_json_and_spaces(keychain):
    # Pins that the real stdin/hex path preserves a multi-field JSON blob.
    value = '{"designOauth": {"accessToken": "fake at"}, "n": 1}'
    keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, value)
    assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == value


class TestRealKeychainWriteFailure:
    """cswap's file fallback against the real keychain.

    Reads and deletes go to the real throwaway keychain; the write is refused
    either at the CLI boundary (guaranteed) or by a genuinely read-only
    keychain file (best effort; skipped where macOS still lets the write
    through).
    """

    ITEM = _login(
        "fake-live",
        designOauth=DESIGN,
        mcpOAuth={"server": {"refreshToken": "fake-mcp"}},
    )

    def test_refused_write_moves_shared_fields_but_not_design_into_file(
        self, switcher, keychain, temp_home, monkeypatch
    ):
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, self.ITEM)
        monkeypatch.setattr(macos_keychain, "_SECURITY", str(FAIL_ADD_SECURITY))

        switcher._write_credentials(_login("fake-target"))

        written = json.loads((temp_home / ".claude" / ".credentials.json").read_text())
        assert written["claudeAiOauth"] == {"accessToken": "fake-target"}
        assert "designOauth" not in written  # the outgoing account's
        assert written["mcpOAuth"] == {"server": {"refreshToken": "fake-mcp"}}
        # The stale item was really deleted, so it cannot shadow the file.
        monkeypatch.setattr(macos_keychain, "_SECURITY", str(REAL_SECURITY))
        assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) is None

    def test_locked_keychain_falls_back_to_file_with_design_oauth(
        self, switcher, keychain, temp_home
    ):
        # A genuinely locked keychain (a read-only keychain *file* did not block
        # writes on the CI runner, measured). Reads fail too, so the item cannot
        # be consulted: the composed credential, which carries the target
        # account's own designOauth, must reach the file without raising.
        path = os.environ["CSWAP_CI_KEYCHAIN"]
        keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, self.ITEM)
        real = [str(REAL_SECURITY)]
        subprocess.run(real + ["lock-keychain", path], check=True)
        try:
            try:
                macos_keychain.set_password("claude-swap-probe", ACCOUNT, "x")
            except macos_keychain.KEYCHAIN_ERRORS:
                pass
            else:
                pytest.skip("the locked keychain still accepted a write here")

            switcher._write_credentials(_login("fake-target", designOauth=DESIGN))

            written = json.loads(
                (temp_home / ".claude" / ".credentials.json").read_text()
            )
            assert written["designOauth"] == DESIGN
            assert written["claudeAiOauth"] == {"accessToken": "fake-target"}
        finally:
            subprocess.run(
                real + ["unlock-keychain", "-p", os.environ["CSWAP_CI_KEYCHAIN_PW"], path],
                check=False,
            )
