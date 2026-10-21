"""``designOauth`` against the REAL macOS Keychain — GitHub Actions macOS only.

Re-runs the scenarios of ``test_design_oauth_macos`` with the real ``security``
CLI and the real ``macos_keychain`` wrapper, against a throwaway keychain the
workflow creates (``CSWAP_CI_KEYCHAIN``) with a password generated in CI. Fake
credentials only. Gated like the other Layer-2 tests (``GITHUB_ACTIONS`` and
darwin) plus that variable, so a developer running pytest locally never touches
a keychain.
"""

from __future__ import annotations

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
    FakeKeychain,
    TestAddRemovePurgeOnKeychain,
    TestSwapOnKeychain,
    switcher,
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
MANAGED_SERVICE = "Claude Code"


class RealKeychain(FakeKeychain):
    def __init__(self):
        pass

    def put(self, service: str, value: str) -> None:
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
    for service in (CLAUDE_CODE_KEYCHAIN_SERVICE, MANAGED_SERVICE):
        macos_keychain.delete_password(service, ACCOUNT)


def test_real_security_roundtrip_with_json_and_spaces(keychain):
    # Pins that the real stdin/hex path preserves a multi-field JSON blob.
    value = '{"designOauth": {"accessToken": "fake at"}, "n": 1}'
    keychain.put(CLAUDE_CODE_KEYCHAIN_SERVICE, value)
    assert keychain.get(CLAUDE_CODE_KEYCHAIN_SERVICE) == value
