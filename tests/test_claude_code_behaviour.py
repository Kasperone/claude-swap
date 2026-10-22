"""Behaviour of the real Claude Code binary, next to cswap — fake credentials only.

The rest of the suite mirrors Claude Code from the strings of its binaries.
These tests run it instead (Linux builds), wherever that needs no secret and
no network:

- ``claude design-login --json --status`` (hidden; the VS Code extension's
  probe) reports whether the store Claude Code resolves holds a Design login,
  without refreshing it. It shows which store each environment points
  Claude Code at, and what a cswap switch or ``cswap run`` profile leaves
  there for it.
- ``claude auth logout`` shows that the Design login goes with the login.
- Its store writes wait for ``.storage-write.lock``, which cswap now holds
  while it rewrites the store (``claude_store_locks``).

Opt-in: ``CSWAP_CC_BINARY`` names the binary (CI downloads the pinned and the
latest version for the binary check). Every run is inside ``unshare -rn``, a
network namespace with no route out, so no request (a logout's revoke, an
update check) can leave the machine; without that the tests fail rather than
run unisolated. The environment is scrubbed and ``HOME`` is the test's own.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from claude_swap.claude_locks import claude_store_write_lock
from claude_swap.paths import get_credentials_path
from claude_swap.session import SessionManager, session_dir_for

from tests.test_design_oauth_per_account import (  # noqa: F401
    _email,
    _identity_file,
    _roster,
    linux,
)

BINARY = os.environ.get("CSWAP_CC_BINARY", "")

pytestmark = pytest.mark.skipif(
    not BINARY or sys.platform != "linux",
    reason="runs the real Claude Code binary: set CSWAP_CC_BINARY (Linux)",
)

DESIGN = {
    "accessToken": "fake-design-at", "refreshToken": "fake-design-rt",
    "expiresAt": 4_102_444_800_000,  # 2100: never refreshed here
    "scopes": ["user:design:read", "user:design:write"],
    "clientId": "00000000-0000-0000-0000-000000000000",
}


def _login(num: str, design: dict | None = None) -> str:
    # Shaped like a real login: without a subscriptionType Claude Code would
    # try to look it up (and wait out a timeout with no network).
    blob: dict = {"claudeAiOauth": {
        "accessToken": f"fake-login-{num}-at", "refreshToken": f"fake-login-{num}-rt",
        "expiresAt": 4_102_444_800_000, "scopes": ["user:inference", "user:profile"],
        "subscriptionType": "max",
    }}
    if design is not None:
        blob["designOauth"] = design
    return json.dumps(blob)


@pytest.fixture(scope="module")
def isolated() -> None:
    """``unshare -rn`` must work: the binary never runs with a network."""
    probe = subprocess.run(
        ["unshare", "-rn", "true"], capture_output=True, timeout=30,
    ) if shutil.which("unshare") else None
    if probe is None or probe.returncode != 0:
        pytest.fail(
            "CSWAP_CC_BINARY is set but `unshare -rn` is unavailable, so Claude "
            "Code cannot be run without network access; refusing to run it"
        )


def claude(home: Path, *args: str, env: dict | None = None,
           timeout: float = 60) -> subprocess.CompletedProcess:
    clean = {
        "HOME": str(home), "PATH": "/usr/bin:/bin", "TERM": "dumb",
        "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        **(env or {}),
    }
    # The namespace's own loopback up (nothing listens there): a lookup Claude
    # Code attempts then fails at once instead of waiting out a DNS timeout.
    up = 'ip link set lo up 2>/dev/null; exec "$0" "$@"'
    return subprocess.run(
        ["unshare", "-rn", "sh", "-c", up, BINARY, *args], env=clean,
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=timeout, cwd=home,
    )


def signed_in(home: Path, env: dict | None = None) -> bool:
    """Claude Code's own answer: does its store hold a Design login?"""
    result = claude(home, "design-login", "--json", "--status", env=env)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])["signed_in"]


class TestStoreResolution:
    """Which store Claude Code reads designOauth from, for each environment
    cswap resolves (``paths.get_credentials_path``)."""

    def test_follows_the_store_cswap_resolves(self, temp_home, isolated, monkeypatch):
        profile = temp_home / "profile"
        secure = temp_home / "secure"
        for d in (profile, secure):
            d.mkdir()
        cases = [
            {},
            {"CLAUDE_CONFIG_DIR": str(profile)},
            {"CLAUDE_SECURESTORAGE_CONFIG_DIR": str(secure)},
            {"CLAUDE_CONFIG_DIR": str(profile), "CLAUDE_SECURESTORAGE_CONFIG_DIR": ""},
        ]
        for env in cases:
            for name in ("CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR"):
                monkeypatch.delenv(name, raising=False)
            for name, value in env.items():
                monkeypatch.setenv(name, value)
            store = get_credentials_path()
            for path in (temp_home / ".claude" / ".credentials.json",
                         profile / ".credentials.json", secure / ".credentials.json"):
                path.unlink(missing_ok=True)

            store.parent.mkdir(parents=True, exist_ok=True)
            store.write_text(_login("1", DESIGN))
            assert signed_in(temp_home, env), env
            store.write_text(_login("1"))
            assert not signed_in(temp_home, env), env


class TestPerAccountWithCswap:
    """A cswap switch, and a ``cswap run`` profile, give Claude Code exactly
    the account's own Design login."""

    def test_switch_and_session_profile(self, linux, temp_home, isolated):  # noqa: F811
        sw = linux
        _roster(sw, temp_home, {"1": _login("1", DESIGN), "2": _login("2"),
                                "3": _login("3", {**DESIGN, "accessToken": "fake-3"})},
                active="1")
        assert signed_in(temp_home)

        sw.switch_to("2", json_output=True)
        assert not signed_in(temp_home)  # account 2 has none of its own

        profile = session_dir_for(sw.backup_dir, "3", _email("3"))
        SessionManager(sw)._bootstrap(profile, "3", _email("3"), "")
        _identity_file(profile, "3")
        # Inside `cswap run 3`: the profile's own Design login, while the
        # default (account 2) still has none.
        assert signed_in(temp_home, {"CLAUDE_CONFIG_DIR": str(profile)})
        assert not signed_in(temp_home)

        sw.switch_to("1", json_output=True)
        assert signed_in(temp_home)


class TestOwnershipAndLocks:
    def test_logout_takes_the_design_login_with_the_login(self, temp_home, isolated):
        store = temp_home / ".claude" / ".credentials.json"
        store.write_text(_login("1", DESIGN))

        result = claude(temp_home, "auth", "logout")

        assert result.returncode == 0, result.stderr
        assert not store.exists() or "designOauth" not in json.loads(store.read_text())
        assert not signed_in(temp_home)

    def test_store_writes_wait_for_the_lock_cswap_holds(self, temp_home, isolated):
        """``claude_store_write_lock`` names the lock Claude Code's own store
        writes take: a logout (a store write) waits until cswap lets go."""
        store = temp_home / ".claude" / ".credentials.json"
        store.write_text(_login("1", DESIGN))
        held = threading.Event()
        written_while_held: list[bool] = []

        def hold() -> None:
            # Hold for 3 s, watching the store: a logout removes it, so any
            # change while the lock is held is a write that did not wait.
            with claude_store_write_lock(temp_home / ".claude"):
                held.set()
                before = store.read_text()
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    if not store.exists() or store.read_text() != before:
                        written_while_held.append(True)
                        break
                    time.sleep(0.05)

        holder = threading.Thread(target=hold)
        holder.start()
        assert held.wait(10)
        try:
            result = claude(temp_home, "auth", "logout")
        finally:
            holder.join(30)

        assert result.returncode == 0, result.stderr
        assert not written_while_held, "Claude Code wrote while cswap held the lock"
        assert not store.exists() or "designOauth" not in json.loads(store.read_text())
