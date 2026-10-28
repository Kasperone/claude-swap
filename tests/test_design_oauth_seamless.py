"""Seamless switching: a Design login is never lost, with Claude Code running.

The other designOauth suites check cswap on its own. These run cswap next to
a simulated Claude Code (``tests/claude_code_sim.py``, the 2.1.306/2.1.308
store semantics: ``mutate`` under ``.storage-write.lock``, the Design refresh
under ``.design_oauth_refresh.lock`` with a CAS save that revokes its new
token when the store changed) and a token server whose refresh tokens are
single-use. A Design login counts as lost when the copy an account would use
next is spent or revoked. Fake credentials only.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_swap import macos_keychain, migrations, oauth, transfer
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.models import Platform
from claude_swap.session import keychain_service_name

from tests.claude_code_sim import (
    FakeClaudeCode,
    FakeOAuthServer,
    FileStore,
    InvalidGrant,
    KeychainStore,
)
from tests.test_design_oauth_per_account import (
    _backup,
    _bootstrap,
    _email,
    _identity_file,
    _platform,
    _roster,
    linux,  # noqa: F401
)


def _blob(text: str | None) -> dict:
    return json.loads(text) if text else {}


def _design(text: str | None) -> dict | None:
    return _blob(text).get("designOauth")


class SeamlessScenarios:
    """Subclasses provide ``sw`` and say where Claude Code keeps a store."""

    def live_store(self, home: Path):
        return FileStore(home / ".claude")

    def profile_store(self, session_dir: Path):
        return FileStore(session_dir)

    # -- harness -----------------------------------------------------------

    @pytest.fixture
    def world(self, sw, temp_home):
        """Accounts 1-3 with server-issued logins; account 1 is the default."""
        server = FakeOAuthServer()
        _roster(sw, temp_home, {
            n: json.dumps({"claudeAiOauth": server.issue(n, "login")})
            for n in ("1", "2", "3")
        }, active="1")
        claude = FakeClaudeCode(server, self.live_store(temp_home))

        def refresh(creds: str, **_kw) -> oauth.RefreshOutcome:
            blob = json.loads(creds)
            try:
                login = server.refresh(blob["claudeAiOauth"]["refreshToken"])
            except InvalidGrant:
                return oauth.RefreshOutcome(None, "invalid_grant")
            hook = getattr(sw, "_test_during_post", None)
            if hook is not None:
                hook()
            return oauth.RefreshOutcome(json.dumps({**blob, "claudeAiOauth": login}), None)

        def profile(token: str):
            owner = server.owner({"refreshToken": token.replace("-at-", "-rt-")})
            return {"uuid": f"u{owner}", "email": _email(owner), "organizationUuid": ""}

        usage_calls: list[str] = []

        def usage(num, email, creds, is_active, **_kw):
            usage_calls.append(num)
            # The first call per pass says 401, so the active path refreshes.
            if getattr(sw, "_test_force_401", False):
                sw._test_force_401 = False
                return oauth.UsageOutcome(None, "http-401")
            return oauth.UsageOutcome({"five_hour": {"utilization": 1}})

        with (
            patch("claude_swap.oauth.try_refresh_oauth_credentials", side_effect=refresh),
            patch("claude_swap.oauth.fetch_oauth_profile", side_effect=profile),
            patch("claude_swap.oauth.try_fetch_usage_for_account", side_effect=usage),
        ):
            yield server, claude

    def active_refresh(self, sw, num: str, during_post=None) -> None:
        """cswap's background usage passes for the default login: a normal
        one (it resyncs a rotation into the backup), then one the server
        answers 401, which makes cswap refresh the login itself."""
        assert sw._fetch_active_usage(
            num, _email(num), sw._read_credentials()
        ).error is None
        sw._test_force_401 = True
        sw._test_during_post = during_post
        try:
            record = sw._fetch_active_usage(num, _email(num), sw._read_credentials())
        finally:
            sw._test_during_post = None
        assert record.error is None and record.sentinel is None, record

    def switch_racing_a_design_refresh(self, sw, claude, target: str) -> str:
        """Switch while the default claude's Design refresh is mid-POST."""
        posting = threading.Event()
        outcome: list[str] = []
        worker = threading.Thread(target=lambda: outcome.append(
            claude.refresh_design(post_seconds=0.4, during_post=posting.set)
        ))
        worker.start()
        while not posting.wait(0.05):
            # Ended without a POST: no usable Design login was left to refresh.
            assert worker.is_alive(), outcome
        sw.switch_to(target, json_output=True)
        worker.join(30)
        return outcome[0]

    @staticmethod
    def live_session(session_dir: Path):
        """A claude process registered as running in the profile. Ends like
        claude does: the process exits and its record goes."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(600)"]
        )
        record_dir = session_dir / "sessions"
        record_dir.mkdir(parents=True, exist_ok=True)
        record = record_dir / f"{proc.pid}.json"
        record.write_text(json.dumps({"pid": proc.pid}))

        class Session:
            pid = proc.pid

            @staticmethod
            def end() -> None:
                proc.kill()
                proc.wait()
                record.unlink(missing_ok=True)

        return Session

    # -- regression tests ----------------------------------------------------

    def test_switch_waits_for_a_design_refresh_in_flight(self, sw, world):
        server, claude = world
        d1 = claude.design_login("1")

        assert self.switch_racing_a_design_refresh(sw, claude, "2") == "saved"

        # The refreshed generation was captured, not revoked by a CAS miss.
        assert server.revoked == []
        assert server.is_valid(_design(_backup(sw, "1")))
        assert _design(_backup(sw, "1")) != d1
        assert self.live_store_design(claude) is None  # account 2 has none

    def test_active_refresh_keeps_a_design_refresh_saved_during_its_post(
        self, sw, world
    ):
        server, claude = world
        claude.design_login("1")

        self.active_refresh(sw, "1", during_post=claude.refresh_design)

        live = self.live_store_design(claude)
        assert claude.events[-1] == "saved"
        assert server.is_valid(live), "the live Design login was reverted"
        assert _design(_backup(sw, "1")) == live
        assert server.is_valid(_blob(_backup(sw, "1"))["claudeAiOauth"])

    def test_wiped_login_still_captures_its_newer_design(self, sw, world):
        server, claude = world
        claude.design_login("1")
        sw.switch_to("2", json_output=True)
        sw.switch_to("1", json_output=True)
        claude.refresh_design()  # newer than the backup's copy
        server.revoke(claude.store.read()["claudeAiOauth"]["refreshToken"])
        server.revoked.clear()
        assert claude.refresh_login() == "wiped"
        live_design = self.live_store_design(claude)
        login_before = _blob(_backup(sw, "1"))["claudeAiOauth"]

        sw.switch_to("2", json_output=True)

        assert _design(_backup(sw, "1")) == live_design
        assert server.is_valid(live_design)
        # The wiped login itself never reaches the backup.
        assert _blob(_backup(sw, "1"))["claudeAiOauth"] == login_before

    def test_capture_keeps_a_newer_design_the_backup_got_from_its_session(
        self, sw, world
    ):
        server, claude = world
        claude.design_login("1")
        older = self.live_store_design(claude)
        # Account 1's own session refreshed the Design login and it was
        # adopted into the backup, while account 1 is also the default.
        newer = server.refresh(older["refreshToken"])
        backup = _blob(_backup(sw, "1"))
        sw._store._write_account_credentials(
            "1", _email("1"), json.dumps({**backup, "designOauth": newer})
        )

        sw.switch_to("2", json_output=True)

        assert _design(_backup(sw, "1")) == newer

    def test_rotation_resync_keeps_a_newer_design_in_the_backup(self, sw, world):
        server, claude = world
        claude.design_login("1")
        sw.switch_to("2", json_output=True)
        sw.switch_to("1", json_output=True)
        newer = server.refresh(self.live_store_design(claude)["refreshToken"])
        backup = _blob(_backup(sw, "1"))
        sw._store._write_account_credentials(
            "1", _email("1"), json.dumps({**backup, "designOauth": newer})
        )
        claude.refresh_login()  # the live login rotated, the backup is behind

        sw._resync_rotated_backup("1", _email("1"), "", sw._read_credentials())

        stored = _blob(_backup(sw, "1"))
        assert server.is_valid(stored["claudeAiOauth"])  # resynced
        assert stored["designOauth"] == newer

    def test_stash_adoption_keeps_the_stores_design(self, sw, world):
        server, claude = world
        old = _blob(_backup(sw, "2"))
        successor = server.refresh(old["claudeAiOauth"]["refreshToken"])
        design = server.issue("2", "design")
        # A gate's persist failed after its POST: the successor waits in the
        # stash; meanwhile the backup got its Design login (a session).
        sw._store._write_unclaimed_credential(
            json.dumps({**old, "claudeAiOauth": successor}),
            {"reason": "consume-gate-persist-failed", "configSlot": "2",
             "consumedFp": oauth.credential_fingerprint(json.dumps(old)),
             "fingerprint": "x"},
        )
        sw._store._write_account_credentials(
            "2", _email("2"), json.dumps({**old, "designOauth": design})
        )

        result = sw.consume_backup_grant("2", _email("2"), _backup(sw, "2"))

        stored = _blob(_backup(sw, "2"))
        assert stored["claudeAiOauth"] == successor
        assert stored["designOauth"] == design
        assert _design(result.credentials) == design

    def test_running_session_cannot_spend_the_owners_design_login(self, sw, world):
        """The one-time migration finds account 2's running session holding
        account 1's Design login (seeded there from another slot). It is
        removed under that session's own locks, so the session's next Design
        refresh cannot spend the copy account 1 uses — and no refreshed
        generation of it can pass for account 2's own later."""
        server, claude = world
        d1 = claude.design_login("1")  # live: account 1's
        session_dir = _bootstrap(sw, "2")
        _identity_file(session_dir, "2")
        session = FakeClaudeCode(server, self.profile_store(session_dir))
        session.mutate(lambda blob: {**blob, "designOauth": d1})  # the old seed
        running = self.live_session(session_dir)
        try:
            assert migrations.migrate_design_oauth_per_account(sw) is True
            assert session.refresh_design() == "needs_design_login"
            assert session.store.read()["claudeAiOauth"]  # its login stays
        finally:
            running.end()

        assert server.is_valid(d1)
        assert claude.refresh_design() == "saved"
        assert server.revoked == []
        sw._adopt_session_credential("2", _email("2"), "")
        assert _design(_backup(sw, "2")) is None

    def test_import_keeps_the_slots_own_design_login(self, sw, world, tmp_path):
        """A default export carries the login only; importing it over the
        slot (``--force``, or the dead-token auto-heal) renews the login and
        keeps the account's own Design login."""
        server, claude = world
        export = tmp_path / "backup.cswap"
        transfer.export_accounts(sw, str(export))  # before any Design login
        claude.design_login("1")
        sw.switch_to("2", json_output=True)  # account 1's is in its backup now
        design = _design(_backup(sw, "1"))

        transfer.import_accounts(sw, str(export), force=True)
        assert _design(_backup(sw, "1")) == design
        assert server.is_valid(design)

        # The plain import that replaces a dead-token slot, same rule.
        with patch.object(sw, "_slot_token_dead", lambda num, email: num == "1"):
            transfer.import_accounts(sw, str(export))
        assert _design(_backup(sw, "1")) == design

        sw.switch_to("1", json_output=True)
        assert self.live_store_design(claude) == design

    def test_import_takes_a_later_design_login_from_a_full_export(
        self, sw, world, tmp_path
    ):
        server, claude = world
        claude.design_login("1")
        sw.switch_to("2", json_output=True)
        stored = _blob(_backup(sw, "1"))
        later = server.refresh(stored["designOauth"]["refreshToken"])
        sw._store._write_account_credentials(
            "1", _email("1"), json.dumps({**stored, "designOauth": later})
        )
        export = tmp_path / "full.cswap"
        transfer.export_accounts(sw, str(export), full=True)
        sw._store._write_account_credentials("1", _email("1"), json.dumps(stored))

        transfer.import_accounts(sw, str(export), force=True)
        assert _design(_backup(sw, "1")) == later

    # -- the end-to-end scenario ---------------------------------------------

    def test_a_b_a_b_with_refreshes_and_a_running_session(self, sw, world):
        """A -> B -> A -> B on the default login while:
        - the default claude refreshes its login and Design login between
          switches, and once during each switch;
        - cswap refreshes the default login in the background (a Design
          refresh landing in its POST) and the other account's backup;
        - account 3 runs in a ``cswap run`` session that made its own
          ``/design-login`` and keeps refreshing.
        Each account keeps a valid Design login of its own throughout, and
        only the one initial ``/design-login`` per account is ever needed."""
        server, claude = world
        claude.design_login("1")  # once, as account 1
        sw.switch_to("2", json_output=True)
        claude.design_login("2")  # once, as account 2

        session_dir = _bootstrap(sw, "3")
        _identity_file(session_dir, "3")
        session = FakeClaudeCode(server, self.profile_store(session_dir))
        session.design_login("3")  # once, inside the session
        running = self.live_session(session_dir)
        try:
            active = "2"
            for target in ("1", "2", "1", "2"):
                other = "1" if active == "2" else "2"
                claude.refresh_login()
                assert claude.refresh_design() == "saved"
                session.refresh_login()
                assert session.refresh_design() == "saved"
                self.active_refresh(sw, active, during_post=claude.refresh_design)
                assert claude.events[-1] == "saved"
                assert sw.consume_backup_grant(
                    other, _email(other), _backup(sw, other)
                ).error is None

                assert self.switch_racing_a_design_refresh(sw, claude, target) == (
                    "saved"
                )
                active = target
                self.assert_seamless(sw, server, claude, active, session_dir)
        finally:
            running.end()

        # The session exits; the next usage/switch pass adopts its state.
        sw._adopt_session_credential("3", _email("3"), "")
        assert _design(_backup(sw, "3")) == server.current("3")
        sw.switch_to("3", json_output=True)
        assert self.live_store_design(claude) == server.current("3")
        sw.switch_to("1", json_output=True)
        assert self.live_store_design(claude) == server.current("1")
        self.assert_seamless(sw, server, claude, "1", None)

    def assert_seamless(self, sw, server, claude, active, session_dir) -> None:
        # No Design login was ever revoked by a CAS miss, and none is
        # missing or spent where its account will use it next.
        assert server.revoked == []
        live = claude.store.read()
        assert live["designOauth"] == server.current(active)
        assert server.is_valid(live["claudeAiOauth"])
        for num in ("1", "2"):
            stored = _blob(_backup(sw, num))
            assert server.owner(stored.get("designOauth")) == num
            if num != active:  # the next switch to it activates this copy
                assert stored["designOauth"] == server.current(num)
                assert server.is_valid(stored["claudeAiOauth"])
        if session_dir is not None:
            profile = self.profile_store(session_dir).read()
            assert profile["designOauth"] == server.current("3")
            assert server.owner(_design(_backup(sw, "3"))) in (None, "3")

    def live_store_design(self, claude) -> dict | None:
        return claude.store.read().get("designOauth")


class TestSeamlessLinux(SeamlessScenarios):
    @pytest.fixture
    def sw(self, linux):  # noqa: F811
        return linux


class TestSeamlessWindows(SeamlessScenarios):
    @pytest.fixture
    def sw(self, temp_home, monkeypatch):
        return _platform(monkeypatch, Platform.WINDOWS)


@pytest.mark.no_keychain_fake
@pytest.mark.skipif(sys.platform == "win32", reason="fake security is a POSIX script")
class TestSeamlessMacOS(SeamlessScenarios):
    """Claude Code keeps the default login and each session in Keychain items."""

    @pytest.fixture
    def sw(self, temp_home, keychain, monkeypatch):  # noqa: F811
        return _platform(monkeypatch, Platform.MACOS)

    def live_store(self, home):
        return KeychainStore(home / ".claude", CLAUDE_CODE_KEYCHAIN_SERVICE)

    def profile_store(self, session_dir):
        return KeychainStore(session_dir, keychain_service_name(session_dir))

    def test_a_failed_read_while_merging_keeps_the_live_write_in_the_keychain(
        self, sw, world, temp_home, monkeypatch
    ):
        """The Design merge before the post-POST live write reads the item.
        One transient failure there must not flip cswap to file mode for the
        write itself: the refreshed login would land in a plaintext file the
        (stale) item shadows, and Claude Code would keep the spent login."""
        server, claude = world
        claude.design_login("1")
        real = macos_keychain.get_password
        armed: list[int] = []

        def flaky(service, account):
            if armed and service == CLAUDE_CODE_KEYCHAIN_SERVICE:
                armed.clear()
                raise macos_keychain.KeychainError("fake: one transient failure")
            return real(service, account)

        monkeypatch.setattr(macos_keychain, "get_password", flaky)
        self.active_refresh(sw, "1", during_post=lambda: armed.append(1))

        assert not armed  # the failure did happen
        item = json.loads(real(
            CLAUDE_CODE_KEYCHAIN_SERVICE, macos_keychain.keychain_account_name()
        ))
        assert server.is_valid(item["claudeAiOauth"])
        assert item["designOauth"] == server.current("1")
        assert not (temp_home / ".claude" / ".credentials.json").exists()
