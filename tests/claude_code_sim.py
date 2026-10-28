"""A stand-in for the parts of Claude Code that touch its credential store.

Mirrors Claude Code 2.1.306 and 2.1.308 (strings of the published binaries):

- Every store write is ``mutate``: under ``<storage dir>/.storage-write.lock``
  (proper-lockfile, stale 15 s, 10 retries), re-read the store, apply, write
  back. Sibling keys are never written from memory.
- The Design refresh holds ``<storage dir>/.design_oauth_refresh.lock``
  (stale 60 s, 5 tries) across re-read -> POST -> save. The save is a CAS on
  the refresh token it POSTed: when the store's ``designOauth`` changed
  meanwhile, it revokes the token it was just issued and reports a race.
- ``/design-login`` saves its new login with a plain ``mutate``.
- The login refresh saves ``claudeAiOauth`` with ``mutate``, keeping every
  sibling key; an ``invalid_grant`` empties the login's tokens in place.

The "server" is in memory: refresh tokens are single-use (rotation), and a
revoked or spent token never refreshes again. Fake tokens only.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from claude_swap import macos_keychain

DESIGN_SCOPES = ["user:design:read", "user:design:write"]
DESIGN_CLIENT = "00000000-fake-design-client"
# Claude Code's lock directories, all in the store's directory.
DESIGN_LOCK = ".design_oauth_refresh.lock"
STORE_WRITE_LOCK = ".storage-write.lock"


class InvalidGrant(Exception):
    """The token endpoint refused a spent, revoked or unknown refresh token."""


@dataclass
class FakeOAuthServer:
    """Token endpoint with single-use refresh tokens, for logins and Design logins."""

    valid: dict[str, tuple[str, str]] = field(default_factory=dict)  # rt -> (owner, kind)
    revoked: list[str] = field(default_factory=list)
    spent: list[str] = field(default_factory=list)
    latest: dict[tuple[str, str], dict] = field(default_factory=dict)
    _n: int = 0

    def issue(self, owner: str, kind: str = "design") -> dict:
        """A new login generation for ``owner`` (``kind`` "design" or "login")."""
        self._n += 1
        token = {
            "accessToken": f"fake-{kind}-{owner}-at-{self._n}",
            "refreshToken": f"fake-{kind}-{owner}-rt-{self._n}",
            # Later generations expire later; far in the future, so cswap never
            # treats one as expired on its own.
            "expiresAt": int(time.time() * 1000) + 3_600_000 + self._n,
        }
        if kind == "design":
            token["scopes"] = list(DESIGN_SCOPES)
            token["clientId"] = DESIGN_CLIENT
        else:
            token["scopes"] = ["user:inference", "user:profile"]
        self.valid[token["refreshToken"]] = (owner, kind)
        self.latest[(owner, kind)] = token
        return token

    def refresh(self, refresh_token: str) -> dict:
        if refresh_token not in self.valid:
            raise InvalidGrant(refresh_token)
        owner, kind = self.valid.pop(refresh_token)  # single use
        self.spent.append(refresh_token)
        return self.issue(owner, kind)

    def revoke(self, refresh_token: str) -> None:
        self.valid.pop(refresh_token, None)
        self.revoked.append(refresh_token)

    def is_valid(self, token: dict | None) -> bool:
        return bool(token) and token.get("refreshToken") in self.valid

    def owner(self, token: dict | None) -> str | None:
        """The account a token was issued to (spent or revoked ones too)."""
        if not token:
            return None
        rt = token.get("refreshToken", "")
        parts = rt.split("-")
        return parts[2] if len(parts) > 3 and parts[0] == "fake" else None

    def current(self, owner: str, kind: str = "design") -> dict | None:
        """The live generation of ``owner``'s login, if it is still valid."""
        token = self.latest.get((owner, kind))
        return token if self.is_valid(token) else None


class FileStore:
    """Claude Code's plaintext store: ``<dir>/.credentials.json`` (Linux, Windows)."""

    def __init__(self, directory: Path):
        self.dir = Path(directory)

    @property
    def path(self) -> Path:
        return self.dir / ".credentials.json"

    def read(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}

    def write(self, data: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)


class KeychainStore:
    """Claude Code's macOS store: one Keychain item, locks in the config dir.

    With the plaintext fallback: while the item is absent the profile's
    ``.credentials.json`` (a cswap seed) is read, and the first write moves
    the whole blob into the item.
    """

    def __init__(self, directory: Path, service: str):
        self.dir = Path(directory)
        self.service = service

    def read(self) -> dict:
        value = macos_keychain.get_password(
            self.service, macos_keychain.keychain_account_name()
        )
        if value is None:
            return FileStore(self.dir).read()
        return json.loads(value) if value else {}

    def write(self, data: dict) -> None:
        macos_keychain.set_password(
            self.service, macos_keychain.keychain_account_name(), json.dumps(data)
        )


@contextmanager
def _lock(directory: Path, name: str, tries: int, delay: float):
    """proper-lockfile as Claude Code calls it: mkdir is the mutex."""
    lock = directory / name
    directory.mkdir(parents=True, exist_ok=True)
    for attempt in range(tries):
        try:
            os.mkdir(lock)
            break
        except FileExistsError:
            if attempt == tries - 1:
                raise TimeoutError(f"{name} is held")
            time.sleep(delay)
    try:
        yield
    finally:
        os.rmdir(lock)


class FakeClaudeCode:
    """One running Claude Code, bound to one store (default login or session)."""

    def __init__(self, server: FakeOAuthServer, store: FileStore | KeychainStore):
        self.server = server
        self.store = store
        self.events: list[str] = []

    def mutate(self, fn) -> None:
        # 10 retries, 100 ms -> 1 s backoff in Claude Code; a flat 0.1 s here.
        with _lock(self.store.dir, STORE_WRITE_LOCK, tries=80, delay=0.1):
            self.store.write(fn(self.store.read()))

    def design_login(self, owner: str) -> dict:
        """``/design-login``: a new Design login, saved without any CAS."""
        token = self.server.issue(owner, "design")
        self.mutate(lambda blob: {**blob, "designOauth": token})
        return token

    def refresh_design(self, post_seconds: float = 0.0, during_post=None) -> str:
        """The Design token refresh. Returns "saved", "raced" or "needs_design_login"."""
        with _lock(self.store.dir, DESIGN_LOCK, tries=40, delay=0.25):
            current = self.store.read().get("designOauth")
            if not current or not current.get("refreshToken"):
                return self._log("needs_design_login")
            posted = current["refreshToken"]
            try:
                fresh = self.server.refresh(posted)
            except InvalidGrant:
                self.mutate(lambda blob: _without_design(blob, posted))
                return self._log("needs_design_login")
            if during_post is not None:
                during_post()
            time.sleep(post_seconds)
            raced = []

            def save(blob: dict) -> dict:
                if (blob.get("designOauth") or {}).get("refreshToken") != posted:
                    raced.append(True)
                    return blob
                return {**blob, "designOauth": fresh}

            self.mutate(save)
            if raced:
                self.server.revoke(fresh["refreshToken"])
                return self._log("raced")
            return self._log("saved")

    def refresh_login(self) -> str:
        """The login refresh, saved with ``mutate`` (siblings kept)."""
        login = self.store.read().get("claudeAiOauth") or {}
        posted = login.get("refreshToken")
        try:
            fresh = self.server.refresh(posted or "")
        except InvalidGrant:
            # Claude Code's invalid_grant reaction: empty the tokens in place.
            def wipe(blob: dict) -> dict:
                old = blob.get("claudeAiOauth") or {}
                if old.get("refreshToken") != posted:
                    return blob
                return {**blob, "claudeAiOauth": {
                    **old, "accessToken": "", "refreshToken": "", "expiresAt": 0,
                }}

            self.mutate(wipe)
            return self._log("wiped")

        def save(blob: dict) -> dict:
            return {**blob, "claudeAiOauth": {**(blob.get("claudeAiOauth") or {}),
                                              **fresh}}

        self.mutate(save)
        return self._log("saved")

    def _log(self, outcome: str) -> str:
        self.events.append(outcome)
        return outcome


def _without_design(blob: dict, refresh_token: str) -> dict:
    design = blob.get("designOauth") or {}
    if design.get("refreshToken") != refresh_token:
        return blob
    return {k: v for k, v in blob.items() if k != "designOauth"}
