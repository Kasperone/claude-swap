"""One-time, run-once data migrations for claude-swap.

A small, boring home for compatibility migrations so they don't pollute the
core switch/read/write flow in :mod:`claude_swap.switcher`. Each migration:

- is **idempotent** and **self-guarded** (safe to run twice, safe even if the
  state file is missing or corrupt),
- returns ``True`` when it *completed* (runner records it as applied),
- returns ``False`` when it was *skipped / not applicable* (runner records
  nothing, so a later-restored backup can still trigger it),
- raises :class:`~claude_swap.exceptions.MigrationIncomplete` (or any other
  exception) when it *partially failed* — the runner logs it and leaves it
  unmarked so the next run retries.

Applied migrations are tracked in ``<backup_dir>/.migrations.json``:

    {"version": 1, "applied": {"windows_keyring_to_files": "<iso-timestamp>"}}

Run once at switcher construction (see ``ClaudeAccountSwitcher.__init__``);
after the state file records a migration it short-circuits with a single tiny
file read and never touches the source backend again.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from claude_swap import macos_keychain
from claude_swap.exceptions import MigrationIncomplete
from claude_swap.fsutil import atomic_write_text
from claude_swap.models import Platform, get_timestamp
from claude_swap.switcher import KEYRING_SERVICE, SECURITY_SERVICE

if TYPE_CHECKING:
    from claude_swap.switcher import ClaudeAccountSwitcher

STATE_FILENAME = ".migrations.json"
STATE_VERSION = 1


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------


def _state_path(switcher: "ClaudeAccountSwitcher") -> Path:
    return switcher.backup_dir / STATE_FILENAME


def _load_applied(switcher: "ClaudeAccountSwitcher") -> dict:
    """Return the ``{migration_id: timestamp}`` map; {} if missing or corrupt.

    A missing or unparseable state file is treated as "nothing applied" so a
    corrupt file can never permanently block a migration.
    """
    path = _state_path(switcher)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return {}
    applied = data.get("applied") if isinstance(data, dict) else None
    return applied if isinstance(applied, dict) else {}


def _mark_applied(switcher: "ClaudeAccountSwitcher", migration_id: str) -> None:
    """Record ``migration_id`` as applied, written atomically.

    Preserves any previously-recorded migrations. Published through the shared
    ``fsutil.atomic_write_text`` (0600 temp beside the target, rename), like
    every other local state file; this one holds no secrets, the mode simply
    matches.
    """
    path = _state_path(switcher)
    applied = _load_applied(switcher)
    applied[migration_id] = get_timestamp()
    content = json.dumps({"version": STATE_VERSION, "applied": applied}, indent=2)
    atomic_write_text(path, content)


# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------


def _delete_keyring_quietly(
    keyring, switcher, username: str, context: str = "windows_keyring_to_files"
) -> None:
    """Best-effort delete of a keyring entry; never raises.

    Used for cleanup *after* data has been safely relocated to a file, so a
    failure here is cosmetic (the entry is no longer read, and ``purge`` mops
    up any leftovers).

    Note: ``PasswordDeleteError`` is deliberately silent, but it covers more
    than "entry doesn't exist" — keyring's macOS backend also raises it when
    the user *denies* the delete in a Keychain prompt. The macOS migration
    therefore verifies removal separately (see ``item_exists``).
    """
    try:
        keyring.delete_password(KEYRING_SERVICE, username)
    except keyring.errors.PasswordDeleteError:
        pass  # Entry doesn't exist — fine.
    except Exception as e:  # noqa: BLE001 - best effort
        switcher._logger.warning(
            f"{context}: best-effort delete of {username} failed: {e}"
        )


def migrate_windows_keyring_to_files(switcher: "ClaudeAccountSwitcher") -> bool:
    """Copy Windows backup credentials from Credential Manager to files.

    Windows now stores per-account backup credentials as base64 files (like
    Linux/WSL) because the Credential Manager rejects entries over ~2,500 bytes
    (#45). This relocates any pre-existing keyring entries so upgrading users
    don't lose access, then cleans up the old entries best-effort.

    Returns ``True`` (completed) on a Windows host once every account's creds
    have been read successfully (including the benign "no legacy entries"
    case); ``False`` (skip) on non-Windows or when there's no readable
    sequence yet. Raises :class:`MigrationIncomplete` if the keyring backend is
    inaccessible or any account could not be safely relocated, so the runner
    retries on the next launch rather than marking it done.
    """
    if switcher.platform != Platform.WINDOWS:
        return False
    if not switcher.sequence_file.exists():
        return False  # No managed accounts yet — let a later restore migrate.

    data = switcher._get_sequence_data()
    if data is None:
        # sequence.json exists but is corrupt/unparseable. Never mark applied:
        # a user who repairs or restores it must still get the migration.
        return False

    accounts = data.get("accounts", {})
    if not accounts:
        return True  # Readable sequence, nothing to migrate → done.

    try:
        import keyring  # noqa: PLC0415 - only needed on the migration path
        # Touch the attribute we rely on so a broken backend surfaces here.
        keyring.errors.PasswordDeleteError  # noqa: B018
    except Exception as e:  # noqa: BLE001
        # An inaccessible backend is NOT "nothing to migrate" — that would
        # permanently skip real entries. Force a retry next run.
        raise MigrationIncomplete(
            f"keyring backend unavailable, deferring Windows migration: {e}"
        ) from e

    # Existing Windows keyring users may have sequence.json + configs but no
    # credentials/ dir yet (it never held files before this change), and the
    # file backend's write does a bare write_text. Ensure it exists up front —
    # only reached on the real-work path (Windows + readable accounts).
    switcher.credentials_dir.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        os.chmod(switcher.credentials_dir, 0o700)

    # account-None-{email} can only be attributed to a slot when its email is
    # unique; otherwise it's an ambiguous stale artifact (cleanup-only).
    email_counts = Counter(info.get("email", "") for info in accounts.values())

    migrated = 0
    failed = 0

    for account_num, info in accounts.items():
        email = info.get("email", "")
        canonical = f"account-{account_num}-{email}"
        none_user = f"account-None-{email}"

        # --- pick a source (canonical wins) -------------------------------
        try:
            creds = keyring.get_password(KEYRING_SERVICE, canonical)
        except Exception as e:  # noqa: BLE001
            switcher._logger.warning(
                f"windows_keyring_to_files: read of {canonical} failed: {e}"
            )
            failed += 1
            continue

        source_username = canonical
        if not creds and str(account_num) != "None" and email_counts[email] == 1:
            # Canonical missing; fall back to account-None only when the email
            # unambiguously maps to this one slot.
            try:
                creds = keyring.get_password(KEYRING_SERVICE, none_user)
            except Exception as e:  # noqa: BLE001
                switcher._logger.warning(
                    f"windows_keyring_to_files: read of {none_user} failed: {e}"
                )
                failed += 1
                continue
            if creds:
                source_username = none_user

        if not creds:
            # Nothing in the keyring for this slot (e.g. added on the new
            # version, or an ambiguous account-None we won't touch). Benign —
            # not a failure. Leave any account-None entry alone.
            continue

        # --- write + verify before deleting the only other copy -----------
        try:
            switcher._write_account_credentials(account_num, email, creds)
            readback = switcher._read_account_credentials(account_num, email)
        except Exception as e:  # noqa: BLE001
            switcher._logger.warning(
                f"windows_keyring_to_files: write/read-back for {canonical} failed: {e}"
            )
            # A partial/garbage file must not shadow the still-intact keyring
            # entry (files are authoritative now). Drop it; retry rewrites it.
            switcher._delete_account_credentials(account_num, email)
            failed += 1
            continue

        if readback != creds:
            switcher._logger.warning(
                f"windows_keyring_to_files: read-back mismatch for {canonical}; "
                "discarding the bad file and leaving the keyring entry in place"
            )
            switcher._delete_account_credentials(account_num, email)
            failed += 1
            continue

        # Data is safely in the file now → files are authoritative. Remove the
        # source entry, and the redundant account-None entry, best-effort.
        _delete_keyring_quietly(keyring, switcher, source_username)
        if str(account_num) != "None" and source_username != none_user:
            _delete_keyring_quietly(keyring, switcher, none_user)
        migrated += 1

    if migrated:
        print(
            f"claude-swap: migrated {migrated} Windows credential(s) from "
            "Credential Manager to files",
            file=sys.stderr,
        )

    if failed:
        raise MigrationIncomplete(
            f"{failed} account(s) could not be migrated from Credential Manager; "
            "will retry on next run"
        )
    return True


def _keyring_backend_unavailable(keyring, exc: Exception) -> bool:
    """Whether ``exc`` from a keyring call means the backend is *unusable* (vs. a
    locked/denied Keychain).

    Only an unusable backend justifies the ``security`` fallback — `security` is a
    real alternative path to the same data. A locked/denied Keychain would hit
    `security` identically, so that must stay a genuine failure (retry), not a
    fallback that just re-prompts.
    """
    errs = getattr(keyring, "errors", None)
    candidates = tuple(
        c
        for c in (
            getattr(errs, "NoKeyringError", None),
            getattr(errs, "InitError", None),
        )
        if isinstance(c, type)
    )
    return bool(candidates) and isinstance(exc, candidates)


def migrate_macos_keyring_to_security(switcher: "ClaudeAccountSwitcher") -> bool:
    """Move macOS backup credentials from the ``keyring`` service to the
    ``security`` service.

    macOS now stores per-account backup credentials in the Keychain via the
    ``security`` CLI under ``SECURITY_SERVICE`` (see
    :mod:`claude_swap.macos_keychain`) instead of the third-party ``keyring``
    library's ``KEYRING_SERVICE``. Source and dest are *different* services, so old
    keyring items and new security items coexist during a safe
    write → verify → delete (no risk window), like the Windows keyring → files
    migration.

    Returns ``True`` (completed) on macOS once every account is accounted for
    (including the benign "already migrated / nothing to do" cases); ``False``
    (skip) on non-macOS or when there's no readable sequence yet. Raises
    :class:`MigrationIncomplete` if any account could not be safely relocated, so
    the runner retries on the next launch rather than marking it done.

    Source reads prefer ``keyring`` (silent, same-app). They fall back to the
    ``security`` CLI *only* when ``keyring`` is genuinely unavailable (not
    installed / no usable backend) — where ``security`` is a real alternative and
    may prompt once. This branch is dormant while ``keyring`` is a dependency; it
    exists so a future ``keyring`` removal can't strand a long-absent user.
    """
    if switcher.platform != Platform.MACOS:
        return False
    if not switcher.sequence_file.exists():
        return False  # No managed accounts yet — let a later restore migrate.

    data = switcher._get_sequence_data()
    if data is None:
        # sequence.json exists but is corrupt. Never mark applied: a user who
        # repairs/restores it must still get the migration.
        return False

    accounts = data.get("accounts", {})
    if not accounts:
        return True  # Readable sequence, nothing to migrate → done.

    # Pre-check: anything already in the new security service is done. New installs
    # and already-migrated users have every account here, so they never touch
    # keyring at all. Only the still-missing accounts proceed below; on a retry
    # this also narrows work to the accounts that actually failed last time.
    #
    # Read the security service *directly* (not the transparent .enc-wins backup
    # methods): this migration's job is the Keychain specifically, so a fallback
    # .enc must not be mistaken for "already migrated". A down Keychain here is not
    # "nothing to migrate" — defer and retry rather than skip real entries.
    try:
        pending = {
            account_num: info
            for account_num, info in accounts.items()
            if not switcher._kc_read_backup(account_num, info.get("email", ""))
        }
    except macos_keychain.KEYCHAIN_ERRORS as e:
        # Keychain unusable (locked/denied/missing) — defer, don't skip real
        # entries. A programming error is NOT caught here; it propagates.
        raise MigrationIncomplete(
            f"Keychain unavailable, deferring macOS keyring migration: {e}"
        ) from e
    if not pending:
        return True  # All accounts already in the security service.

    # account-None-{email} maps to a slot only when its email is unique.
    email_counts = Counter(info.get("email", "") for info in accounts.values())

    # Source backend: keyring if importable, else None → security fallback.
    keyring = None
    try:
        import keyring as _keyring  # noqa: PLC0415 - only on the migration path

        keyring = _keyring
    except Exception as e:  # noqa: BLE001
        switcher._logger.warning(
            "macos_keyring_to_security: keyring unavailable, using security "
            f"fallback for legacy reads (may prompt once): {e}"
        )

    def _read_old(username: str) -> str:
        """Read a legacy ``KEYRING_SERVICE`` item: ``""`` if absent, else its value.

        Prefers ``keyring``; downgrades to ``security`` only if the keyring backend
        is unusable. Raises on a genuine read failure (e.g. locked Keychain).
        """
        nonlocal keyring
        if keyring is not None:
            try:
                creds = keyring.get_password(KEYRING_SERVICE, username)
                return creds or ""
            except Exception as e:  # noqa: BLE001
                if not _keyring_backend_unavailable(keyring, e):
                    raise  # locked/denied → real failure, security can't help
                switcher._logger.warning(
                    "macos_keyring_to_security: keyring backend unusable, "
                    f"falling back to security (may prompt once): {e}"
                )
                keyring = None  # subsequent reads use security too
        creds = macos_keychain.get_password(KEYRING_SERVICE, username)
        return creds or ""

    def _delete_old(username: str) -> None:
        """Best-effort removal of a legacy ``KEYRING_SERVICE`` item — only when
        ``keyring`` is available (a silent, same-app delete). Never raises.

        In the keyring-unavailable fallback we deliberately leave the legacy item
        behind: deleting it via ``security`` could raise a *second* Keychain prompt
        (the item was created by a different app), and the data is already safely
        in the new service. The orphan is harmless cruft (``purge`` mops it up)."""
        if keyring is not None:
            _delete_keyring_quietly(
                keyring, switcher, username, context="macos_keyring_to_security"
            )

    migrated = 0
    failed = 0

    for account_num, info in pending.items():
        email = info.get("email", "")
        canonical = f"account-{account_num}-{email}"
        none_user = f"account-None-{email}"

        # --- pick a source (canonical wins) -------------------------------
        try:
            creds = _read_old(canonical)
        except Exception as e:  # noqa: BLE001
            switcher._logger.warning(
                f"macos_keyring_to_security: read of {canonical} failed: {e}"
            )
            failed += 1
            continue

        source_username = canonical
        if not creds and str(account_num) != "None" and email_counts[email] == 1:
            try:
                creds = _read_old(none_user)
            except Exception as e:  # noqa: BLE001
                switcher._logger.warning(
                    f"macos_keyring_to_security: read of {none_user} failed: {e}"
                )
                failed += 1
                continue
            if creds:
                source_username = none_user

        if not creds:
            # Nothing in the keyring for this slot (e.g. added on the new version,
            # or an ambiguous account-None we won't touch). Benign — not a failure.
            continue

        # --- write + verify before deleting the source ------------------------
        # Keychain-only helpers: this migration targets the security service, so
        # it must not be diverted to .enc files by the transparent backup methods.
        try:
            switcher._kc_write_backup(account_num, email, creds)
            readback = switcher._kc_read_backup(account_num, email)
        except Exception as e:  # noqa: BLE001
            switcher._logger.warning(
                f"macos_keyring_to_security: write/read-back for {canonical} failed: {e}"
            )
            # A partial/garbage security item must not shadow the still-intact
            # keyring entry. Drop it; the retry rewrites it.
            switcher._delete_backup_keychain_quiet(account_num, email)
            failed += 1
            continue

        if readback != creds:
            switcher._logger.warning(
                f"macos_keyring_to_security: read-back mismatch for {canonical}; "
                "discarding the security item and leaving the keyring entry in place"
            )
            switcher._delete_backup_keychain_quiet(account_num, email)
            failed += 1
            continue

        # Data is safely in the security service now → remove the keyring source(s).
        _delete_old(source_username)
        if str(account_num) != "None" and source_username != none_user:
            _delete_old(none_user)
        # Verify the removal: keyring masks a *denied* delete as the same
        # PasswordDeleteError a missing entry raises, so a leftover would
        # otherwise be invisible. The check is attribute-only (never decrypts,
        # never prompts). The orphan is harmless — log it, don't fail.
        if macos_keychain.item_exists(KEYRING_SERVICE, source_username):
            switcher._logger.warning(
                f"macos_keyring_to_security: legacy keyring entry {source_username} "
                "was left behind (delete failed or was denied); harmless — "
                "remove manually or via purge"
            )
        migrated += 1

    if migrated:
        print(
            f"claude-swap: migrated {migrated} macOS credential(s) from the keyring "
            "into the Keychain via security",
            file=sys.stderr,
        )

    if failed:
        raise MigrationIncomplete(
            f"{failed} account(s) could not be migrated to the security service; "
            "will retry on next run"
        )
    return True


# Bump to re-run the per-account designOauth migration on every data dir: the
# id recorded in .migrations.json carries the version.
DESIGN_MIGRATION_VERSION = 1
_DESIGN_TAG = "design_oauth_per_account"
DESIGN_MIGRATION_ID = f"{_DESIGN_TAG}.v{DESIGN_MIGRATION_VERSION}"
# Short: this runs at switcher construction, and a busy lock only defers it.
_DESIGN_LOCK_TIMEOUT = 2.0


def _expires(design: dict) -> float | None:
    try:
        return float(design["expiresAt"])
    except (KeyError, TypeError, ValueError):
        return None


def _design_owner(
    fp: str,
    candidates: dict[str, dict],
    preferred: list[str],
) -> tuple[str | None, str]:
    """The one slot a duplicated Design login belongs to, and why.

    ``candidates`` maps each slot that may own the family (its backup holds
    it, or holds none and its profile does) to that slot's newest copy. The
    token carries no account identity cswap could read offline, so in order:
    the logged-in / active slot when it is a candidate, else the slot holding
    the strictly newest generation (``expiresAt``: where it was captured
    last, since a capture takes the live, newest copy).
    ``(None, reason)`` when that is still a tie: genuinely ambiguous.
    """
    if not candidates:
        return None, "every holder has its own other Design login"
    if len(candidates) == 1:
        return next(iter(candidates)), "only holder"
    for slot in preferred:
        if slot in candidates:
            return slot, "active account"
    stamped = {
        n: stamp for n, d in candidates.items() if (stamp := _expires(d)) is not None
    }
    if len(stamped) == len(candidates):
        newest = max(stamped.values())
        top = [n for n, v in stamped.items() if v == newest]
        if len(top) == 1:
            return top[0], "most recently captured"
    return None, "identical or undated copies in several accounts"


def _assign_design_oauth(
    switcher: "ClaudeAccountSwitcher", data: dict
) -> tuple[int, int]:
    """One pass of :func:`migrate_design_oauth_per_account`, under cswap's lock.

    Returns ``(changed, unreadable)`` counts.
    """
    from claude_swap.credentials import (
        design_fingerprint,
        design_oauth_of,
        newer_design_oauth,
        with_design_oauth,
    )
    from claude_swap.session import (
        mark_foreign_design,
        profile_is_quiescent,
        read_profile_design,
        strip_live_profile_design,
        strip_profile_design_oauth,
    )

    accounts = data.get("accounts", {})
    log = switcher._logger
    tag = DESIGN_MIGRATION_ID
    live, readable = switcher._store.peek_live_design_oauth()
    if not readable:
        raise MigrationIncomplete(f"{tag}: the live credential store is unreadable")
    live_fp = design_fingerprint(live)

    # The account logged in now, then the roster's active slot.
    preferred: list[str] = []
    identity = switcher._get_current_account()
    if identity is not None:
        slot = switcher._find_account_slot(data, *identity)
        if slot is not None:
            preferred.append(slot)
    active = data.get("activeAccountNumber")
    if active is not None and str(active) not in preferred:
        preferred.append(str(active))
    preferred = [
        n for n in preferred
        if n in accounts and switcher._account_kind(n) != "api_key"
    ]
    # The live Design login belongs to the logged-in account outright.
    live_owner = None
    if live is not None and identity is not None:
        slot = switcher._find_account_slot(data, *identity)
        if slot is not None and switcher._account_kind(slot) != "api_key":
            live_owner = slot

    backups: dict[str, str] = {}
    backup_design: dict[str, dict | None] = {}
    profiles: dict[str, tuple[Path, dict]] = {}
    # Profiles whose store could not be read (a denied or timed-out Keychain
    # prompt): what they hold is unknown, so every family another account
    # owns is marked there below, never left to read as this account's.
    unread_profiles: dict[str, Path] = {}
    # Keyed by fingerprint; a Design login without any token has none and
    # is left alone (it can neither be told apart nor spent).
    copies: dict[str, list[dict]] = {}

    def collect(design: dict | None) -> None:
        fp = design_fingerprint(design)
        if design is not None and fp is not None:
            copies.setdefault(fp, []).append(design)

    unreadable = 0
    for num, info in accounts.items():
        email = info.get("email", "")
        creds, failed = switcher._read_account_credentials_ex(num, email)
        if failed:
            unreadable += 1
            continue
        backups[num] = creds or ""
        design = design_oauth_of(creds)
        backup_design[num] = design
        collect(design)
        session_dir = switcher._session_dir(num, email)
        if session_dir.is_dir():
            pdesign, profile_readable = read_profile_design(session_dir)
            if not profile_readable:
                unread_profiles[num] = session_dir
            if pdesign is not None:
                profiles[num] = (session_dir, pdesign)
                collect(pdesign)
    collect(live)
    if unreadable:
        # Ownership needs every holder; decide nothing on partial evidence.
        return 0, unreadable

    def newest(designs: list[dict]) -> dict:
        best = designs[0]
        for d in designs[1:]:
            best = newer_design_oauth(best, d) or best
        return best

    owners: dict[str, str] = {}
    keep: dict[str, dict] = {}
    for fp, found in copies.items():
        if fp == live_fp and live_owner is not None and live is not None:
            owners[fp], keep[fp] = live_owner, live
            continue
        candidates: dict[str, dict] = {}
        for num in backups:
            mine = [
                d for d in (
                    backup_design.get(num),
                    profiles.get(num, (None, None))[1],
                )
                if d is not None and design_fingerprint(d) == fp
            ]
            own_fp = design_fingerprint(backup_design.get(num))
            if mine and own_fp in (fp, None):
                candidates[num] = newest(mine)
        holders = {
            n for n in backups
            if design_fingerprint(backup_design.get(n)) == fp
            or (n in profiles and design_fingerprint(profiles[n][1]) == fp)
        }
        if not holders:
            continue  # only live, owned by no managed OAuth account
        if len(holders) == 1:
            # One account's own copy. Recorded so its backup gets the newest
            # generation (e.g. a profile's own copy when the backup has none);
            # never moved into a backup that holds another family.
            (only,) = holders
            if only in candidates:
                owners[fp], keep[fp] = only, newest(found)
            continue
        owner, why = _design_owner(fp, candidates, preferred)
        if owner is None:
            log.warning(
                f"{tag}: Design login {fp} is held by accounts "
                f"{', '.join(sorted(holders, key=int))} and its owner cannot be "
                f"told apart ({why}); left untouched in all of them. Remove it "
                "from the wrong ones with /logout or /design-login there."
            )
            continue
        owners[fp], keep[fp] = owner, newest(found)
        log.info(f"{tag}: Design login {fp} belongs to Account-{owner} ({why})")

    changed = 0
    for num, creds in backups.items():
        email = accounts[num].get("email", "")
        fp = design_fingerprint(backup_design.get(num))
        updated, action = creds, ""
        own = [f for f, o in owners.items() if o == num]
        if live_owner == num and live_fp in owners:
            updated = with_design_oauth(creds, keep[live_fp])
            action = f"set to the live Design login {live_fp}"
        elif fp is not None and fp in owners and owners[fp] != num:
            updated = with_design_oauth(creds, None)
            action = (
                f"removed Design login {fp} (belongs to Account-{owners[fp]})"
            )
        else:
            target = next((f for f in own if f == fp), None) or (
                own[0] if fp is None and own else None
            )
            if target is not None:
                updated = with_design_oauth(creds, keep[target])
                action = f"set to its newest copy of Design login {target}"
        if updated == creds:
            continue
        switcher._store._write_account_credentials(num, email, updated)
        if action.startswith("removed"):
            # The retained generation still holds the removed copy.
            switcher._store.delete_previous_backup(num, email)
        backups[num] = updated
        changed += 1
        log.info(f"{tag}: Account-{num} backup: {action}")

    for num, (session_dir, design) in profiles.items():
        fp = design_fingerprint(design)
        if fp not in owners or owners[fp] == num:
            continue
        if not profile_is_quiescent(session_dir):
            # A claude runs in it: the copy is stripped under the profile's
            # own Claude Code locks, before that claude can refresh it (which
            # would spend the owner's). Marked as well: from now on the copy
            # is ignored for this account, should it come back or the strip
            # not land (the profile's locks busy), and the marker settles
            # once the profile is quiescent (next run/adoption).
            stripped = strip_live_profile_design(session_dir, {fp})
            if mark_foreign_design(session_dir, fp) or stripped:
                changed += 1
                log.info(
                    f"{tag}: Account-{num} session profile holds Design login "
                    f"{fp} (Account-{owners[fp]}'s); a claude is running in it, "
                    + ("removed under its locks" if stripped
                       else "its locks are busy: marked, and removed on a later "
                            "usage pass or once it exits")
                )
            else:
                log.warning(
                    f"{tag}: Account-{num} session profile: could not remove or "
                    f"mark Design login {fp}"
                )
            continue
        if strip_profile_design_oauth(session_dir, only={fp}):
            changed += 1
            log.info(
                f"{tag}: Account-{num} session profile: removed Design login "
                f"{fp} (Account-{owners[fp]}'s)"
            )
        elif mark_foreign_design(session_dir, fp):
            changed += 1
            log.warning(
                f"{tag}: Account-{num} session profile: could not remove Design "
                f"login {fp} now; marked for removal"
            )

    for num, session_dir in unread_profiles.items():
        foreign = sorted(fp for fp, owner in owners.items() if owner != num)
        if not foreign:
            continue
        if all(mark_foreign_design(session_dir, fp) for fp in foreign):
            changed += 1
            log.warning(
                f"{tag}: Account-{num} session profile could not be read; "
                f"Design login(s) {', '.join(foreign)} of other accounts marked "
                "for removal there in case it holds one"
            )
        else:
            log.warning(
                f"{tag}: Account-{num} session profile could not be read or "
                "marked; a Design login of another account may remain there"
            )
    return changed, unreadable


def migrate_design_oauth_per_account(switcher: "ClaudeAccountSwitcher") -> bool:
    """Make every slot and session profile hold only its own ``designOauth``.

    ``designOauth`` (Claude Design's ``/design-login``) is account-owned
    (``ACCOUNT_CREDENTIAL_KEYS``), but a slot stored before that rule can hold
    a copy captured from whichever account was live at the time (an add or a
    switch capture), and session profiles are seeded from those slots. Such a
    copy would now be activated for the wrong account. Token families are compared by
    :func:`design_fingerprint` (sha256 of the refresh token, 12 hex digits);
    only fingerprints are logged.

    1. The live store's Design login belongs to the logged-in account and is
       written into that slot's backup (the freshest generation). The live
       store is read, never written.
    2. Any other family held by several accounts gets one owner, decided
       deterministically (:func:`_design_owner`): the active account if it
       holds it, else the one holding the newest generation. The owner keeps
       the newest copy; it is removed only from the others (backups with
       their ``.prev``, and session profiles). A family whose owner cannot be
       told apart is left untouched everywhere, with a warning — the
       migration never strips an account of a copy that may be its own.
    3. A session profile a claude runs in is rewritten under that profile's
       own Claude Code locks (:func:`~claude_swap.session.strip_live_profile_design`),
       before the running claude can refresh the copy and spend the owner's.
       It is also marked (``FOREIGN_DESIGN_MARKER``, fingerprints only): the
       copy is ignored for that account from then on, should it come back or
       the strip not land (locks busy), and the marker settles when the
       profile is next quiescent, so the migration itself still completes.

    A one-shot: recorded under the versioned id ``DESIGN_MIGRATION_ID``
    before the lock is released, and re-checked under the lock, so
    concurrent processes run it once. Only an unreadable store, a busy lock
    or a ``cswap run`` session shell (nothing decided yet) leaves it for a
    later run. Idempotent either way.
    """
    from claude_swap.exceptions import LockError
    from claude_swap.locking import FileLock

    if not switcher.sequence_file.exists():
        return False
    data = switcher._get_sequence_data()
    if data is None:
        return False
    if not data.get("accounts", {}):
        return True
    if switcher._in_session_shell():
        # Inside `cswap run` the env-following live store and identity are
        # the session profile's, not the default login's: its copy may be
        # one seeded there from another slot. Left for a normal shell.
        return False

    tag = DESIGN_MIGRATION_ID
    try:
        with FileLock(switcher.lock_file, timeout=_DESIGN_LOCK_TIMEOUT):
            if DESIGN_MIGRATION_ID in _load_applied(switcher):
                return True  # another process ran it while we waited
            data = switcher._get_sequence_data() or data
            changed, unreadable = _assign_design_oauth(switcher, data)
            if not unreadable:
                # Recorded before the lock goes: a process waiting for it
                # re-checks the record as soon as it gets the lock.
                try:
                    _mark_applied(switcher, DESIGN_MIGRATION_ID)
                except OSError as e:
                    switcher._logger.warning(
                        f"{tag}: ran but recording it failed: {e}"
                    )
    except LockError as e:
        raise MigrationIncomplete(f"{tag}: cswap is busy ({e})") from e

    if changed:
        print(
            "claude-swap: Claude Design logins are now kept per account; "
            f"updated {changed} stored cop{'y' if changed == 1 else 'ies'} "
            "(fingerprints in the log)",
            file=sys.stderr,
        )
    if unreadable:
        raise MigrationIncomplete(
            f"{tag}: {unreadable} unreadable backup(s); nothing decided, "
            "will retry on next run"
        )
    return True


# Registry of (id, fn). Order matters if migrations ever depend on each other.
MIGRATIONS: list[tuple[str, Callable[["ClaudeAccountSwitcher"], bool]]] = [
    ("windows_keyring_to_files", migrate_windows_keyring_to_files),
    ("macos_keyring_to_security", migrate_macos_keyring_to_security),
    (DESIGN_MIGRATION_ID, migrate_design_oauth_per_account),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_migrations(switcher: "ClaudeAccountSwitcher") -> None:
    """Run any not-yet-applied migrations. Never raises.

    A no-op on fresh installs (backup dir not yet materialized — preserves the
    lazy-dir invariant) and once the state file records every migration. A
    failing migration is logged and left unmarked so it retries next run; it
    must never abort switcher construction.
    """
    if not switcher.backup_dir.exists():
        return

    applied = _load_applied(switcher)
    for migration_id, fn in MIGRATIONS:
        if migration_id in applied:
            continue
        try:
            completed = fn(switcher)
        except Exception as e:  # noqa: BLE001 - migrations must never brick the tool
            switcher._logger.warning(
                f"Migration {migration_id} did not complete (will retry): {e}"
            )
            continue
        if completed:
            try:
                _mark_applied(switcher, migration_id)
            except Exception as e:  # noqa: BLE001
                switcher._logger.warning(
                    f"Migration {migration_id} ran but recording it failed "
                    f"(will re-run next time): {e}"
                )
