"""Detect Claude Code's Windows Credential Manager mode (presence only).

Claude Code on Windows keeps its credentials in the plaintext
``.credentials.json`` — the file cswap reads and writes — unless Credential
Manager is opted into (2.1.306, strings of the win32 builds):

- ``CLAUDE_CODE_FORCE_WINDOWS_CREDMAN=1``, or
- ``cachedGrowthBookFeatures.tengu_windows_credman === true`` in the global
  config it reads (``<config home>/.config.json`` when non-empty, else
  ``(CLAUDE_CONFIG_DIR || ~)/.claude.json``).

In that mode it reads Credential Manager first and deletes the plaintext file
on its first write there, so a cswap switch would write a file Claude Code
does not read. cswap does not support that store; it only detects the mode so
switching can refuse instead of silently doing nothing.

Credential Manager is only *enumerated*, never read or written: Bun.secrets
(``src/jsc/bindings/SecretsWindows.cpp``) stores a ``CRED_TYPE_GENERIC``
credential with target name ``"<service>/<account>"`` (chunks append
``#0..n``/``#m``/``#p`` to the account), with the same service as the macOS
Keychain item. :func:`entry_stamps` lists the target names under
``"<service>/*"`` with their ``LastWritten`` time and frees the result
without touching the secret blob.

An entry with no opt-in in sight is ambiguous: a stale leftover of a mode
that was turned off, or a Claude Code that was started with the opt-in in its
own environment. When the user overrides that refusal, the entry's
``LastWritten`` is remembered (:func:`acknowledge`): the same entry, unchanged,
no longer refuses. Claude Code rewrites its entry on every login refresh in
that mode, so a new ``LastWritten`` makes it ambiguous again.

This module is import-safe on every platform; the enumeration only runs on
Windows.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

FORCE_ENV = "CLAUDE_CODE_FORCE_WINDOWS_CREDMAN"
FEATURE_FLAG = "tengu_windows_credman"
IGNORE_ENV = "CSWAP_IGNORE_CREDMAN"

ACTIVE = "active"
AMBIGUOUS = "ambiguous"

# In cswap's data dir: target name -> LastWritten of entries the user said
# were stale (by overriding the refusal they caused).
ACK_FILE = ".credman-acknowledged.json"

# A config Claude Code is rewriting can be briefly unreadable on Windows
# (sharing violation); a few quick retries keep that from reading as
# "unknown".
_CONFIG_READ_ATTEMPTS = 3
_CONFIG_READ_RETRY_DELAY = 0.1


@dataclass(frozen=True)
class CredmanMode:
    """Why switching is unsafe: ``state`` is ACTIVE or AMBIGUOUS.

    ``entries`` holds the ``(target name, LastWritten)`` pairs behind an
    ambiguity that rests on entries alone (no opt-in seen), else is empty.
    """

    state: str
    reason: str
    entries: tuple[tuple[str, int], ...] = ()


def _enumerate_targets(pattern: str) -> dict[str, int]:
    """Target names matching ``pattern`` (``CredEnumerateW``) with their
    ``LastWritten`` (a FILETIME as an int), blobs untouched.

    Raises ``OSError`` when the enumeration itself fails; an empty result is
    a genuine "no such entry".
    """
    import ctypes  # noqa: PLC0415 - Windows-only path
    from ctypes import wintypes  # noqa: PLC0415

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            # The remaining fields (blob size, blob, attributes, ...) are never
            # read; only TargetName is dereferenced, LastWritten read in place.
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    enumerate_w = advapi32.CredEnumerateW
    enumerate_w.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(CREDENTIALW))),
    ]
    enumerate_w.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    advapi32.CredFree.restype = None

    count = wintypes.DWORD(0)
    creds = ctypes.POINTER(ctypes.POINTER(CREDENTIALW))()
    if not enumerate_w(pattern, 0, ctypes.byref(count), ctypes.byref(creds)):
        err = ctypes.get_last_error()
        if err == 1168:  # ERROR_NOT_FOUND
            return {}
        raise ctypes.WinError(err)
    try:
        found = {}
        for i in range(count.value):
            cred = creds[i].contents
            written = cred.LastWritten
            found[cred.TargetName or ""] = (
                (written.dwHighDateTime << 32) | written.dwLowDateTime
            )
        return found
    finally:
        advapi32.CredFree(creds)


def entry_stamps(services: list[str]) -> dict[str, int] | None:
    """Credential Manager entries for ``services``: target name -> LastWritten.

    ``None`` when it cannot be told (not Windows, or the enumeration failed).
    """
    if sys.platform != "win32":
        return None
    try:
        return {
            target: stamp
            for service in services
            for target, stamp in _enumerate_targets(f"{service}/*").items()
            if target.startswith(f"{service}/")
        }
    except OSError:
        return None


def entry_present(services: list[str]) -> bool | None:
    """Whether Credential Manager holds an entry for any of ``services``.

    ``None`` when it cannot be told (not Windows, or the enumeration failed).
    """
    stamps = entry_stamps(services)
    return None if stamps is None else bool(stamps)


def _flag_config_path(config_dir: str | Path | None = None) -> Path:
    """The global config Claude Code reads the cached flag from.

    For the profile named by ``config_dir`` (a ``cswap run`` session), else
    the one ``CLAUDE_CONFIG_DIR`` names.
    """
    if config_dir is None:
        config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
    home = Path(config_dir) if config_dir else Path.home() / ".claude"
    legacy = home / ".config.json"
    try:
        if legacy.read_text(encoding="utf-8") != "":
            return legacy
    except OSError:
        pass
    return (Path(config_dir) if config_dir else Path.home()) / ".claude.json"


def _cached_flag(config_dir: str | Path | None = None) -> bool | None:
    """The cached ``tengu_windows_credman`` value; ``None`` when unreadable.

    A config that reads but does not parse counts as "off", as in Claude
    Code, whose lookup falls back to the plaintext store on any parse error.
    """
    path = _flag_config_path(config_dir)
    for attempt in range(_CONFIG_READ_ATTEMPTS):
        try:
            text = path.read_text(encoding="utf-8")
            break
        except FileNotFoundError:
            return False
        except OSError:
            if attempt == _CONFIG_READ_ATTEMPTS - 1:
                return None
            time.sleep(_CONFIG_READ_RETRY_DELAY)
    try:
        data = json.loads(text)
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    features = data.get("cachedGrowthBookFeatures")
    return isinstance(features, dict) and features.get(FEATURE_FLAG) is True


def detect(
    services: list[str], config_dir: str | Path | None = None
) -> CredmanMode | None:
    """Claude Code's Credential Manager mode for the active profile.

    ``config_dir`` names another profile to check (its config and, through
    ``services``, its entry) instead of the one ``CLAUDE_CONFIG_DIR`` names.

    ACTIVE when the env var or the cached flag opts in; AMBIGUOUS when the
    config exists but cannot be read, or an entry exists for this profile without an
    opt-in (a stale entry, or a running Claude Code that started opted in and
    still uses it). ``None`` means the plaintext file is Claude Code's store.
    """
    if os.environ.get(FORCE_ENV) == "1":
        return CredmanMode(ACTIVE, f"{FORCE_ENV}=1 is set")
    flag = _cached_flag(config_dir)
    if flag:
        return CredmanMode(
            ACTIVE, f"{FEATURE_FLAG} is enabled in {_flag_config_path(config_dir)}"
        )
    if flag is None:
        return CredmanMode(
            AMBIGUOUS,
            f"{_flag_config_path(config_dir)} could not be read, so whether "
            f"{FEATURE_FLAG} is enabled is unknown",
        )
    stamps = entry_stamps(services)
    if stamps:
        return CredmanMode(
            AMBIGUOUS,
            f"Credential Manager holds a '{services[0]}' entry although "
            "Credential Manager mode is not enabled (a stale entry, or a "
            "Claude Code instance that started with it enabled)",
            tuple(sorted(stamps.items())),
        )
    return None


def _read_acks(ack_file: Path) -> dict:
    try:
        data = json.loads(ack_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def acknowledged(mode: CredmanMode, ack_file: Path) -> bool:
    """Whether ``mode`` rests only on entries the user overrode before, each
    unchanged since (same ``LastWritten``). Never true for an opt-in."""
    if not mode.entries:
        return False
    acks = _read_acks(ack_file)
    return all(acks.get(target) == stamp for target, stamp in mode.entries)


def acknowledge(mode: CredmanMode, ack_file: Path) -> None:
    """Remember the entries behind an overridden ambiguity as stale.

    A no-op for an opt-in (no entries); best-effort otherwise — failing to
    remember only means the next switch asks again.
    """
    if not mode.entries:
        return
    acks = {**_read_acks(ack_file), **dict(mode.entries)}
    tmp = None
    try:
        ack_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=ack_file.parent, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(acks, f)
        os.replace(tmp, ack_file)
        tmp = None
    except OSError:
        pass
    finally:
        if tmp is not None:
            Path(tmp).unlink(missing_ok=True)
