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
Keychain item. :func:`entry_present` lists the target names under
``"<service>/*"`` and frees the result without touching the secret blob.

This module is import-safe on every platform; the enumeration only runs on
Windows.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

FORCE_ENV = "CLAUDE_CODE_FORCE_WINDOWS_CREDMAN"
FEATURE_FLAG = "tengu_windows_credman"
IGNORE_ENV = "CSWAP_IGNORE_CREDMAN"

ACTIVE = "active"
AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class CredmanMode:
    """Why switching is unsafe: ``state`` is ACTIVE or AMBIGUOUS."""

    state: str
    reason: str


def _enumerate_targets(pattern: str) -> list[str]:
    """Target names matching ``pattern`` (``CredEnumerateW``), blobs untouched.

    Raises ``OSError`` when the enumeration itself fails; an empty list is a
    genuine "no such entry".
    """
    import ctypes  # noqa: PLC0415 - Windows-only path
    from ctypes import wintypes  # noqa: PLC0415

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            # The remaining fields (comment, blob, attributes, ...) are never
            # read; only the leading TargetName pointer is dereferenced.
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
            return []
        raise ctypes.WinError(err)
    try:
        return [creds[i].contents.TargetName or "" for i in range(count.value)]
    finally:
        advapi32.CredFree(creds)


def entry_present(services: list[str]) -> bool | None:
    """Whether Credential Manager holds an entry for any of ``services``.

    ``None`` when it cannot be told (not Windows, or the enumeration failed).
    """
    if sys.platform != "win32":
        return None
    try:
        return any(
            target.startswith(f"{service}/")
            for service in services
            for target in _enumerate_targets(f"{service}/*")
        )
    except OSError:
        return None


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
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    except OSError:
        return None
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
    if entry_present(services):
        return CredmanMode(
            AMBIGUOUS,
            f"Credential Manager holds a '{services[0]}' entry although "
            "Credential Manager mode is not enabled (a stale entry, or a "
            "Claude Code instance that started with it enabled)",
        )
    return None
