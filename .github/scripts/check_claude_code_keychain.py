"""Static check: cswap's Keychain naming matches the published Claude Code binary.

Reads Claude Code binaries as bytes (never executed, never logged in) and
asserts the credential-storage logic cswap mirrors is still there:

* service  = "Claude Code" + OAUTH_FILE_SUFFIX + part + hash, where part is
  "-credentials" for the OAuth item and empty for the managed API key item, and
  hash is "-" + first 8 hex of sha256(NFC config dir) unless default profile
* account  = $USER, or "claude-code-user" for a name outside [a-zA-Z0-9._-]
* designOauth is read from / spread into the same credential blob
  (plaintext fallback: .credentials.json), and it belongs to the login:
  logout revokes it and a re-login deletes it (with cloudSessionsOauth)
  together with claudeAiOauth — why cswap keeps it per account
* the plaintext file lives in the secure-storage dir (CLAUDE_SECURESTORAGE_CONFIG_DIR
  when defined, empty = ~/.claude), and the only storage kinds are keychain,
  plaintext and windows-credman — Linux has no secret-store backend
* Windows (``*.exe``): Credential Manager is opt-in only; otherwise the
  plaintext file is the store (WINDOWS_CHECKS)
* the locks cswap holds while it rewrites the store (claude_store_locks): the
  Design and cloud-sessions refreshes run under their own proper-lockfile
  dirs in the secure-storage dir, and their CAS save revokes the new token
  when the store changed; every store write takes ``.storage-write.lock`` and
  re-reads the store under it

Patterns avoid minified identifiers (they change every release) and anchor on
string literals and property names instead.

Usage: check_claude_code_keychain.py LABEL=PATH [LABEL=PATH ...]
Exit status 1, with a message naming the broken expectation, when any binary
no longer matches: review cswap's keychain naming (credentials.py,
session.keychain_service_name, macos_keychain.keychain_account_name).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from unittest import mock

CHECKS = {
    "service template": rb"Claude Code\$\{[^}]{0,60}OAUTH_FILE_SUFFIX\}\$\{\w+\}\$\{\w+\}",
    "-credentials part (OAuth item)": rb'="-credentials"',
    "config-dir hash": rb'"sha256"\)\.update\(\w+\)\.digest\("hex"\)\.substring\(0,8\)',
    "secure-storage dir override": rb"CLAUDE_SECURESTORAGE_CONFIG_DIR",
    "managed-key item (service builder with no argument)": rb'"find-generic-password","-a",\w+\(\),"-w","-s",\w+\(\)',
    "account name rule": rb"\^\[a-zA-Z0-9\._-\]\+\$",
    "account fallback": rb"claude-code-user",
    "plaintext fallback file": rb"\.credentials\.json",
    "plaintext file in the secure-storage dir": rb'storagePath:\w+\(\w+,"\.credentials\.json"\)',
    "secure-storage dir rule": rb"process\.env\.CLAUDE_SECURESTORAGE_CONFIG_DIR;if\(\w+!==void 0\)return\(\w+\|\|",
    "storage kinds (no Linux secret store)": rb'"keychain","plaintext","windows-credman"',
    "designOauth read": rb"\?\.designOauth",
    "designOauth write (blob spread)": rb"\.\.\.\w+,designOauth:\w+",
    "re-login deletes designOauth and cloudSessionsOauth with the login":
        rb"delete \w+\.claudeAiOauth,[^;]{0,200}?delete \w+\.designOauth,"
        rb"delete \w+\.cloudSessionsOauth",
    "logout revokes designOauth":
        rb"\?\.designOauth;if\(\w+\?\.refreshToken\)await \w+\(\w+\.refreshToken,\w+\.clientId\)",
    # cswap holds these while it rewrites the store (claude_locks.claude_store_locks):
    "Design refresh lock": rb'"\.design_oauth_refresh\.lock"',
    "cloud-sessions refresh lock": rb'"\.cloud_sessions_oauth_refresh\.lock"',
    "refresh locks are proper-lockfile dirs in the secure-storage dir, stale 60s":
        rb"let \w+=\w+\(\);await \w+\(\)\.mkdir\(\w+\);let \w+=\w+\(\w+,\w+\),\w+=!1,"
        rb"\w+,\w+=0;while\(!\w+\)\{\w+\+\+;try\{\w+=await \w+\(\w+,\{lockfilePath:\w+,"
        rb"realpath:!1,stale:60000",
    "store writes take .storage-write (proper-lockfile: .storage-write.lock), stale 15s":
        rb'\w+\(\w+\(\w+,"\.storage-write"\),\{realpath:!1,retries:\{retries:\d+,'
        rb"minTimeout:\d+,maxTimeout:\d+\},stale:15000",
    "store writes re-read the store under that lock":
        rb"\.invalidateCache\?\.\(\);let \w+=await\(\w+\.readAsyncStrict\?\.",
    # Why the switch must hold the Design refresh lock: a store that changed
    # under the refresh makes Claude Code revoke the token it was just issued.
    "Design save is a CAS that revokes its new token on a race":
        rb"onlyIf:\(\w+\)=>\w+\?\.refreshToken===\w+\}\);if\(\w+\.raced\)\{await "
        rb"\w+\(\w+\.refreshToken,\w+\.clientId\);let \w+=await \w+\(\);return "
        rb"\w+\?\.accessToken&&!\w+\(\w+\.expiresAt\)\?\{ok:!0,accessToken:"
        rb'\w+\.accessToken\}:\{ok:!1,reason:"needs_design_login"\}',
    # A wiped login keeps its siblings, Design login included (why a switch
    # still captures a wiped login's Design login).
    "invalid_grant wipe empties only the login's tokens":
        rb'\{\.\.\.\w+,claudeAiOauth:\{\.\.\.\w+,refreshToken:"",accessToken:"",'
        rb"expiresAt:0\}\}",
}

# win32 builds only (``claude.exe``): the plaintext file stays the store unless
# Credential Manager is opted into, which cswap does not support. If the opt-in
# gate disappears (credman by default), cswap's file writes stop reaching
# Claude Code on Windows.
WINDOWS_CHECKS = {
    "store selector: credman only when opted in, else plaintext":
        rb"function \w+\(\)\{if\(\w+\)return \w+;if\(\w+\(\)\)return \w+\(\w+,\w+\);return \w+\}",
    "credman opt-in env var": rb'process\.env\.CLAUDE_CODE_FORCE_WINDOWS_CREDMAN==="1"\)return!0',
    "credman opt-in feature flag": rb"cachedGrowthBookFeatures\?\.tengu_windows_credman===!0",
    "credman backend via Bun.secrets": rb'name:"windows-credman",osGuarded:!0',
    "credman entry = Keychain service + account": rb"\{service:\w+\(\w+\),name:\w+\(\)\}",
    "first credman write deletes the plaintext file":
        rb"let \w+=await \w+\.readAsync\(\),\w+=await \w+\.update\(\w+\);"
        rb"if\(\w+\.success\)\{if\(\w+===null\)await \w+\.delete\(\w+\)",
}


RELOGIN_PRUNE = rb"delete \w+\.claudeAiOauth(?:,delete \w+\.\w+)+"


def relogin_pruned_keys(data: bytes) -> set[str]:
    """Keys Claude Code deletes together with claudeAiOauth on a re-login."""
    match = re.search(RELOGIN_PRUNE, data)
    if not match:
        return set()
    return {key.decode() for key in re.findall(rb"delete \w+\.(\w+)", match.group(0))}


def check_binary(label: str, path: str) -> list[str]:
    """Return a failure message per broken expectation (empty when all hold)."""
    data = Path(path).read_bytes()
    from claude_swap.credentials import ACCOUNT_CREDENTIAL_KEYS

    pruned = relogin_pruned_keys(data)
    unowned = sorted(pruned - ACCOUNT_CREDENTIAL_KEYS)
    print(f"{'ok  ' if pruned and not unowned else 'FAIL'} [{label}] re-login "
          f"pruned keys are all account-owned in cswap: {sorted(pruned)}")
    prune_failures = [] if pruned and not unowned else [
        f"[{label}] expectation changed: Claude Code's re-login now prunes "
        f"{unowned or 'nothing recognisable'}; add account-bound keys to "
        f"ACCOUNT_CREDENTIAL_KEYS (credentials.py) before trusting this version."
    ]
    checks = dict(CHECKS)
    if path.lower().endswith(".exe"):
        checks.update(WINDOWS_CHECKS)
    failures = []
    for name, pattern in checks.items():
        match = re.search(pattern, data)
        print(f"{'ok  ' if match else 'FAIL'} [{label}] {name}: "
              f"{match.group(0).decode(errors='replace') if match else 'not found'}")
        if not match:
            failures.append(
                f"[{label}] expectation changed: {name}. Claude Code's credential "
                f"storage may have changed; re-verify cswap's Keychain naming "
                f"against this version before trusting it."
            )
    return failures + prune_failures


def check_cswap() -> None:
    from claude_swap import claude_locks, macos_keychain

    assert claude_locks.DESIGN_REFRESH_LOCK == ".design_oauth_refresh.lock"
    assert claude_locks.CLOUD_SESSIONS_REFRESH_LOCK == ".cloud_sessions_oauth_refresh.lock"
    assert claude_locks.STORE_WRITE_LOCK == ".storage-write.lock"
    assert claude_locks.STORE_WRITE_STALENESS_S == 15.0
    assert claude_locks.CREDENTIALS_STALENESS_S == 60.0
    from claude_swap.credentials import (
        ACCOUNT_CREDENTIAL_KEYS,
        CLAUDE_CODE_KEYCHAIN_SERVICE,
        SHARED_CREDENTIAL_KEYS,
        _active_managed_keychain_services,
    )
    from claude_swap.session import STORAGE_OVERRIDE_ENV_VARS
    from claude_swap.session import keychain_service_name

    from claude_swap.paths import get_credentials_path

    assert CLAUDE_CODE_KEYCHAIN_SERVICE == "Claude Code-credentials"
    # Account-owned, as the re-login prune above shows.
    assert {"designOauth", "cloudSessionsOauth"} <= ACCOUNT_CREDENTIAL_KEYS
    assert not {"designOauth", "cloudSessionsOauth"} & SHARED_CREDENTIAL_KEYS
    # Sessions drop the store override the "secure-storage dir rule" names.
    assert "CLAUDE_SECURESTORAGE_CONFIG_DIR" in STORAGE_OVERRIDE_ENV_VARS
    with mock.patch.dict(os.environ):
        os.environ["CLAUDE_CONFIG_DIR"] = "/cfg"
        os.environ["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = "/secure"
        assert get_credentials_path() == Path("/secure/.credentials.json")
        os.environ["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = ""
        assert get_credentials_path() == Path.home() / ".claude" / ".credentials.json"
        del os.environ["CLAUDE_SECURESTORAGE_CONFIG_DIR"]
        assert get_credentials_path() == Path("/cfg/.credentials.json")
    assert re.fullmatch(
        r"Claude Code-credentials-[0-9a-f]{8}", keychain_service_name("/some/dir")
    )
    with mock.patch.dict(os.environ):
        os.environ["CLAUDE_CONFIG_DIR"] = "/some/dir"
        os.environ.pop("CLAUDE_SECURESTORAGE_CONFIG_DIR", None)
        (managed,) = _active_managed_keychain_services()
        assert re.fullmatch(r"Claude Code-[0-9a-f]{8}", managed), managed
        os.environ["USER"] = "not a valid name"
        assert macos_keychain.keychain_account_name() == "claude-code-user"
        os.environ["USER"] = "ok.user-1_x"
        assert macos_keychain.keychain_account_name() == "ok.user-1_x"
    print("ok   cswap service/account derivation matches the template")


def main(args: list[str]) -> int:
    failures: list[str] = []
    for arg in args:
        label, _, path = arg.partition("=")
        failures += check_binary(label, path)
    check_cswap()
    for message in failures:
        print(f"::error::{message}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
