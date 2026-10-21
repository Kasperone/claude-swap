"""Static check: cswap's Keychain naming matches the published Claude Code binary.

Reads Claude Code binaries as bytes (never executed, never logged in) and
asserts the credential-storage logic cswap mirrors is still there:

* service  = "Claude Code" + OAUTH_FILE_SUFFIX + part + hash, where part is
  "-credentials" for the OAuth item and empty for the managed API key item, and
  hash is "-" + first 8 hex of sha256(NFC config dir) unless default profile
* account  = $USER, or "claude-code-user" for a name outside [a-zA-Z0-9._-]
* designOauth is read from / spread into the same credential blob
  (plaintext fallback: .credentials.json)

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
    "designOauth read": rb"\?\.designOauth",
    "designOauth write (blob spread)": rb"\.\.\.\w+,designOauth:\w+",
}


def check_binary(label: str, path: str) -> list[str]:
    """Return a failure message per broken expectation (empty when all hold)."""
    data = Path(path).read_bytes()
    failures = []
    for name, pattern in CHECKS.items():
        match = re.search(pattern, data)
        print(f"{'ok  ' if match else 'FAIL'} [{label}] {name}: "
              f"{match.group(0).decode(errors='replace') if match else 'not found'}")
        if not match:
            failures.append(
                f"[{label}] expectation changed: {name}. Claude Code's credential "
                f"storage may have changed; re-verify cswap's Keychain naming "
                f"against this version before trusting it."
            )
    return failures


def check_cswap() -> None:
    from claude_swap import macos_keychain
    from claude_swap.credentials import (
        CLAUDE_CODE_KEYCHAIN_SERVICE,
        _active_managed_keychain_services,
    )
    from claude_swap.session import keychain_service_name

    assert CLAUDE_CODE_KEYCHAIN_SERVICE == "Claude Code-credentials"
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
