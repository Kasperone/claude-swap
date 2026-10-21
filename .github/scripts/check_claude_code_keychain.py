"""Static check: cswap's Keychain naming matches the published Claude Code binary.

Reads the (never executed, never logged-in) Claude Code binary as bytes and
asserts the credential-storage logic cswap mirrors is still there:

* service  = "Claude Code" + OAUTH_FILE_SUFFIX + "-credentials" + ("-" + first 8
  hex of sha256(NFC config dir) unless the default profile)
* account  = $USER, or "claude-code-user" for a name outside [a-zA-Z0-9._-]
* designOauth is stored in that same credential blob (plaintext fallback:
  .credentials.json)

Usage: check_claude_code_keychain.py PATH_TO_CLAUDE_BINARY
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from claude_swap import macos_keychain
from claude_swap.credentials import CLAUDE_CODE_KEYCHAIN_SERVICE
from claude_swap.session import keychain_service_name

CHECKS = {
    "service template": rb"Claude Code\$\{[^}]*OAUTH_FILE_SUFFIX\}\$\{\w+\}\$\{\w+\}",
    "-credentials suffix": rb'="-credentials"',
    "config-dir hash": rb'\("sha256"\)\.update\(\w+\)\.digest\("hex"\)\.substring\(0,8\)',
    "secure-storage dir override": rb"CLAUDE_SECURESTORAGE_CONFIG_DIR",
    "account name rule": rb"\^\[a-zA-Z0-9\._-\]\+\$",
    "account fallback": rb"claude-code-user",
    "plaintext fallback file": rb"\.credentials\.json",
    "designOauth read": rb"readAsync\(r\)\)\?\.designOauth|readAsync\(\)\)\?\.designOauth",
    "designOauth write (blob spread)": rb"\.\.\.e,designOauth:\w+",
}


def main(path: str) -> int:
    data = Path(path).read_bytes()
    failed = False
    for name, pattern in CHECKS.items():
        match = re.search(pattern, data)
        print(f"{'ok  ' if match else 'FAIL'} {name}: "
              f"{match.group(0).decode(errors='replace') if match else 'not found'}")
        failed |= match is None

    assert CLAUDE_CODE_KEYCHAIN_SERVICE == "Claude Code-credentials"
    assert re.fullmatch(
        r"Claude Code-credentials-[0-9a-f]{8}", keychain_service_name("/some/dir")
    )
    os.environ["USER"] = "not a valid name"
    assert macos_keychain.keychain_account_name() == "claude-code-user"
    os.environ["USER"] = "ok.user-1_x"
    assert macos_keychain.keychain_account_name() == "ok.user-1_x"
    print("ok   cswap service/account derivation matches the template above")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
