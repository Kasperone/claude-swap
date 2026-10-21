"""The CI binary check fails loudly, with the broken expectation named."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / ".github" / "scripts" / "check_claude_code_keychain.py"

GOOD = b"""
`Claude Code${cn().OAUTH_FILE_SUFFIX}${e}${a}` var T="-credentials"
c("sha256").update(r).digest("hex").substring(0,8)
CLAUDE_SECURESTORAGE_CONFIG_DIR
["find-generic-password","-a",yP(),"-w","-s",RB()]
/^[a-zA-Z0-9._-]+$/ claude-code-user .credentials.json
(await Vn().readAsync(r))?.designOauth ({...e,designOauth:r})
{storageDir:e,storagePath:Q(e,".credentials.json")}
let e=process.env.CLAUDE_SECURESTORAGE_CONFIG_DIR;if(e!==void 0)return(e||u(o(),".claude"))
new Set(["keychain","plaintext","windows-credman"])
delete e.claudeAiOauth,delete e.organizationUuid,delete e.designOauth,delete e.cloudSessionsOauth,e}
let m=e?.designOauth;if(m?.refreshToken)await X_(m.refreshToken,m.clientId)
"""


def _load():
    spec = importlib.util.spec_from_file_location("check_cc_keychain", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_matching_binary_passes(tmp_path):
    binary = tmp_path / "claude"
    binary.write_bytes(GOOD)
    assert _load().check_binary("v1", str(binary)) == []


def test_changed_binary_names_the_broken_expectation(tmp_path):
    binary = tmp_path / "claude"
    binary.write_bytes(GOOD.replace(b'substring(0,8)', b'substring(0,12)'))
    failures = _load().check_binary("v2", str(binary))
    assert len(failures) == 1
    assert "[v2]" in failures[0] and "config-dir hash" in failures[0]
    assert "re-verify cswap's Keychain naming" in failures[0]


def test_designoauth_ownership_change_is_flagged(tmp_path):
    binary = tmp_path / "claude"
    binary.write_bytes(GOOD.replace(b"delete e.designOauth,", b""))
    failures = _load().check_binary("v3", str(binary))
    assert len(failures) == 1 and "re-login deletes designOauth" in failures[0]


def test_unrelated_binary_fails_every_check(tmp_path):
    binary = tmp_path / "claude"
    binary.write_bytes(b"nothing here")
    module = _load()
    assert len(module.check_binary("x", str(binary))) == len(module.CHECKS)


WINDOWS = GOOD + b"""
function Vn(){if(Q)return Q;if(JQn())return B(F,D);return D}
if(process.env.CLAUDE_CODE_FORCE_WINDOWS_CREDMAN==="1")return!0;
JSON.parse(n).cachedGrowthBookFeatures?.tengu_windows_credman===!0
var F={name:"windows-credman",osGuarded:!0,read(){}}
return{service:hre(m2e),name:v1()}
let i=await e.readAsync(),c=await e.update(a);if(c.success){if(i===null)await r.delete(o)
"""


def test_windows_binary_runs_the_windows_checks(tmp_path):
    module = _load()
    exe = tmp_path / "claude.exe"
    exe.write_bytes(WINDOWS)
    assert module.check_binary("w", str(exe)) == []

    # credman by default: the opt-in gate is gone
    exe.write_bytes(WINDOWS.replace(b"if(JQn())return B(F,D);return D", b"return B(F,D)"))
    failures = module.check_binary("w2", str(exe))
    assert len(failures) == 1 and "credman only when opted in" in failures[0]

    # POSIX binaries are not held to the Windows expectations
    posix = tmp_path / "claude"
    posix.write_bytes(GOOD)
    assert module.check_binary("p", str(posix)) == []


def test_cswap_side_assertions_hold():
    _load().check_cswap()
