"""A fake macOS ``security`` CLI for Keychain tests (fake credentials only).

``tests/fixtures/fake_security`` keeps items in a JSON file; the ``keychain``
fixture in conftest points ``macos_keychain`` at it, so the real
subprocess/argv code runs without touching any Keychain.
"""

from __future__ import annotations

import json
from pathlib import Path

ACCOUNT = "fakeuser"
FAKE_SECURITY = Path(__file__).parent / "fixtures" / "fake_security"


class FakeKeychain:
    """The fake script's item store, for test setup and asserts."""

    def __init__(self, db: Path):
        self.db = db

    def _data(self) -> dict:
        return json.loads(self.db.read_text()) if self.db.exists() else {}

    def put(self, service: str, value: str) -> None:
        data = self._data()
        data[f"{service}\0{ACCOUNT}"] = value
        self.db.write_text(json.dumps(data))

    def get(self, service: str) -> str | None:
        return self._data().get(f"{service}\0{ACCOUNT}")

    def get_json(self, service: str) -> dict:
        return json.loads(self.get(service))
