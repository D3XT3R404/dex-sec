"""Generate the release notes for a tag from CHANGELOG.md.

    python scripts/release_notes.py v0.7.0
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"


def section_for(version: str) -> str:
    if not CHANGELOG.is_file():
        return ""
    text = CHANGELOG.read_text(encoding="utf-8")
    version = version.lstrip("v")
    pattern = re.compile(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        return ""
    body = match.group(1).strip()
    return f"## DEX-SEC {version}\n\n{body}\n"


def main() -> int:
    version = sys.argv[1] if len(sys.argv) > 1 else ""
    notes = section_for(version)
    if not notes:
        notes = f"## DEX-SEC {version}\n\nSee CHANGELOG.md for the full details.\n"
    print(notes)
    print("### Install\n")
    print("```bash")
    print("pip install dexsec          # Python users")
    print("npm install -g dexsec       # JavaScript teams")
    print("```")
    print("\nStandalone binaries (no Python required) are attached to this release.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
