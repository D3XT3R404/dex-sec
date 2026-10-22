"""Copy the documentation into the package so it ships with the wheel.

The canonical documentation lives in ``docs/`` inside the repository (it is
versioned together with the code and can be edited through pull requests).
Before a release this script copies the important parts into
``dexsec/manual/`` so that users who installed the package can read the guide
offline with ``dexsec manual``.

Usage:
    python scripts/sync_manual.py
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
TARGET = ROOT / "dexsec" / "manual"

FILES = {
    "PANDUAN-OPERASIONAL.md": "PANDUAN.md",
    "COVERAGE.md": "COVERAGE.md",
}


def main() -> int:
    TARGET.mkdir(parents=True, exist_ok=True)
    for source_name, target_name in FILES.items():
        source = DOCS / source_name
        if not source.is_file():
            print(f"[skip] {source} not found")
            continue
        shutil.copy2(source, TARGET / target_name)
        print(f"[ok]   docs/{source_name} -> dexsec/manual/{target_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
