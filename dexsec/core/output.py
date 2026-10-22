"""Output location management.

DEX-SEC never writes into the directory that was scanned: a security audit
must not modify the project it inspects.  All artefacts end up in a dedicated
output folder instead.

Resolution order for the output root:

1. ``DEXSEC_OUTPUT_ROOT`` environment variable
2. the source checkout the tool was started from (``<source>/hasil-scan``)
3. ``~/.dexsec/hasil-scan`` for pip/onefile installations
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime
from pathlib import Path

DEFAULT_FOLDER_NAME = "hasil-scan"


def _is_source_checkout(package_dir: Path) -> bool:
    """True when the tool runs from a checkout that contains pyproject.toml."""
    for parent in [package_dir, *package_dir.parents][:3]:
        if (parent / "pyproject.toml").is_file():
            return True
    return False


def default_output_root() -> Path:
    """The folder where all scan results are stored."""
    env = os.environ.get("DEXSEC_OUTPUT_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()

    package_dir = Path(__file__).resolve().parent.parent
    if _is_source_checkout(package_dir):
        # .../dex-sec/dexsec/core/output.py -> .../dex-sec/hasil-scan
        return package_dir.parent / DEFAULT_FOLDER_NAME

    if getattr(sys, "frozen", False):
        # one-file build: keep the results next to the executable
        # <dex-sec>/dist/dexsec.exe -> <dex-sec>/hasil-scan
        exe_dir = Path(sys.executable).resolve().parent
        if exe_dir.name.lower() in ("dist", "build"):
            exe_dir = exe_dir.parent
        return exe_dir / DEFAULT_FOLDER_NAME

    return Path.home() / ".dexsec" / DEFAULT_FOLDER_NAME


def project_slug(project_path: str) -> str:
    """A readable folder name for a project."""
    path = Path(project_path).resolve()
    name = path.name or "project"
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
    return slug or "project"


def run_output_dir(project_path: str, explicit: str = "", target: str = "") -> Path:
    """Return (and create) the folder for one scan run."""
    if explicit:
        base = Path(explicit).expanduser()
    else:
        base = default_output_root() / project_slug(project_path)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if target:
        host = re.sub(r"^https?://", "", target).split("/")[0]
        host = re.sub(r"[^A-Za-z0-9._-]+", "-", host).strip("-") or "target"
        folder = f"{stamp}-{host}"
    else:
        folder = stamp
    folder = folder.replace(":", "-")

    target_dir = base / folder
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir
