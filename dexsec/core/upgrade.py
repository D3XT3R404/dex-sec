"""Self update helper for the standalone binary.

Users who installed the single file executable (``dexsec.exe``) cannot use
``pip install -U``, so this module checks GitHub Releases for a newer version
and replaces the running executable.  For pip installations it only prints the
command to run.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass

import requests

GITHUB_RELEASES = "https://api.github.com/repos/{repo}/releases/latest"


@dataclass
class Release:
    version: str
    tag: str
    url: str
    assets: dict[str, str]


def _version_tuple(version: str) -> tuple[int, ...]:
    cleaned = version.lstrip("v").split(".")
    parts = []
    for part in cleaned[:4]:
        digits = "".join(ch for ch in part if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) + (0,) * (4 - len(parts))


def latest_release(repo: str = "your-org/dex-sec", timeout: float = 10.0) -> Release | None:
    """Fetch the latest release from GitHub (returns None on any problem)."""
    try:
        response = requests.get(
            GITHUB_RELEASES.format(repo=repo),
            headers={"Accept": "application/vnd.github+json"},
            timeout=timeout,
        )
    except requests.RequestException:
        return None
    if response.status_code != 200:
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    assets = {
        asset.get("name", ""): asset.get("browser_download_url", "")
        for asset in data.get("assets", [])
    }
    return Release(
        version=str(data.get("tag_name", "")).lstrip("v"),
        tag=str(data.get("tag_name", "")),
        url=str(data.get("html_url", "")),
        assets=assets,
    )


def _asset_for_platform(assets: dict[str, str]) -> str:
    system = sys.platform.lower()
    machine = os.uname().machine if hasattr(os, "uname") else os.environ.get("PROCESSOR_ARCHITECTURE", "x64")
    machine = machine.lower()
    if "amd64" in machine or "x86_64" in machine:
        machine = "x64"
    elif "arm64" in machine or "aarch64" in machine:
        machine = "arm64"
    else:
        machine = "x64"
    if system.startswith("win"):
        key = f"dexsec-windows-{machine}.exe"
    elif system == "darwin":
        key = f"dexsec-macos-{machine}"
    else:
        key = f"dexsec-linux-{machine}"
    if key in assets:
        return assets[key]
    for name, url in assets.items():
        if name.endswith(".exe") and system.startswith("win"):
            return url
        if not name.endswith(".exe") and not system.startswith("win"):
            return url
    return ""


def upgrade(repo: str = "your-org/dex-sec", dry_run: bool = False) -> tuple[bool, str]:
    """Check for a newer release and replace the executable when possible."""
    from . import __version__

    release = latest_release(repo)
    if release is None:
        return False, "Could not reach the GitHub release API (offline?)."

    if _version_tuple(release.version) <= _version_tuple(__version__):
        return True, f"Already up to date (installed {__version__}, latest {release.version})."

    if not getattr(sys, "frozen", False):
        return True, (
            f"A newer version is available: {release.version} (installed {__version__}).\n"
            f"Update it with:  pip install -U dexsec      (or: pipx upgrade dexsec)\n"
            f"Release notes:  {release.url}"
        )

    asset_url = _asset_for_platform(release.assets)
    if not asset_url:
        return False, f"Version {release.version} is available but no binary matches this platform."

    if dry_run:
        return True, f"Would download {asset_url} (current {__version__} -> {release.version})."

    executable = sys.executable
    try:
        with requests.get(asset_url, stream=True, timeout=120) as response:
            response.raise_for_status()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".exe" if os.name == "nt" else "") as tmp:
                for chunk in response.iter_content(chunk_size=1 << 16):
                    tmp.write(chunk)
                temporary = tmp.name
        backup = executable + ".old"
        shutil.copy2(executable, backup)
        shutil.move(temporary, executable)
        os.chmod(executable, 0o755)
        return True, f"Updated {__version__} -> {release.version}. (backup: {backup})"
    except (OSError, requests.RequestException) as exc:
        return False, f"Update failed: {exc}"


def check(repo: str = "your-org/dex-sec") -> dict:
    """Return the current and latest version as a small dictionary."""
    from . import __version__

    release = latest_release(repo)
    return {
        "installed": __version__,
        "latest": release.version if release else None,
        "url": release.url if release else None,
    }
