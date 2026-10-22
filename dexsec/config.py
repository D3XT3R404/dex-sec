"""User configuration.

DEX-SEC reads an optional TOML file so that defaults (which folders to
ignore, which severity to report, the notification webhook, the LLM provider)
do not have to be repeated on every command line.

Location (first one that exists wins):

1. ``DEXSEC_CONFIG`` environment variable
2. ``./dexsec.toml`` in the current directory (project specific)
3. ``~/.config/dexsec/config.toml`` (user wide, Windows: %APPDATA%\\dexsec\\config.toml)
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    tomllib = None  # type: ignore[assignment]


def user_config_path() -> Path:
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "dexsec" / "config.toml"


def project_config_path(root: str = ".") -> Path:
    return Path(root).resolve() / "dexsec.toml"


def find_config(root: str = ".") -> Path | None:
    env = os.environ.get("DEXSEC_CONFIG", "").strip()
    if env:
        path = Path(env).expanduser()
        return path if path.is_file() else None
    project = project_config_path(root)
    if project.is_file():
        return project
    user = user_config_path()
    return user if user.is_file() else None


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    min_severity: str = "INFO"
    target: str = ""
    output_root: str = ""
    notify_url: str = ""
    notify_level: str = "CRITICAL"
    ai_provider: str = "openai"
    ai_model: str = "gpt-4o-mini"
    ai_key_env: str = "DEXSEC_AI_KEY"
    source_path: str = ""

    @classmethod
    def load(cls, root: str = ".") -> "Config":
        path = find_config(root)
        config = cls()
        if path is None:
            return config
        config.source_path = str(path)
        data = _read_toml(path)
        if not data:
            return config
        config.exclude = list(data.get("exclude", []) or [])
        config.min_severity = str(data.get("min_severity", config.min_severity)).upper()
        config.target = str(data.get("target", config.target))
        config.output_root = str(data.get("output_root", config.output_root))
        notify = data.get("notify", {}) or {}
        config.notify_url = str(notify.get("url", config.notify_url))
        config.notify_level = str(notify.get("level", config.notify_level)).upper()
        ai = data.get("ai", {}) or {}
        config.ai_provider = str(ai.get("provider", config.ai_provider))
        config.ai_model = str(ai.get("model", config.ai_model))
        config.ai_key_env = str(ai.get("key_env", config.ai_key_env))
        return config

    def to_dict(self) -> dict[str, Any]:
        return {
            "exclude": self.exclude,
            "min_severity": self.min_severity,
            "target": self.target,
            "output_root": self.output_root,
            "notify": {"url": self.notify_url, "level": self.notify_level},
            "ai": {
                "provider": self.ai_provider,
                "model": self.ai_model,
                "key_env": self.ai_key_env,
            },
            "source": self.source_path,
        }


def _read_toml(path: Path) -> dict[str, Any]:
    if tomllib is not None:
        try:
            with open(path, "rb") as fh:
                return tomllib.load(fh)
        except (OSError, ValueError):
            return {}
    try:  # pragma: no cover - fallback for Python 3.10 without tomllib
        import tomli  # type: ignore
    except ModuleNotFoundError:
        return {}
    try:
        with open(path, "rb") as fh:
            return tomli.load(fh)
    except (OSError, ValueError):
        return {}


TEMPLATE = """# DEX-SEC configuration
# Letakkan file ini di root project (dexsec.toml) atau di ~/.config/dexsec/config.toml

# Folder yang tidak perlu dipindai (selain yang sudah otomatis)
exclude = [
    "vendor",
    "storage",
    "*.min.js",
]

# Severity minimum yang ditampilkan di laporan
min_severity = "INFO"

# Target default untuk verifikasi eksternal (bisa ditimpa dengan --target)
target = ""

# Folder tempat hasil scan disimpan (default: <dexsec>/hasil-scan)
output_root = ""

# Notifikasi ke Slack/Discord saat ada temuan kritis
[notify]
url = ""
level = "CRITICAL"

# Provider LLM untuk pembuatan patch (tanpa key, tool tetap jalan)
[ai]
provider = "openai"      # openai | anthropic | gemini
model = "gpt-4o-mini"
key_env = "DEXSEC_AI_KEY"
"""


def write_template(path: Path, force: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        return path
    path.write_text(TEMPLATE, encoding="utf-8")
    return path
