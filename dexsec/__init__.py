"""DEX-SEC — Inside-Out Hybrid Application Security Testing CLI.

Fase:
    1. Inside Inspection   -> route discovery + taint analysis (SAST)
    2. Outside Verification-> safe, non-destructive probes against a live target
    3. Correlation         -> confirmed / potential / not reproducible
    4. AI Remediation      -> unified diff (LLM) or offline heuristic fallback
    5. Attack Chain Analysis
    6. Next Step Advisor
    7. Reporting           -> terminal summary + Markdown/JSON/HTML/PDF/SARIF
"""

from __future__ import annotations

try:  # installed package -> use the metadata (single source of truth)
    from importlib.metadata import PackageNotFoundError, version as _version

    try:
        __version__ = _version("dexsec")
    except PackageNotFoundError:  # running from a source checkout
        __version__ = "0.7.0"
except ImportError:  # pragma: no cover - Python < 3.8
    __version__ = "0.7.0"

__all__ = ["__version__"]
