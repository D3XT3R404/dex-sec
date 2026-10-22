"""Notification helpers for Discord and Slack webhooks.

A webhook is triggered when a finding reaches a configurable severity.  The
payload format is chosen by inspecting the webhook URL, so the user does not
have to say which platform they use.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import requests

from ..models import CorrelatedFinding

DEFAULT_TIMEOUT = 10.0


def detect_platform(url: str) -> str:
    """Return 'slack', 'discord' or 'generic' for a webhook URL."""
    lowered = url.lower()
    if "hooks.slack.com" in lowered:
        return "slack"
    if "discord.com/api/webhooks" in lowered or "discordapp.com/api/webhooks" in lowered:
        return "discord"
    return "generic"


def _format_slack(findings: list[CorrelatedFinding], target: str) -> dict[str, Any]:
    lines = [f"*DEX-SEC: {len(findings)} confirmed finding(s)*" + (f" on {target}" if target else "")]
    for item in findings[:10]:
        lines.append(f"• *[{item.final_severity.value}]* {item.title}")
    if len(findings) > 10:
        lines.append(f"• … and {len(findings) - 10} more")
    return {"text": "\n".join(lines)}


def _format_discord(findings: list[CorrelatedFinding], target: str) -> dict[str, Any]:
    lines = [f"**DEX-SEC** — {len(findings)} confirmed finding(s)" + (f" on `{target}`" if target else "")]
    for item in findings[:10]:
        lines.append(f"• **[{item.final_severity.value}]** {item.title}")
    if len(findings) > 10:
        lines.append(f"• … and {len(findings) - 10} more")
    return {"content": "\n".join(lines)[:1900]}


def _format_generic(findings: list[CorrelatedFinding], target: str) -> dict[str, Any]:
    return {
        "tool": "dex-sec",
        "target": target,
        "count": len(findings),
        "findings": [
            {
                "severity": item.final_severity.value,
                "status": item.status.value,
                "title": item.title,
                "file": item.finding.file,
                "line": item.finding.line,
                "cwe": item.finding.cwe,
                "remediation": item.remediation_hint,
            }
            for item in findings
        ],
    }


def send_webhook(
    url: str,
    findings: list[CorrelatedFinding],
    target: str = "",
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[bool, str]:
    """Send the findings to a webhook.  Returns (ok, message)."""
    if not findings:
        return True, "no finding to report"
    platform = detect_platform(url)
    if platform == "slack":
        payload = _format_slack(findings, target)
    elif platform == "discord":
        payload = _format_discord(findings, target)
    else:
        payload = _format_generic(findings, target)
    try:
        response = requests.post(url, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        return False, f"webhook gagal: {exc}"
    if response.status_code >= 300:
        return False, f"webhook responded HTTP {response.status_code}: {response.text[:160]}"
    return True, f"notifikasi terkirim ke {platform} webhook"
