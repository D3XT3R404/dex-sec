"""Minimal unified diff applier.

DEX-SEC can fix code even when the project is not a git repository, so the
patch is applied with a small self-contained implementation of the unified
diff format instead of shelling out to ``git apply``.

Only the subset produced by DEX-SEC is supported:

    --- a/path
    +++ b/path
    @@ -start,count +start,count @@
     context
    -removed
    +added
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)


@dataclass
class FilePatch:
    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)


@dataclass
class ApplyResult:
    applied: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed


def parse_diff(diff: str) -> list[FilePatch]:
    """Parse a unified diff into file patches."""
    patches: list[FilePatch] = []
    current: FilePatch | None = None
    hunk: Hunk | None = None

    for raw in diff.splitlines():
        if raw.startswith("--- "):
            current = FilePatch(old_path=_strip_prefix(raw[4:]), new_path="")
            patches.append(current)
            hunk = None
            continue
        if raw.startswith("+++ "):
            if current is None:
                current = FilePatch(old_path="", new_path="")
                patches.append(current)
            current.new_path = _strip_prefix(raw[4:])
            hunk = None
            continue
        if raw.startswith("@@"):
            match = HUNK_RE.match(raw)
            if not match or current is None:
                hunk = None
                continue
            hunk = Hunk(
                old_start=int(match.group(1)),
                old_count=int(match.group(2) or 1),
                new_start=int(match.group(3)),
                new_count=int(match.group(4) or 1),
            )
            current.hunks.append(hunk)
            continue
        if hunk is None:
            continue
        if raw.startswith((" ", "-", "+")):
            hunk.lines.append(raw)
        elif raw == "":
            hunk.lines.append(" ")
        elif raw.startswith("\\"):
            continue  # "\ No newline at end of file"
    return patches


def _strip_prefix(path: str) -> str:
    path = path.strip()
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _read_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        text = fh.read()
    return text.splitlines()


def apply_diff(diff: str, root: str, dry_run: bool = False) -> ApplyResult:
    """Apply a unified diff to the files below *root*."""
    result = ApplyResult()
    for patch in parse_diff(diff):
        target = patch.new_path or patch.old_path
        if not target:
            continue
        absolute = target if os.path.isabs(target) else os.path.join(root, target)
        if not os.path.isfile(absolute):
            result.failed.append((target, "file not found"))
            continue
        try:
            original = _read_lines(absolute)
        except OSError as exc:
            result.failed.append((target, str(exc)))
            continue

        patched, error = _apply_hunks(original, patch.hunks)
        if error:
            result.failed.append((target, error))
            continue
        if not dry_run:
            try:
                with open(absolute, "w", encoding="utf-8", newline="") as fh:
                    fh.write("\n".join(patched) + "\n")
            except OSError as exc:
                result.failed.append((target, str(exc)))
                continue
        result.applied.append(target)
    return result


def _apply_hunks(original: list[str], hunks: list[Hunk]) -> tuple[list[str], str]:
    result: list[str] = []
    cursor = 0  # index into the original file
    for hunk in hunks:
        start = max(hunk.old_start - 1, 0)
        if start < cursor:
            return original, "overlapping hunks"
        result.extend(original[cursor:start])
        cursor = start
        for line in hunk.lines:
            if not line:
                continue
            marker, text = line[0], line[1:]
            if marker == " ":
                if cursor >= len(original) or original[cursor] != text:
                    return original, f"context mismatch near line {cursor + 1}"
                result.append(original[cursor])
                cursor += 1
            elif marker == "-":
                if cursor >= len(original) or original[cursor] != text:
                    return original, f"removal mismatch near line {cursor + 1}"
                cursor += 1
            elif marker == "+":
                result.append(text)
    result.extend(original[cursor:])
    return result, ""
