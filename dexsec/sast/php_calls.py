"""PHP call graph analysis.

In a classic PHP application the vulnerable code usually lives in an include
file (a "library") while the reachable endpoint is a thin page that calls a
function with request data::

    // config.php
    function render_greeting($text) { echo "<h1>$text</h1>"; }   // sink

    // public/modules/xss_reflected.php
    $q = $_GET['q'] ?? '';
    render_greeting($q);                                        // tainted call

A purely file based scanner would report the sink in ``config.php`` - a file
that is not an endpoint at all.  This module follows the call one level deep
so the finding is reported on the page that can actually be reached.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from ..models import CodeFinding, Severity, VulnClass
from . import languages, rules


@dataclass
class PhpFunction:
    name: str
    file: str
    start_line: int
    end_line: int
    params: list[str] = field(default_factory=list)
    body: str = ""


def _php_files(root: str) -> list[str]:
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in rules.IGNORED_DIRS and not d.startswith(".")]
        for name in filenames:
            if name.lower().endswith((".php", ".phtml")):
                result.append(os.path.join(dirpath, name))
    return result


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def _extract_functions(content: str, file_path: str) -> list[PhpFunction]:
    """Find function definitions together with their body."""
    functions: list[PhpFunction] = []
    for match in re.finditer(r"\bfunction\s+(\w+)\s*\(([^)]*)\)\s*\{", content):
        name = match.group(1)
        params = [
            p.strip().lstrip("$").split("=")[0].strip()
            for p in match.group(2).split(",")
            if p.strip()
        ]
        start = match.end() - 1
        depth = 0
        end = len(content)
        for index in range(start, len(content)):
            char = content[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        body = content[start:end]
        functions.append(
            PhpFunction(
                name=name,
                file=file_path,
                start_line=content[: match.start()].count("\n") + 1,
                end_line=content[:end].count("\n") + 1,
                params=[p for p in params if p],
                body=body,
            )
        )
    return functions


def _dangerous_functions(functions: list[PhpFunction]) -> dict[str, tuple[PhpFunction, object, str]]:
    """Map function name -> (function, sink rule, tainted parameter)."""
    spec = languages.PHP
    dangerous: dict[str, tuple[PhpFunction, object, str]] = {}
    for function in functions:
        for sink in spec.sinks:
            for match in re.finditer(sink.pattern, function.body, re.IGNORECASE):
                # the parameter that reaches the sink
                used = ""
                for param in function.params:
                    if re.search(rf"\b{re.escape(param)}\b", function.body):
                        used = param
                        break
                if not used:
                    continue
                dangerous.setdefault(function.name, (function, sink, used))
                break
    return dangerous


def analyze(root: str) -> list[CodeFinding]:
    """Report findings on the call sites that carry request data."""
    files = _php_files(root)
    if not files:
        return []

    functions: list[PhpFunction] = []
    for path in files:
        content = _read(path)
        if content:
            functions.extend(_extract_functions(content, path))

    dangerous = _dangerous_functions(functions)
    if not dangerous:
        return []

    findings: list[CodeFinding] = []
    for path in files:
        content = _read(path)
        if not content:
            continue
        lines = content.splitlines()
        tainted = languages.tainted_variables(content, languages.PHP)
        for name, (function, sink, param) in dangerous.items():
            if function.file == path:
                continue  # the definition itself is reported by the file scanner
            pattern = re.compile(rf"\b{re.escape(name)}\s*\(", re.IGNORECASE)
            for match in pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                statement = " ".join(lines[line_no - 1: line_no + 1])
                argument = ""
                for var in tainted:
                    if re.search(rf"\b{re.escape(var)}\b", statement):
                        argument = var
                        break
                if not argument:
                    continue
                findings.append(
                    CodeFinding(
                        vuln_class=VulnClass(sink.vuln_class),
                        severity=Severity(sink.severity),
                        file=path,
                        line=line_no,
                        code_snippet="\n".join(lines[max(0, line_no - 2): line_no + 2]),
                        description=(
                            f"{sink.description} (fungsi {name}() meneruskan data request ke sink "
                            f"di {os.path.basename(function.file)})"
                        ),
                        cwe=sink.cwe,
                        taint_source=statement[:200],
                        taint_var=argument,
                        sink=f"{name}() -> {sink.vuln_class}",
                        confidence=min(sink.confidence + 0.1, 0.9),
                    )
                )
    return findings
