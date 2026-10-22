"""Static analysis engine.

Walks the project directory, discovers HTTP routes, and locates tainted sinks.
Pure standard library so the tool installs anywhere with zero native deps.
"""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Iterable, Optional

from ..models import CodeFinding, RouteInfo, Severity, VulnClass
from . import access, ast_taint, config_scan, languages, php_calls, rules


def _iter_source_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in rules.IGNORED_DIRS and not d.startswith(".")]
        for name in filenames:
            if any(fnmatch.fnmatch(name, pat) for pat in rules.IGNORED_FILES):
                continue
            if name.endswith(
                (".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".phtml", ".java", ".kt",
                 ".go", ".rb", ".cs", ".vue", ".svelte")
            ):
                yield os.path.join(dirpath, name)


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def _normalize_route(path: str) -> str:
    """Convert framework param syntax to a single canonical form.

    FastAPI/Django `:id` and Express `:id` become `{id}`;
    Flask `<int:id>` becomes `{id}`.
    """
    route = re.sub(r"<(?:[^:>]+:)?([^>]+)>", r"{\1}", path)
    route = re.sub(r":(\w+)", r"{\1}", route)
    route = re.sub(r"\*(\w*)", r"{\1}", route)
    if not route.startswith("/"):
        route = "/" + route
    return route


def _extract_params(route: str) -> list[str]:
    return re.findall(r"\{(\w+)\}", route)


# ------------------------------------------------------------------ routes
def detect_frameworks(root: str) -> list[str]:
    """Detect frameworks from dependency manifests in the project root."""
    found: list[str] = []
    manifests = [
        "requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
        "package.json", "composer.json", "go.mod",
    ]
    for manifest in manifests:
        path = os.path.join(root, manifest)
        if not os.path.isfile(path):
            continue
        content = _read(path).lower()
        for framework, needles in rules.FRAMEWORK_HINTS:
            if any(needle in content for needle in needles) and framework not in found:
                found.append(framework)
    return found


def _handler_block(lines: list[str], start_line: int, max_lines: int = 40) -> str:
    """Capture the body of a handler that follows a route decorator."""
    body: list[str] = []
    for raw in lines[start_line: start_line + max_lines]:
        stripped = raw.strip()
        if stripped:
            body.append(stripped)
        if len(body) > 2 and stripped.startswith(("return", "def ", "async def ")):
            break
    return "\n".join(body)


def _handler_params(lines: list[str], start_line: int) -> list[str]:
    """Return the parameter names of the function defined below a decorator."""
    for raw in lines[start_line: start_line + 5]:
        match = re.match(r"\s*(?:async\s+)?def\s+(\w+)\s*\((.*?)\)", raw)
        if match:
            params = []
            for part in match.group(2).split(","):
                part = part.strip()
                if not part or part in ("self", "cls"):
                    continue
                name = part.split(":")[0].split("=")[0].strip()
                if name and name.isidentifier():
                    params.append(name)
            return params
    return []


def _http_method_above(lines: list[str], line_no: int, lookback: int = 80) -> str:
    """Detect the HTTP method from a surrounding ``def do_<METHOD>`` block."""
    for index in range(min(line_no, lookback), 0, -1):
        line = lines[index - 1]
        match = re.match(r"\s*def\s+do_(get|post|put|patch|delete|head|options)\b", line, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        if re.match(r"\s*def\s+\w+", line):
            return ""  # another function starts here
    return ""


def discover_routes(root: str) -> list[RouteInfo]:
    """Find HTTP routes declared in the source tree."""
    routes: list[RouteInfo] = []
    for file_path in _iter_source_files(root):
        content = _read(file_path)
        if not content:
            continue
        lines = content.splitlines()
        for framework, _family, pattern in rules.ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                groups = match.groupdict()
                path = groups.get("path")
                if not path:
                    continue
                method = (groups.get("method") or "GET").upper()
                if method in rules.GENERIC_VERBS:
                    method = "GET"
                line_no = content[: match.start()].count("\n") + 1
                if framework == "Python":
                    # the method comes from the enclosing handler: do_POST(...)
                    detected = _http_method_above(lines, line_no)
                    if detected:
                        method = detected
                normalized = _normalize_route(path)
                route = RouteInfo(
                    method=method,
                    path=normalized,
                    file=file_path,
                    line=line_no,
                    framework=framework,
                    params=_extract_params(normalized),
                    handler_body=_handler_block(lines, line_no),
                    source_excerpt="\n".join(lines[line_no - 1: line_no + 4]),
                )
                route.handler_params = _handler_params(lines, line_no)  # type: ignore[attr-defined]
                routes.append(route)
    unique: dict[tuple, RouteInfo] = {}
    for route in routes:
        # The same endpoint can be described by a decorator and by a manual
        # dispatch table; keep only the first description per method+path.
        key = (route.method, route.path, route.file)
        if key not in unique:
            unique[key] = route
    return list(unique.values())


# ------------------------------------------------------------------- taint
def _tainted_variables(content: str) -> list[str]:
    """Variables assigned directly from a user-controlled source."""
    tainted: list[str] = []
    source_alt = "|".join(rules.TAINT_SOURCES)
    assign = re.compile(r"^\s*(?:const|let|var|final)?\s*([A-Za-z_]\w*)\s*=\s*(.+)$")
    for line in content.splitlines():
        match = assign.match(line)
        if not match:
            continue
        value = match.group(2)
        if re.search(source_alt, value, re.IGNORECASE):
            tainted.append(match.group(1))
    return tainted


def _enclosing_window(lines: list[str], index: int, lookback: int = 12) -> str:
    """Text of the function block that contains the given line."""
    start = index
    def_indent = None
    for i in range(index, max(-1, index - lookback), -1):
        if re.match(r"^\s*(async\s+)?def\s+\w+|^\s*function\s+\w+", lines[i]):
            start = i
            def_indent = len(lines[i]) - len(lines[i].lstrip())
            break
    end = index
    for i in range(index + 1, min(len(lines), index + lookback + 1)):
        match = re.match(r"^(\s*)(async\s+)?def\s+\w+|^(\s*)function\s+\w+", lines[i])
        if match:
            indent = len(match.group(1) or match.group(3) or "")
            if def_indent is None or indent <= def_indent:
                end = i - 1
                break
    return "\n".join(lines[start: end + 1])


def _snippet(lines: list[str], line_no: int, context: int = 2) -> str:
    start = max(0, line_no - 1 - context)
    end = min(len(lines), line_no + context)
    return "\n".join(lines[start:end])


def _is_tainted(statement: str, tainted_vars: list[str], source_re: re.Pattern) -> tuple[bool, str]:
    """Return (tainted, tainted_variable_name) for a statement."""
    if source_re.search(statement):
        match = source_re.search(statement)
        return True, match.group(0)
    for var in tainted_vars:
        if var in rules.GENERIC_TAINT_NAMES:
            # A generic container name is only trusted when it is produced by
            # a request object, which is handled by the source regex above.
            continue
        if re.search(rf"\b{re.escape(var)}\b", statement):
            return True, var
    return False, ""


def find_tainted_sinks(root: str, routes: list[RouteInfo]) -> list[CodeFinding]:
    """Scan the tree for user input reaching a dangerous sink."""
    findings: list[CodeFinding] = []
    source_re = re.compile("|".join(rules.TAINT_SOURCES), re.IGNORECASE)
    cross_file_taint = propagate_taint_across_files(root)

    # Handler parameters of route handlers are tainted by definition.
    handler_params: dict[str, list[str]] = {}
    for route in routes:
        params = getattr(route, "handler_params", []) or []
        if params:
            handler_params.setdefault(route.file, []).extend(params)

    for file_path in _iter_source_files(root):
        content = _read(file_path)
        if not content:
            continue
        lines = content.splitlines()
        tainted_vars = _tainted_variables(content) + handler_params.get(file_path, [])
        tainted_vars += cross_file_taint.get(file_path, [])
        tainted_vars = list(dict.fromkeys(tainted_vars))

        for rule in rules.SINK_RULES:
            for pattern in rule.patterns:
                try:
                    regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                except re.error:
                    continue
                for match in regex.finditer(content):
                    line_no = content[: match.start()].count("\n") + 1
                    index = line_no - 1
                    statement = _enclosing_window(lines, index)
                    tainted, taint_var = _is_tainted(statement, tainted_vars, source_re)

                    if rule.vuln_class == "SQL_INJECTION":
                        # A parameterised query is not injectable: the statement must
                        # contain a placeholder AND the call must pass parameters.
                        placeholders = re.search(r"(%s|\?|%d)\b", statement)
                        params_passed = re.search(r"\.execute(?:many)?\s*\([^)]*,\s*\(", statement)
                        if placeholders and params_passed:
                            continue
                        # Require the interpolated value itself to be user controlled.
                        interpolated = set(re.findall(r"\{(\w+)\}", statement))
                        interpolated |= set(re.findall(r"%\s*\(?(\w+)\)?", statement))
                        if interpolated and tainted_vars:
                            tainted = bool(interpolated & set(tainted_vars))
                            taint_var = ", ".join(sorted(interpolated & set(tainted_vars)))
                        elif not tainted:
                            continue
                    elif rule.require_taint and not tainted:
                        continue

                    if rule.vuln_class == "HARDCODE_SECRET":
                        # Ignore enum-like constants such as SECRET = "SECRET_NAME".
                        value_match = re.search(r"""["']([^"']+)["']""", match.group(0))
                        if value_match and re.fullmatch(r"[A-Z0-9_\-]{6,}", value_match.group(1)):
                            continue

                    confidence = rule.confidence + (0.1 if tainted else 0.0)
                    findings.append(
                        CodeFinding(
                            vuln_class=VulnClass(rule.vuln_class),
                            severity=Severity(rule.severity),
                            file=file_path,
                            line=line_no,
                            code_snippet=_snippet(lines, line_no),
                            description=rule.description,
                            cwe=rule.cwe,
                            taint_source=statement.strip().splitlines()[0][:200] if statement else "",
                            taint_var=taint_var,
                            sink=match.group(0)[:120],
                            confidence=min(confidence, 0.95),
                            matched_pattern=pattern,
                        )
                    )
    return _dedupe(findings)


def _dedupe(findings: list[CodeFinding]) -> list[CodeFinding]:
    """One finding per (class, file, line) — keep the most specific match."""
    best: dict[tuple, CodeFinding] = {}
    order: list[tuple] = []
    for finding in findings:
        key = (finding.vuln_class, finding.file, finding.line)
        current = best.get(key)
        if current is None:
            best[key] = finding
            order.append(key)
        elif len(finding.sink) > len(current.sink) or finding.confidence > current.confidence:
            best[key] = finding
    return [best[key] for key in order]


def attach_routes(findings: list[CodeFinding], routes: list[RouteInfo]) -> None:
    """Link each finding to the route whose handler contains it.

    The route whose decorator is the closest one *above* the finding wins,
    because that is the handler the code belongs to.
    """
    by_file: dict[str, list[RouteInfo]] = {}
    for route in routes:
        by_file.setdefault(route.file, []).append(route)
    for file_routes in by_file.values():
        file_routes.sort(key=lambda r: r.line)

    for finding in findings:
        candidates = by_file.get(finding.file, [])
        enclosing: Optional[RouteInfo] = None
        for route in candidates:
            if route.line <= finding.line:
                enclosing = route
            else:
                break
        if enclosing is not None and finding.line - enclosing.line <= 60:
            finding.route = enclosing
            continue
        best: Optional[RouteInfo] = None
        best_distance = 10**9
        for route in candidates:
            distance = abs(route.line - finding.line)
            if distance < best_distance:
                best_distance = distance
                best = route
        if best is not None and best_distance <= 40:
            finding.route = best


def _module_level_tainted(content: str) -> list[str]:
    """Tainted variables that live at module level (top level assignments)."""
    tainted: list[str] = []
    source_alt = "|".join(rules.TAINT_SOURCES)
    for line in content.splitlines():
        if line[:1].isspace():
            continue
        match = re.match(r"^([A-Za-z_]\w*)\s*=\s*(.+)$", line)
        if match and re.search(source_alt, match.group(2), re.IGNORECASE):
            tainted.append(match.group(1))
    return tainted


def _imported_names(content: str) -> list[str]:
    """Names that this file imports from other modules."""
    names: list[str] = []
    for match in re.finditer(r"^\s*from\s+[\w.]+\s+import\s+(.+)$", content, re.MULTILINE):
        raw = match.group(1)
        raw = raw.split("#")[0]
        for part in raw.split(","):
            part = part.strip().strip("()")
            if not part:
                continue
            alias = part.split(" as ")[-1].strip()
            if alias.isidentifier():
                names.append(alias)
    return names


def propagate_taint_across_files(root: str) -> dict[str, list[str]]:
    """Approximate cross-file taint: a name that is tainted in the module it
    comes from stays tainted in the modules that import it.

    Returns a mapping of file path -> extra tainted variable names.
    """
    module_taint: dict[str, list[str]] = {}
    imports: dict[str, list[str]] = {}
    for file_path in _iter_source_files(root):
        content = _read(file_path)
        if not content:
            continue
        module_taint[file_path] = _module_level_tainted(content)
        imports[file_path] = _imported_names(content)

    extra: dict[str, list[str]] = {}
    for _ in range(3):  # a few rounds to follow a chain of imports
        changed = False
        for file_path, imported in imports.items():
            for name in imported:
                for other, tainted_names in module_taint.items():
                    if other == file_path:
                        continue
                    if name in tainted_names:
                        current = extra.setdefault(file_path, [])
                        if name not in current:
                            current.append(name)
                            changed = True
                            module_taint.setdefault(file_path, []).append(name)
        if not changed:
            break
    return extra


def find_language_sinks(root: str) -> list[CodeFinding]:
    """Language aware sink detection (PHP, JavaScript, Java, Go, C#, Ruby)."""
    findings: list[CodeFinding] = []
    for file_path in _iter_source_files(root):
        spec = languages.detect_language(file_path)
        if spec is None or spec.name == "python":
            continue
        content = _read(file_path)
        if not content:
            continue
        lines = content.splitlines()
        tainted = languages.tainted_variables(content, spec)
        source_alt = "|".join(spec.sources)
        interpolation_alt = "|".join(spec.interpolations) if spec.interpolations else r"(?!x)x"

        for sink in spec.sinks:
            try:
                regex = re.compile(sink.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            for match in regex.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                statement = _enclosing_window(lines, line_no - 1)
                direct = bool(re.search(source_alt, statement, re.IGNORECASE))
                via_var = False
                taint_var = ""
                for name in tainted:
                    if re.search(rf"\b{re.escape(name)}\b", statement):
                        via_var = True
                        taint_var = name
                        break
                if not direct and not via_var:
                    continue
                if sink.needs_interpolation:
                    if not re.search(interpolation_alt, statement, re.IGNORECASE):
                        continue
                    if direct and not via_var:
                        taint_var = "request"
                if not taint_var:
                    taint_var = "request"
                findings.append(
                    CodeFinding(
                        vuln_class=VulnClass(sink.vuln_class),
                        severity=Severity(sink.severity),
                        file=file_path,
                        line=line_no,
                        code_snippet=_snippet(lines, line_no),
                        description=sink.description,
                        cwe=sink.cwe,
                        taint_source=statement[:200],
                        taint_var=taint_var,
                        sink=match.group(0)[:120],
                        confidence=min(sink.confidence + (0.1 if direct else 0.0), 0.95),
                    )
                )
    return _dedupe(findings)


def _php_routes(root: str) -> list[RouteInfo]:
    """Map PHP files to HTTP endpoints (file path + query parameters)."""
    routes: list[RouteInfo] = []
    # the document root is the folder that contains index.php
    doc_root = root
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in rules.IGNORED_DIRS]
        if "index.php" in filenames:
            doc_root = dirpath
            break

    for file_path in _iter_source_files(root):
        if not file_path.lower().endswith((".php", ".phtml")):
            continue
        relative = os.path.relpath(file_path, doc_root).replace("\\", "/")
        if relative.startswith(".."):
            # outside the document root: not reachable over HTTP
            continue
        content = _read(file_path)
        if not content:
            continue
        lines = content.splitlines()
        url_path = "/" + relative
        params = sorted(set(re.findall(
            r"\$_(?:GET|POST|REQUEST)\s*\[\s*[\"']([A-Za-z0-9_]+)[\"']", content
        )))
        methods = set()
        if re.search(r"\$_POST\s*\[", content):
            methods.add("POST")
        if re.search(r"\$_GET\s*\[", content):
            methods.add("GET")
        if re.search(r"\$_REQUEST\s*\[", content):
            methods.add("GET")
            methods.add("POST")
        if not methods:
            methods = {"GET"}
        for method in sorted(methods):
            routes.append(
                RouteInfo(
                    method=method,
                    path=url_path,
                    file=file_path,
                    line=1,
                    framework="PHP",
                    params=params,
                    handler_body="",
                    source_excerpt=lines[0] if lines else "",
                    handler_params=params,
                )
            )
    return routes


def scan_project(root: str) -> tuple[list[RouteInfo], list[CodeFinding], list[str]]:
    """Run the full static analysis pass over a project directory.

    Phases: route discovery -> tainted sinks (regex + AST for Python) ->
    access control heuristics -> repository level misconfiguration.
    """
    frameworks = detect_frameworks(root)
    routes = discover_routes(root)
    routes.extend(_php_routes(root))
    findings = find_tainted_sinks(root, routes)
    findings.extend(find_language_sinks(root))
    findings.extend(php_calls.analyze(root))
    findings = _refine_with_ast(root, findings)
    findings.extend(access.analyze_access_control(routes))
    findings.extend(config_scan.scan_misconfiguration(root))
    attach_routes(findings, routes)
    return routes, _dedupe(findings), frameworks


def _refine_with_ast(root: str, findings: list[CodeFinding]) -> list[CodeFinding]:
    """Replace the regex results of Python files with the AST results.

    The AST analysis understands the real data flow, so it produces fewer
    false positives and more accurate line numbers.  Classes that the AST
    analysis does not understand are kept from the regex scanner.
    """
    python_files = [path for path in _iter_source_files(root) if ast_taint.is_python(path)]
    ast_results = ast_taint.analyze_paths(python_files)
    if not ast_results:
        return findings

    ast_classes = set(ast_taint.AST_CLASSES)
    kept: list[CodeFinding] = []
    ast_findings: list[CodeFinding] = []
    for finding in findings:
        if (
            finding.file in ast_results
            and finding.vuln_class in ast_classes
            and finding.vuln_class in ast_taint.AST_CLASSES
        ):
            continue
        kept.append(finding)
    for file_findings in ast_results.values():
        ast_findings.extend(file_findings)
    return kept + ast_findings
