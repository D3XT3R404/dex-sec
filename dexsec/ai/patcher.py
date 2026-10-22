"""AI-assisted remediation engine.

Two patch sources are supported:

1. `llm`      - a real language model produces a unified diff.
2. `fallback` - deterministic, offline heuristics produce a best-effort diff
                so the tool stays useful without any API key.

Every generated patch is validated with `git apply --check` before it is
offered, so a broken diff can never corrupt the user's repository.
"""

from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess
import tempfile
from typing import Optional

from ..models import CodeFinding, CorrelatedFinding, PatchResult, VulnClass

LLM_SYSTEM_PROMPT = (
    "You are a senior application security engineer. You receive a vulnerable code snippet "
    "and its context. You MUST reply with a single unified diff (git format) that fixes the "
    "vulnerability while preserving the original behaviour. "
    "Rules: only output the diff, no prose, no markdown fences, no explanations outside the diff. "
    "Use the original file path as the 'a/' and 'b/' targets. Never introduce a syntax error."
)


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def _make_diff(rel_path: str, original: list[str], patched: list[str]) -> str:
    diff = difflib.unified_diff(original, patched, fromfile=f"a/{rel_path}", tofile=f"b/{rel_path}", lineterm="")
    return "\n".join(diff)


# --------------------------------------------------------------------- LLM
def _call_llm(finding: CodeFinding, context: str, api_key: str, provider: str, model: str) -> Optional[str]:
    """Call the configured LLM provider and return the raw diff text."""
    try:
        if provider == "openai":
            from openai import OpenAI  # type: ignore

            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": LLM_SYSTEM_PROMPT},
                    {"role": "user", "content": context},
                ],
                temperature=0.1,
            )
            return resp.choices[0].message.content

        if provider == "anthropic":
            import anthropic  # type: ignore

            client = anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model=model,
                max_tokens=1500,
                system=LLM_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": context}],
            )
            return "".join(block.text for block in msg.content if getattr(block, "type", "") == "text")

        if provider == "gemini":
            import google.generativeai as genai  # type: ignore

            genai.configure(api_key=api_key)
            model_obj = genai.GenerativeModel(model)
            resp = model_obj.generate_content([LLM_SYSTEM_PROMPT, context])
            return resp.text
    except Exception:
        return None
    return None


def _clean_diff(text: str) -> str:
    """Strip markdown fences and any prose around the diff."""
    if not text:
        return ""
    text = text.strip()
    if "```" in text:
        blocks = re.findall(r"```(?:diff)?\n(.*?)```", text, re.DOTALL)
        if blocks:
            text = blocks[0]
        else:
            text = text.replace("```diff", "").replace("```", "")
    start = text.find("--- ")
    if start > 0:
        text = text[start:]
    return text.strip()


def _build_context(finding: CodeFinding, root: str) -> str:
    route = finding.route
    try:
        rel_file = os.path.relpath(finding.file, root).replace("\\", "/")
    except ValueError:
        rel_file = finding.file
    route_info = ""
    if route:
        route_info = (
            f"\nHTTP route: {route.method} {route.path} (file: {rel_file}, line: {route.line})\n"
            f"Framework: {route.framework}\nHandler body:\n{route.handler_body[:1200]}\n"
        )
    return (
        f"Vulnerability: {finding.vuln_class.value} ({finding.cwe})\n"
        f"Severity: {finding.severity.value}\n"
        f"Description: {finding.description}\n"
        f"File: {rel_file}\n"
        f"Line: {finding.line}\n"
        f"Sink: {finding.sink}\n"
        f"{route_info}"
        f"Code around the vulnerability:\n```\n{finding.code_snippet}\n```\n\n"
        f"Return a unified diff fixing {finding.vuln_class.value} without changing the intended behaviour."
    )


# ---------------------------------------------------------------- fallback
def _fstring_parts(line: str) -> Optional[tuple[str, str, str, list[str]]]:
    """Return (quote, body, whole_match, interpolated_names) for an f-string."""
    match = re.search(r"""f(["'])(?P<body>.*?)\1""", line)
    if not match:
        return None
    names = re.findall(r"\{(\w+)\}", match.group("body"))
    if not names:
        return None
    return match.group(1), match.group("body"), match.group(0), names


def _replace_placeholders(body: str, names: list[str], placeholder: str = "%s") -> tuple[str, list[str]]:
    """Turn a f-string body into a parameterised statement.

    ``LIKE '%{term}%'`` becomes ``LIKE %s`` with the parameter ``f"%{term}%"``,
    and ``WHERE id = '{id}'`` becomes ``WHERE id = %s`` with the parameter ``id``.
    The returned list holds the Python expressions for the bound parameters.
    """
    new_body = body
    params: list[str] = []
    for name in names:
        wildcard = False
        quoted_wildcard = f"'%{{{name}}}%'"
        quoted_plain = f"'{{{name}}}'"
        if quoted_wildcard in new_body:
            new_body = new_body.replace(quoted_wildcard, placeholder)
            wildcard = True
        elif quoted_plain in new_body:
            new_body = new_body.replace(quoted_plain, placeholder)
        else:
            new_body = re.sub(r"\{(\w+)\}", placeholder, new_body, count=1)
        params.append(f'f"%{{{name}}}%"' if wildcard else name)
    return new_body, params


def _placeholder_style(lines: list[str]) -> str:
    """sqlite3 uses '?' placeholders, psycopg2/MySQL use '%s'."""
    content = "\n".join(lines)
    if re.search(r"\bimport\s+sqlite3\b|\bsqlite3\.connect\b", content):
        return "?"
    return "%s"


def _fallback_sql_patch(lines: list[str], index: int) -> Optional[list[tuple[int, str]]]:
    """Parameterise a SQL statement that is built through a variable."""
    sink_line = lines[index]
    edits: list[tuple[int, str]] = []

    # Case A: the finding sits on the assignment that builds the query.
    assign_match = re.match(r"^(\s*)(\w+)\s*=\s*(f[\"'].*)$", sink_line)
    if assign_match:
        var = assign_match.group(2)
        fparts = _fstring_parts(sink_line)
        if fparts:
            quote, body, _whole, names = fparts
            new_body, params = _replace_placeholders(body, names, _placeholder_style(lines))
            new_assign = sink_line.replace(f"f{quote}{body}{quote}", f"{quote}{new_body}{quote}")
            edits.append((index, new_assign))
            # Find the call site that consumes the variable and pass the parameters.
            for probe in range(index + 1, min(len(lines), index + 6)):
                call = re.search(r"\.execute(?:many)?\s*\(\s*" + re.escape(var) + r"\s*\)", lines[probe])
                if call:
                    new_sink = lines[probe].replace(
                        f"execute({var})", f"execute({var}, ({', '.join(params)},))"
                    )
                    edits.append((probe, new_sink))
                    break
            return edits

    # Case B: the f-string sits directly inside the sink call.
    call = re.search(r"\.execute(?:many)?\s*\(\s*(\w+)\s*\)", sink_line)
    if call:
        var = call.group(1)
        for probe in range(index - 1, max(-1, index - 6), -1):
            assign = re.match(r"^(\s*)(\w+)\s*=\s*(f[\"'].*)$", lines[probe])
            if not assign:
                continue
            fparts = _fstring_parts(assign.group(0))
            if not fparts:
                break
            quote, body, _whole, names = fparts
            if var not in assign.group(0):
                break
            new_body, params = _replace_placeholders(body, names, _placeholder_style(lines))
            new_assign = assign.group(0).replace(f"f{quote}{body}{quote}", f"{quote}{new_body}{quote}")
            edits.append((probe, new_assign))
            new_sink = sink_line.replace(f"execute({var})", f"execute({var}, ({', '.join(params)},))")
            edits.append((index, new_sink))
            return edits

    fparts = _fstring_parts(sink_line)
    if fparts:
        quote, body, _whole, names = fparts
        new_body, params = _replace_placeholders(body, names)
        new_line = sink_line.replace(f"f{quote}{body}{quote}", f"{quote}{new_body}{quote}")
        new_line = re.sub(
            r"\.(execute(?:many)?)\s*\(\s*([^,)]+?)\s*\)",
            lambda m: f".{m.group(1)}({m.group(2)}, ({', '.join(params)},))",
            new_line,
        )
        if new_line != sink_line:
            return [(index, new_line)]
    return None


def _fallback_cmd_patch(lines: list[str], index: int) -> Optional[list[tuple[int, str]]]:
    """Turn a shell-interpolated command into a safe argument list."""
    sink_line = lines[index]
    call = re.search(r"(subprocess\.\w+|os\.system|os\.popen)\s*\(\s*(\w+)\s*(,|\))", sink_line)
    if not call:
        return None
    var = call.group(2)
    for probe in range(index - 1, max(-1, index - 6), -1):
        assign = re.match(r"^(\s*)(\w+)\s*=\s*(f[\"'].*)$", lines[probe])
        if not assign:
            continue
        fparts = _fstring_parts(assign.group(0))
        if not fparts or var not in assign.group(0):
            break
        _quote, body, _whole, names = fparts
        literal = re.sub(r"\{(\w+)\}", "", body).strip()
        parts = [p for p in re.split(r"\s+", literal) if p]
        args = ", ".join([f'"{p}"' for p in parts] + [f"str({n})" for n in names])
        new_assign = f"{assign.group(1)}{var} = [{args}]"
        new_sink = sink_line.replace(f"({var}", f"({var}", 1)
        new_sink = re.sub(r"shell\s*=\s*True", "shell=False", new_sink)
        new_sink = re.sub(r"os\.system\s*\(\s*\w+\s*\)", f"subprocess.run({var}, shell=False, check=False)", new_sink)
        return [(probe, new_assign), (index, new_sink)]
    return None


def _fallback_traversal_patch(lines: list[str], index: int) -> Optional[list[tuple[int, str]]]:
    """Restrict a user supplied path to a file name inside the base directory."""
    sink_line = lines[index]
    if "open(" not in sink_line:
        return None
    if "os.path.basename" in sink_line or "Path(" in sink_line and ".resolve" in sink_line:
        return None
    tainted = re.findall(r"\b(\w+)\b", sink_line)
    candidates = [t for t in tainted if t not in {"open", "r", "w", "rb", "wb", "encoding", "errors", "replace", "as", "handle", "with", "str"}]
    if not candidates:
        return None
    var = candidates[0]
    base_dir = "os.path.dirname(os.path.abspath(__file__))"
    new_line = re.sub(
        r"open\s*\(\s*" + re.escape(var) + r"\b",
        f"open(os.path.join({base_dir}, os.path.basename(str({var})))",
        sink_line,
    )
    if new_line == sink_line:
        return None
    return [(index, new_line)]


def _php_connection_variable(lines: list[str]) -> str:
    """Find the variable that holds the mysqli connection."""
    for line in lines:
        match = re.search(r"(\$\w+)\s*=\s*mysqli_connect\s*\(", line)
        if match:
            return match.group(1)
    return "$conn"


def _fallback_php_sql_patch(lines: list[str], index: int, taint_var: str = "") -> Optional[list[tuple[int, str]]]:
    """Escape a user value that is interpolated into a PHP SQL string.

    ``"SELECT ... WHERE user = '$user'"`` becomes
    ``"SELECT ... WHERE user = '" . mysqli_real_escape_string($conn, $user) . "'"``
    which removes the injection without changing the query.
    """
    line = lines[index]
    if "mysqli" not in "\n".join(lines) and "->query" not in "\n".join(lines) and "->prepare" not in "\n".join(lines):
        return None
    if not re.search(r"['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)", line, re.IGNORECASE):
        return None

    variables = [taint_var] if taint_var else []
    if not variables:
        variables = re.findall(r"\$(\w+)", line)
    variables = [v for v in variables if v]

    connection = _php_connection_variable(lines)
    new_line = line
    for variable in variables:
        # only replace occurrences inside a string literal
        new_line = re.sub(
            r"(['\"])([^'\"]*)\$" + re.escape(variable) + r"([^'\"]*)\1",
            lambda m: (
                m.group(1) + m.group(2) + '" . mysqli_real_escape_string(' + connection + ", $" + variable + ") . '"
                + m.group(3) + m.group(1)
            ),
            new_line,
        )
    if new_line == line:
        return None
    return [(index, new_line)]


def _fallback_generic_patch(finding: CodeFinding) -> Optional[list[tuple[int, str]]]:
    """Simple, high confidence rewrites for a few well known patterns."""
    lines = _read_lines(finding.file)
    if not lines:
        return None
    index = finding.line - 1
    if index < 0 or index >= len(lines):
        return None
    line = lines[index]
    new_line = None

    if finding.vuln_class == VulnClass.DEBUG_MODE:
        new_line = re.sub(r"\b(DEBUG\s*=\s*|debug\s*=\s*)True\b", r"\1False", line)
    elif finding.vuln_class == VulnClass.WEAK_CRYPTO:
        if "md5" in line.lower():
            new_line = re.sub(r"\b(md5|MD5)\b", "sha256", line)
        elif "sha1" in line.lower():
            new_line = re.sub(r"\b(sha1|SHA1)\b", "sha256", line)
        elif "verify=False" in line:
            new_line = line.replace("verify=False", "verify=True")
    elif finding.vuln_class == VulnClass.INSECURE_RANDOM:
        new_line = re.sub(r"\brandom\.(randint|choice|random|randrange|sample)\s*\(", r"secrets.\1(", line)
        if new_line == line and "import random" in line:
            new_line = line
    elif finding.vuln_class == VulnClass.JWT_NONE_ALG:
        new_line = line.replace("verify=False", "verify=True")
    elif finding.vuln_class == VulnClass.INSECURE_DESERIALIZATION:
        new_line = re.sub(r"\b(pickle|cPickle|dill|marshal)\.loads?\s*\(", r"json.loads(", line)
    elif finding.vuln_class == VulnClass.PERMISSIVE_CORS:
        new_line = line.replace('"*"', '"https://your-trusted-origin.example"')
    elif finding.vuln_class == VulnClass.XXE:
        # Switch to defusedxml, which disables entity expansion by default.
        def _to_defused(match: re.Match) -> str:
            return f"defusedxml.{match.group(1)}.{match.group(2)}("

        new_line = re.sub(
            r"\b(?:xml\.dom\.)?(minidom)\.(parseString|parse)\s*\(",
            lambda m: f"defusedxml.{m.group(1)}.{m.group(2)}(",
            line,
        )
        new_line = re.sub(r"\b(etree)\.(parse|fromstring)\s*\(", lambda m: f"defusedxml.ElementTree.{m.group(2)}(", new_line)
        if new_line != line and "import defusedxml" not in "\n".join(lines):
            new_line = new_line + "  # add: import defusedxml.minidom"

    if not new_line or new_line == line:
        return None
    return [(index, new_line)]


def _fallback_patch(finding: CodeFinding, root: str) -> Optional[str]:
    lines = _read_lines(finding.file)
    if not lines:
        return None
    index = finding.line - 1
    if index < 0 or index >= len(lines):
        return None

    if finding.vuln_class == VulnClass.SQL_INJECTION:
        if finding.file.lower().endswith((".php", ".phtml")):
            edits = _fallback_php_sql_patch(lines, index, finding.taint_var)
        else:
            edits = _fallback_sql_patch(lines, index)
    elif finding.vuln_class == VulnClass.COMMAND_INJECTION:
        edits = _fallback_cmd_patch(lines, index)
    elif finding.vuln_class == VulnClass.PATH_TRAVERSAL:
        edits = _fallback_traversal_patch(lines, index)
    else:
        edits = _fallback_generic_patch(finding)

    if not edits:
        return None

    patched = list(lines)
    for line_no, new_text in edits:
        patched[line_no] = new_text
    try:
        rel_path = os.path.relpath(finding.file, root).replace("\\", "/")
    except ValueError:
        rel_path = finding.file.replace("\\", "/")
    return _make_diff(rel_path, lines, patched)


# ------------------------------------------------------------------ public
def generate_patch(
    finding: CorrelatedFinding,
    root: str,
    api_key: Optional[str] = None,
    provider: str = "openai",
    model: str = "gpt-4o-mini",
) -> PatchResult:
    """Produce a patch for a correlated finding, preferring the LLM when configured."""
    code_finding = finding.finding
    ref = f"{code_finding.file}:{code_finding.line}"

    if api_key:
        context = _build_context(code_finding, root)
        raw = _call_llm(code_finding, context, api_key, provider, model)
        cleaned = _clean_diff(raw or "")
        if cleaned.startswith("--- ") and "+++ " in cleaned:
            return PatchResult(
                finding_ref=ref,
                vuln_class=code_finding.vuln_class,
                diff=cleaned,
                explanation=(
                    f"AI generated fix for {code_finding.vuln_class.value} at {ref}. "
                    f"Remediation guidance: {finding.remediation_hint}"
                ),
                source=f"llm:{provider}/{model}",
                confidence=0.8,
            )

    diff = _fallback_patch(code_finding, root)
    if diff:
        return PatchResult(
            finding_ref=ref,
            vuln_class=code_finding.vuln_class,
            diff=diff,
            explanation=(
                f"Offline heuristic fix for {code_finding.vuln_class.value} at {ref}. "
                f"Remediation guidance: {finding.remediation_hint} "
                "Review the diff before applying."
            ),
            source="fallback",
            confidence=0.55,
        )

    return PatchResult(
        finding_ref=ref,
        vuln_class=code_finding.vuln_class,
        diff="",
        explanation=(
            f"No automatic patch could be generated for {code_finding.vuln_class.value} at {ref}. "
            f"Manual guidance: {finding.remediation_hint}"
        ),
        source="none",
        confidence=0.2,
    )


# --------------------------------------------------------------- validation
def validate_patch(patch: PatchResult, repo_root: str) -> tuple[bool, str]:
    """Check whether a unified diff applies cleanly using `git apply --check`."""
    if not patch.diff.strip():
        return False, "empty diff"
    if not shutil.which("git"):
        return False, "git not available, skipping validation"
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False, encoding="utf-8") as fh:
        fh.write(patch.diff)
        tmp_path = fh.name
    try:
        proc = subprocess.run(
            ["git", "apply", "--check", "--verbose", tmp_path],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        message = (proc.stderr or proc.stdout).strip()
        return proc.returncode == 0, message
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def write_patch_file(patches: list[PatchResult], output_path: str) -> str:
    """Write all patches into a single .patch file usable with `git apply`.

    The line ending of the target file is mirrored so that `git apply` can
    match the context lines on Windows checkouts (CRLF) as well as on
    Unix checkouts (LF).
    """
    parts = []
    newline = "\n"
    for patch in patches:
        if not patch.diff.strip():
            continue
        parts.append(patch.diff.strip())
        if newline == "\n":
            file_path = patch.finding_ref.rsplit(":", 1)[0]
            try:
                with open(file_path, "rb") as fh:
                    if b"\r\n" in fh.read(4096):
                        newline = "\r\n"
            except OSError:
                pass
    content = ("\n\n".join(parts) + "\n") if parts else ""
    with open(output_path, "w", encoding="utf-8", newline=newline) as fh:
        fh.write(content)
    return output_path
