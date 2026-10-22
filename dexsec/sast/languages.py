"""Language definitions for the static analyser.

Every language is described declaratively so new languages can be added
without touching the engine:

* ``sources``     – regexes that recognise user controlled input
* ``sinks``       – regexes that recognise a dangerous operation
* ``interpolation`` – how a tainted value is embedded into a string
* ``routes``      – how an HTTP endpoint is declared
* ``params``      – how request parameters are read

The engine in ``scanner.py`` uses these tables, so PHP, Java, Go, C#, Ruby and
JavaScript/TypeScript are all handled by the same code path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SinkRule:
    """A dangerous operation and the vulnerability class it causes."""

    vuln_class: str
    severity: str
    cwe: str
    description: str
    pattern: str
    confidence: float = 0.6
    # Sinks that are only dangerous when the tainted value is interpolated
    # into a string (SQL, XSS) versus sinks that are dangerous with any
    # tainted argument (command execution, file access).
    needs_interpolation: bool = False
    # Receivers that make a generic method name dangerous ("query", "exec").
    receivers: tuple[str, ...] = ()
    # Method names that are never dangerous with that receiver.
    safe_receivers: tuple[str, ...] = ()


@dataclass
class RouteRule:
    """How a language declares an HTTP endpoint."""

    framework: str
    pattern: str
    method_from_group: str = "method"
    path_from_group: str = "path"
    default_method: str = "GET"
    # Group that holds the HTTP verb when the pattern does not contain one.
    verb_group: str = ""


@dataclass
class LanguageSpec:
    name: str
    extensions: tuple[str, ...]
    sources: list[str] = field(default_factory=list)
    sinks: list[SinkRule] = field(default_factory=list)
    routes: list[RouteRule] = field(default_factory=list)
    # Regexes that find "a tainted value is embedded in a string" for this
    # language, used to decide whether a string sink is really injectable.
    interpolations: list[str] = field(default_factory=list)
    # Extra patterns that mark a variable as user controlled.
    param_readers: list[str] = field(default_factory=list)
    # Regular expression to extract the names of the request parameters.
    param_names: str = r""


PHP = LanguageSpec(
    name="php",
    extensions=(".php", ".phtml", ".php5", ".inc"),
    sources=[
        r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_FILES\b", r"\$_COOKIE\b",
        r"\$_SERVER\s*\[\s*[\"'](?:HTTP_|QUERY_STRING|REQUEST_URI)",
        r"\bfilter_input\s*\(",
        r"\bfilter_input_array\s*\(",
        r"\bphp:\s*//input\b",
        r"\bgetallheaders\s*\(",
    ],
    param_readers=[
        r"\$_(?:GET|POST|REQUEST)\s*\[\s*[\"'](?P<name>[A-Za-z0-9_]+)[\"']",
    ],
    param_names=r"\$_(?:GET|POST|REQUEST)\s*\[\s*[\"']([A-Za-z0-9_]+)[\"']",
    interpolations=[
        # "text $var more" and heredoc {$var}
        r"\"[^\"\n]*\$[A-Za-z_]\w*",
        r"\"[^\"\n]*\{\$[A-Za-z_]\w*\}",
    ],
    sinks=[
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "SQL query built from user controlled input.",
                 r"\bmysqli_query\s*\(", confidence=0.8, needs_interpolation=True,
                 receivers=("mysqli_query",)),
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "SQL query built from user controlled input.",
                 r"\bmysqli_multi_query\s*\(", confidence=0.8, needs_interpolation=True),
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "PDO query built from user controlled input.",
                 r"->\s*(?:query|exec|prepare)\s*\(", confidence=0.75, needs_interpolation=True,
                 receivers=("pdo", "stmt", "db", "conn", "connection", "pdoStatement")),
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "SQL query built from user controlled input.",
                 r"->\s*prepare\s*\(", confidence=0.7, needs_interpolation=True),
        SinkRule("COMMAND_INJECTION", "CRITICAL", "CWE-78",
                 "User input reaches a shell command execution function.",
                 r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", confidence=0.8),
        SinkRule("CODE_INJECTION", "CRITICAL", "CWE-94",
                 "User input reaches eval() or similar.",
                 r"\beval\s*\(", confidence=0.8),
        SinkRule("CODE_INJECTION", "CRITICAL", "CWE-94",
                 "User input reaches a dynamic include.",
                 r"\b(?:assert|create_function)\s*\(", confidence=0.6),
        SinkRule("PATH_TRAVERSAL", "HIGH", "CWE-22",
                 "User input reaches a file path operation.",
                 r"\b(?:file_get_contents|fopen|readfile|file|fread|copy|unlink|file_put_contents)\s*\(",
                 confidence=0.7),
        SinkRule("PATH_TRAVERSAL", "HIGH", "CWE-22",
                 "User input reaches a dynamic include (local file inclusion).",
                 r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$", confidence=0.75),
        SinkRule("SSRF", "HIGH", "CWE-918",
                 "Outbound request with a user controlled URL.",
                 r"\b(?:curl_exec|curl_init|file_get_contents|fopen)\s*\(", confidence=0.5,
                 receivers=("curl_init",)),
        SinkRule("INSECURE_DESERIALIZATION", "HIGH", "CWE-502",
                 "Untrusted data is deserialised with unserialize().",
                 r"\bunserialize\s*\(", confidence=0.8),
        SinkRule("INSECURE_DESERIALIZATION", "HIGH", "CWE-502",
                 "extract() on request data allows variable injection.",
                 r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)", confidence=0.85),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is printed into the response without escaping.",
                 r"\b(?:echo|print)\s+[^;]{0,120}\$", confidence=0.5),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is printed into an HTML attribute without escaping.",
                 r"\b(?:printf|print_r)\s*\(\s*[^)]{0,120}\$", confidence=0.45),
        SinkRule("INSECURE_COOKIE", "MEDIUM", "CWE-1004",
                 "Session cookie without HttpOnly/Secure/SameSite.",
                 r"\bsetcookie\s*\(", confidence=0.5),
        SinkRule("DEBUG_MODE", "MEDIUM", "CWE-489",
                 "Debug output enabled in production.",
                 r"\b(?:display_errors|error_reporting)\s*\(\s*(?:E_ALL|[-+]?\s*\d*E_ALL)",
                 confidence=0.6),
        SinkRule("WEAK_CRYPTO", "MEDIUM", "CWE-327",
                 "Weak hash used for passwords.",
                 r"\b(?:md5|sha1)\s*\(", confidence=0.55),
        SinkRule("MISSING_AUTH_CHECK", "MEDIUM", "CWE-306",
                 "State changing page without any session check.",
                 r"\bmove_uploaded_file\s*\(", confidence=0.4),
    ],
    routes=[
        RouteRule("PHP", r"^\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\"'](?P<path>[^\"']+)[\"']",
                  method_from_group="", path_from_group="path", default_method="GET"),
    ],
)

JAVASCRIPT = LanguageSpec(
    name="javascript",
    extensions=(".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte"),
    sources=[
        r"\breq(?:uest)?\.(?:query|body|params|queryParams|headers|cookies|get|post|path)\b",
        r"\bctx\.(?:query|params|request\.body|queryString|path)\b",
        r"\bthis\.(?:query|body|params)\b",
        r"\bwindow\.location\b",
        r"\bdocument\.(?:URL|location|referrer)\b",
        r"\bprocess\.argv\b",
    ],
    param_readers=[
        r"\b(?:req|request)\.(?:query|body|params)\s*(?:\.|\[\s*[\"'])(?P<name>[A-Za-z0-9_]+)",
    ],
    param_names=r"\b(?:req|request)\.(?:query|body|params)\s*(?:\.|\[\s*[\"'])([A-Za-z0-9_]+)",
    interpolations=[
        r"`[^`]*\$\{[^}]+\}[^`]*`",
        r"\"[^\"\n]*\"\s*\+\s*[A-Za-z_$][\w$]*",
    ],
    sinks=[
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "SQL query built from user controlled input.",
                 r"\.(?:query|execute|raw|unsafe)\s*\(", confidence=0.75, needs_interpolation=True,
                 receivers=("knex", "sequelize", "query", "db", "client", "connection", "pool", "raw")),
        SinkRule("COMMAND_INJECTION", "CRITICAL", "CWE-78",
                 "User input reaches a child process execution.",
                 r"\b(?:exec|execSync|spawn|spawnSync|fork)\s*\(", confidence=0.8,
                 receivers=("child_process",)),
        SinkRule("CODE_INJECTION", "CRITICAL", "CWE-94",
                 "User input reaches eval() or the Function constructor.",
                 r"\b(?:eval|Function)\s*\(", confidence=0.8),
        SinkRule("PATH_TRAVERSAL", "HIGH", "CWE-22",
                 "User input reaches a file path operation.",
                 r"\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|sendfile|download|unlink|createWriteStream)\s*\(",
                 confidence=0.7),
        SinkRule("SSRF", "HIGH", "CWE-918",
                 "Outbound request with a user controlled URL.",
                 r"\b(?:get|post|put|delete|head|request)\s*\(", confidence=0.5,
                 receivers=("axios", "http", "https", "fetch", "request", "superagent", "needle")),
        SinkRule("INSECURE_DESERIALIZATION", "HIGH", "CWE-502",
                 "Untrusted data is deserialised.",
                 r"\b(?:unserialize|deserialize|node-serialize)\b", confidence=0.6),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is written into the DOM without escaping.",
                 r"\.(?:innerHTML|outerHTML)\s*=", confidence=0.6),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is written into the DOM without escaping.",
                 r"\b(?:document\.write|insertAdjacentHTML)\s*\(", confidence=0.6),
        SinkRule("MASS_ASSIGNMENT", "HIGH", "CWE-915",
                 "Request body is copied into an object as-is.",
                 r"\bObject\.assign\s*\(", confidence=0.6),
        SinkRule("INSECURE_RANDOM", "MEDIUM", "CWE-330",
                 "Non-cryptographic randomness used for security tokens.",
                 r"\bMath\.random\s*\(", confidence=0.5),
        SinkRule("JWT_NONE_ALG", "CRITICAL", "CWE-347",
                 "JWT decoded without verifying the signature.",
                 r"\bjwt\.decode\s*\(", confidence=0.7),
    ],
    routes=[
        RouteRule("Express", r"\b(?:app|router)\.(?P<method>get|post|put|patch|delete)\s*\(\s*[\"'`](?P<path>[^\"'`]+)"),
        RouteRule("Next.js", r"export\s+(?:async\s+)?function\s+(?P<method>GET|POST|PUT|PATCH|DELETE)\s*\(",
                  method_from_group="method", path_from_group="", default_method="GET"),
        RouteRule("Fastify", r"\b(?:app|fastify|server)\.(?P<method>get|post|put|patch|delete)\s*\(\s*[\"'`](?P<path>[^\"'`]+)"),
    ],
)

JAVA = LanguageSpec(
    name="java",
    extensions=(".java", ".kt", ".kts"),
    sources=[
        r"\brequest\.getParameter\s*\(", r"\brequest\.getHeader\s*\(",
        r"\brequest\.getQueryString\s*\(", r"\bServletRequest\b",
        r"\bHttpServletRequest\b", r"\bgetInputStream\s*\(",
        r"\bMultiValueMap\b", r"\b@RequestParam\b", r"\b@PathVariable\b",
        r"\b@RequestBody\b", r"\b@RequestHeader\b",
    ],
    param_readers=[
        r"getParameter\s*\(\s*\"(?P<name>[A-Za-z0-9_]+)\"",
    ],
    param_names=r"getParameter\s*\(\s*\"([A-Za-z0-9_]+)\"",
    interpolations=[
        r"\"[^\"\n]*\"\s*\+\s*[A-Za-z_]\w*",
        r"String\.format\s*\(",
    ],
    sinks=[
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "SQL statement built from user controlled input.",
                 r"\.(?:executeQuery|executeUpdate|execute)\s*\(", confidence=0.8, needs_interpolation=True,
                 receivers=("statement", "stmt", "conn", "connection", "ps", "preparedstatement")),
        SinkRule("COMMAND_INJECTION", "CRITICAL", "CWE-78",
                 "User input reaches a process execution.",
                 r"\bRuntime\.getRuntime\s*\(\s*\)\.exec\s*\(", confidence=0.85),
        SinkRule("PATH_TRAVERSAL", "HIGH", "CWE-22",
                 "User input reaches a file path operation.",
                 r"\bnew\s+File\s*\(", confidence=0.7),
        SinkRule("PATH_TRAVERSAL", "HIGH", "CWE-22",
                 "User input reaches a file path operation.",
                 r"\bFiles\.(?:readAllBytes|readString|newInputStream|newOutputStream|delete|copy|write)\s*\(",
                 confidence=0.7),
        SinkRule("SSRF", "HIGH", "CWE-918",
                 "Outbound request with a user controlled URL.",
                 r"\bnew\s+URL\s*\(", confidence=0.6),
        SinkRule("INSECURE_DESERIALIZATION", "HIGH", "CWE-502",
                 "Untrusted data is deserialised.",
                 r"\bnew\s+ObjectInputStream\s*\(", confidence=0.8),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is written into the response without escaping.",
                 r"\b(?:getWriter|getOutputStream)\s*\(\s*\)\s*\.\s*(?:print|write|append)\s*\(",
                 confidence=0.5),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is concatenated into a response string.",
                 r"\breturn\s+[^;]{0,120}\+", confidence=0.4, needs_interpolation=True),
    ],
    routes=[
        RouteRule("Spring", r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?[\"'](?P<path>[^\"']*)",
                  method_from_group="", path_from_group="path", default_method="GET"),
        RouteRule("JAX-RS", r"@(?:GET|POST|PUT|PATCH|DELETE)\s*\n?\s*(?:@Path\s*\(\s*)?[\"'](?P<path>[^\"']*)",
                  method_from_group="", path_from_group="path", default_method="GET"),
    ],
)

GO = LanguageSpec(
    name="go",
    extensions=(".go",),
    sources=[
        r"\br\.URL\.Query\s*\(\s*\)\s*\.Get\s*\(", r"\br\.FormValue\s*\(",
        r"\br\.PostFormValue\s*\(", r"\br\.Header\.Get\s*\(", r"\br\.Body\b",
        r"\bjson\.NewDecoder\s*\(", r"\bc\.Param\s*\(", r"\bc\.Query\s*\(",
    ],
    param_readers=[
        r"Query\s*\(\s*\)\s*\.Get\s*\(\s*\"(?P<name>[A-Za-z0-9_]+)\"",
        r"FormValue\s*\(\s*\"(?P<name>[A-Za-z0-9_]+)\"",
    ],
    param_names=r"(?:Query\s*\(\s*\)\s*\.Get|FormValue)\s*\(\s*\"([A-Za-z0-9_]+)\"",
    interpolations=[
        r"fmt\.Sprintf\s*\(", r"\"[^\"\n]*\"\s*\+\s*[A-Za-z_]\w*",
    ],
    sinks=[
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "SQL query built from user controlled input.",
                 r"\b(?:db|tx|conn)\.(?:Query|QueryRow|Exec)\s*\(", confidence=0.8, needs_interpolation=True),
        SinkRule("COMMAND_INJECTION", "CRITICAL", "CWE-78",
                 "User input reaches an exec.Command call.",
                 r"\bexec\.Command(?:Context)?\s*\(", confidence=0.8),
        SinkRule("PATH_TRAVERSAL", "HIGH", "CWE-22",
                 "User input reaches a file path operation.",
                 r"\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Remove|RemoveAll)\s*\(", confidence=0.7),
        SinkRule("SSRF", "HIGH", "CWE-918",
                 "Outbound request with a user controlled URL.",
                 r"\bhttp\.(?:Get|Post|NewRequest)\s*\(", confidence=0.7),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is written into the response without escaping.",
                 r"\b(?:w|r)\.Write\s*\(\s*fmt\.Sprintf", confidence=0.5),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is written into the response without escaping.",
                 r"\b(?:fmt\.Fprintf|fmt\.Fprint|io\.WriteString)\s*\(", confidence=0.45,
                 needs_interpolation=True),
    ],
    routes=[
        RouteRule("Go", r"\b(?:mux|router|app)\.(?:HandleFunc|Handle|Get|Post|Put|Delete)\s*\(\s*\"(?P<path>[^\"]+)\"",
                  method_from_group="", path_from_group="path", default_method="GET"),
    ],
)

CSHARP = LanguageSpec(
    name="csharp",
    extensions=(".cs",),
    sources=[
        r"\bRequest\.(?:Query|Form|Params|Body|Headers|Cookies)\b",
        r"\bHttpContext\.Request\b", r"\bIFormCollection\b", r"\bFromBody\b",
        r"\bFromQuery\b", r"\bFromRoute\b",
    ],
    param_readers=[
        r"Request\.Query\s*\[\s*\"(?P<name>[A-Za-z0-9_]+)\"",
        r"Request\.Query\.TryGetValue\s*\(\s*\"(?P<name>[A-Za-z0-9_]+)\"",
    ],
    param_names=r"Request\.Query\s*\[\s*\"([A-Za-z0-9_]+)\"",
    interpolations=[
        r"\$\"[^\"]*\{[^}]+\}", r"string\.Format\s*\(", r"\"[^\"\n]*\"\s*\+\s*[A-Za-z_]\w*",
    ],
    sinks=[
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "SQL command built from user controlled input.",
                 r"new\s+SqlCommand\s*\(", confidence=0.85, needs_interpolation=True),
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "Query built with a string that contains user input.",
                 r"\.(?:ExecuteScalar|ExecuteNonQuery|ExecuteReader)\s*\(", confidence=0.6),
        SinkRule("COMMAND_INJECTION", "CRITICAL", "CWE-78",
                 "User input reaches a process execution.",
                 r"\bProcess\.Start\s*\(", confidence=0.8),
        SinkRule("PATH_TRAVERSAL", "HIGH", "CWE-22",
                 "User input reaches a file path operation.",
                 r"\bFile\.(?:ReadAllText|ReadAllBytes|ReadAllLines|WriteAllText|Open|Copy|Delete)\s*\(",
                 confidence=0.7),
        SinkRule("SSRF", "HIGH", "CWE-918",
                 "Outbound request with a user controlled URL.",
                 r"\bnew\s+HttpClient\s*\(", confidence=0.4),
        SinkRule("INSECURE_DESERIALIZATION", "HIGH", "CWE-502",
                 "Untrusted data is deserialised with a binary formatter.",
                 r"\bBinaryFormatter\s*\(", confidence=0.85),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is written into the response without encoding.",
                 r"\bResponse\.Write\s*\(", confidence=0.5),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is written into the response without encoding.",
                 r"\b(?:Content|WriteLiteral)\s*\(", confidence=0.35, needs_interpolation=True),
    ],
    routes=[
        RouteRule("ASP.NET", r"\[Http(?P<method>Get|Post|Put|Patch|Delete)\b[^\]]*\]\s*(?:\[[^\]]*\]\s*)*"
                             r"(?:public|private|protected)?[^=]*\s+(?P<name>\w+)\s*\(",
                  method_from_group="method", path_from_group="", default_method="GET"),
    ],
)

RUBY = LanguageSpec(
    name="ruby",
    extensions=(".rb",),
    sources=[
        r"\bparams\s*\[", r"\bparams\.fetch\b", r"\brequest\.(?:params|cookies|headers|body|ip|path)\b",
        r"\bcookies\s*\[",
    ],
    param_readers=[
        r"params\s*\[\s*[:\"'](?P<name>[A-Za-z0-9_]+)",
    ],
    param_names=r"params\s*\[\s*[:\"']([A-Za-z0-9_]+)",
    interpolations=[
        r"\"[^\"\n]*#\{[^}]+\}", r"\"[^\"\n]*\"\s*\+\s*[A-Za-z_@]\w*",
    ],
    sinks=[
        SinkRule("SQL_INJECTION", "CRITICAL", "CWE-89",
                 "SQL fragment built from user controlled input.",
                 r"\.(?:where|having|order|group|select)\s*\(\s*[\"']", confidence=0.8, needs_interpolation=True),
        SinkRule("COMMAND_INJECTION", "CRITICAL", "CWE-78",
                 "User input reaches a shell command.",
                 r"\b(?:system|exec|spawn)\s*[\(\s]", confidence=0.8),
        SinkRule("PATH_TRAVERSAL", "HIGH", "CWE-22",
                 "User input reaches a file path operation.",
                 r"\b(?:File\.(?:read|open|write|delete)|IO\.(?:read|write))\s*\(", confidence=0.7),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is rendered without escaping.",
                 r"\braw\s*\(", confidence=0.6),
        SinkRule("XSS", "MEDIUM", "CWE-79",
                 "User input is rendered as HTML without escaping.",
                 r"\brender\b[^\n]{0,80}#\{", confidence=0.5, needs_interpolation=True),
        SinkRule("CODE_INJECTION", "CRITICAL", "CWE-94",
                 "User input reaches eval.",
                 r"\b(?:eval|instance_eval|class_eval)\b", confidence=0.7),
    ],
    routes=[
        RouteRule("Rails", r"\b(?:get|post|put|patch|delete)\s+[\"'](?P<path>[^\"']+)",
                  method_from_group="", path_from_group="path", default_method="GET"),
    ],
)

LANGUAGES: list[LanguageSpec] = [PHP, JAVASCRIPT, JAVA, GO, CSHARP, RUBY]

EXTENSION_MAP: dict[str, LanguageSpec] = {}
for _spec in LANGUAGES:
    for _ext in _spec.extensions:
        EXTENSION_MAP[_ext] = _spec


def detect_language(path: str) -> LanguageSpec | None:
    """Return the language spec for a file path (None for unsupported files)."""
    lowered = path.lower()
    for extension, spec in EXTENSION_MAP.items():
        if lowered.endswith(extension):
            return spec
    return None


def statement_of(text: str) -> str:
    """Return a normalised single statement for the given source line."""
    return re.sub(r"\s+", " ", text).strip()


def tainted_variables(content: str, spec: LanguageSpec) -> list[str]:
    """Variables that receive user controlled data.

    Handles the different assignment styles of the supported languages:
    ``x = ...`` (Python/PHP/JS), ``Type x = ...`` (Java/C#) and
    ``x := ...`` (Go).
    """
    result: list[str] = []
    source_alt = "|".join(spec.sources)
    assignment = re.compile(
        r"^\s*(?:.*\s)?(?P<name>[A-Za-z_$][\w$]*)\s*(?::=|=)\s*(?P<value>.+?)\s*;?\s*$"
    )
    for line in content.splitlines():
        match = assignment.match(line)
        if not match:
            continue
        value = match.group("value")
        if not re.search(source_alt, value, re.IGNORECASE):
            continue
        name = match.group("name").split(".")[-1].split("[")[0].lstrip("$")
        if not name or name in {"return", "if", "else", "case", "new", "echo", "print"}:
            continue
        result.append(name)
    return list(dict.fromkeys(result))
