"""Detection rules: source patterns, sink patterns, and route patterns.

Design notes
------------
The scanner is intentionally regex + heuristic based rather than a full
taint-tracking engine. It is fast, dependency-free and tolerant of
polyglot codebases, which is what a developer-facing CLI needs.
Each rule carries a confidence score that later gets adjusted by the
DAST verification phase.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class SinkRule:
    vuln_class: str
    severity: str
    cwe: str
    patterns: list[str]
    description: str
    confidence: float = 0.6
    require_taint: bool = True
    taint_hints: list[str] = field(default_factory=list)


# Sources of user-controlled data.
TAINT_SOURCES = [
    r"req\.(query|params|body|form|args|cookies|headers|json)",
    r"request\.(query_params|json|body|headers|cookies|path_params)",
    r"request\.GET|request\.POST|request\.args|request\.form|request\.json",
    r"req\.body|req\.query",
    r"req\.params\[|req\.query\[|req\.body\[",
    r"req\.get\(|req\.post\(",
    r"params\[|query\[|body\[",
    r"args\.get\(|args\[",
    r"params\.get\(",
    r"parse_qs\(|getlist\(",
    r"getParameter|getParameterValues",
    r"ctx\.(query|params|request\.body|queryString|path)",
    r"c\.req\.(query|params|body)",
]

# Generic container names that are too common to be treated as "the tainted
# value" on their own.  They only count as a source when the expression that
# produces them is a request object.
GENERIC_TAINT_NAMES = {
    "body", "params", "param", "query", "data", "content", "contents", "result",
    "results", "response", "responses", "values", "value", "payload", "item",
    "items", "obj", "object", "message", "msg", "text", "raw", "input", "output",
    "config", "options", "opts", "info", "env", "headers", "header", "cookie",
    "cookies", "session", "db", "conn", "connection", "payloads", "request",
    "req", "args", "form", "json", "fields", "field", "context", "ctx",
}

# Sink rules ordered from highest to lowest confidence.
SINK_RULES: list[SinkRule] = [
    SinkRule(
        vuln_class="SQL_INJECTION",
        severity="CRITICAL",
        cwe="CWE-89",
        confidence=0.75,
        description="SQL query built by concatenating or formatting user input.",
        patterns=[
            r"""(?i)(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;"']{0,300}?(?:%s|\+\s*\w|\.format\(|f["'])""",
            r"""(?i)(?:execute|executemany|query|raw|cursor\.execute)\s*\(\s*(?:f["']|["'][^"']*["']\s*%|["'][^"']*["']\s*\+\s*)""",
            r"""(?i)["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*(?:%|\+|\.format)""",
            r"""(?i)f["'][^"']*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"']*["']""",
            r"""(?i)`[^`]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^`]*\$\{[^}]*\}[^`]*`""",
            r"""(?i)`[^`]*\$\{[^}]*\}[^`]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^`]*`""",
            r"""(?i)["'][^"']*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"']*["']\s*\+""",
        ],
        taint_hints=[
            r"""(?i)["'][^"']*\{[^}]{0,80}\}[^"']*["']""",
            r"""(?i)["'][^"']*(?:%s|\{)[^"']*["']""",
        ],
    ),
    SinkRule(
        vuln_class="COMMAND_INJECTION",
        severity="CRITICAL",
        cwe="CWE-78",
        confidence=0.8,
        description="User input passed into a shell or process execution API.",
        patterns=[
            r"\bos\.(system|popen)\s*\(",
            r"\bsubprocess\.(run|call|Popen|check_output|check_call)\s*\(",
            r"\bexec\s*\(",
            r"\beval\s*\(",
            r"\bchild_process\.(exec|execSync|spawn|spawnSync)\s*\(",
            r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
            r"\bProcessBuilder\b",
            r"\bpopen\s*\(",
        ],
        taint_hints=[r"shell\s*=\s*True"],
    ),
    SinkRule(
        vuln_class="PATH_TRAVERSAL",
        severity="HIGH",
        cwe="CWE-22",
        confidence=0.65,
        description="File path built from user input without normalization.",
        patterns=[
            r"\bopen\s*\(",
            r"\bos\.(remove|unlink|rmdir|makedirs)\s*\(",
            r"\bpathlib\.Path\s*\(",
            r"\bfs\.(readFile|readFileSync|unlinkSync|createReadStream|writeFile)\s*\(",
            r"\bres\.(sendFile|sendfile|download)\s*\(",
            r"\bFile\.read_bytes|File\.open",
        ],
    ),
    SinkRule(
        vuln_class="SSRF",
        severity="HIGH",
        cwe="CWE-918",
        confidence=0.65,
        description="Outbound HTTP request with a user-controlled URL.",
        patterns=[
            r"\brequests\.(get|post|put|delete|head|request)\s*\(",
            r"\bhttpx\.(get|post|put|delete)\s*\(",
            r"\burllib\.request\.urlopen\s*\(",
            r"\burlopen\s*\(",
            r"\bfetch\s*\(",
            r"\baxios\.(get|post|put|delete)\s*\(",
            r"\bhttp\.Get\s*\(",
        ],
    ),
    SinkRule(
        vuln_class="HARDCODE_SECRET",
        severity="MEDIUM",
        cwe="CWE-798",
        confidence=0.85,
        require_taint=False,
        description="Potential hardcoded credential in source code.",
        patterns=[
            r"""(?i)(?:api[_-]?key|secret[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']""",
            r"""(?i)-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----""",
            r"""(?i)(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})""",
        ],
    ),
    SinkRule(
        vuln_class="XSS",
        severity="MEDIUM",
        cwe="CWE-79",
        confidence=0.5,
        description="User input reflected into an HTML response without escaping.",
        patterns=[
            r"""(?i)render_template_string\s*\(""",
            r"""(?i)HttpResponse\s*\(\s*f?["'][^"']*\{""",
            r"""(?i)innerHTML\s*=""",
            r"""(?i)document\.write\s*\(""",
            r"""(?i)\|\s*safe\b""",
        ],
    ),
    # ---------------------------------------------------------- new coverage
    SinkRule(
        vuln_class="INSECURE_DESERIALIZATION",
        severity="HIGH",
        cwe="CWE-502",
        confidence=0.7,
        description="Untrusted data deserialised with a native/object deserialiser can lead to RCE.",
        patterns=[
            r"\bpickle\.loads?\s*\(",
            r"\b_cPickle\.loads?\s*\(",
            r"\bdill\.loads?\s*\(",
            r"\bmarshal\.loads?\s*\(",
            r"\byaml\.load\s*\((?![^)]*Safe)",
            r"\byaml\.unsafe_load\s*\(",
            r"\byaml\.full_load\s*\(",
            r"\bnode-serialize|unserialize\s*\(",
            r"\bObjectInputStream\s*\(",
            r"\bjsonpickle\.decode\s*\(",
        ],
    ),
    SinkRule(
        vuln_class="CODE_INJECTION",
        severity="CRITICAL",
        cwe="CWE-94",
        confidence=0.7,
        description="Dynamic code evaluation of untrusted input allows arbitrary code execution.",
        patterns=[
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\bcompile\s*\([^)]*,\s*[\"']exec[\"']",
            r"\bFunction\s*\(\s*[\"']",
            r"\bnew\s+Function\s*\(",
            r"\bsetTimeout\s*\(\s*[\"']",
            r"\bimportlib\.import_module\s*\(",
            r"\b__import__\s*\(",
        ],
    ),
    SinkRule(
        vuln_class="TEMPLATE_INJECTION",
        severity="CRITICAL",
        cwe="CWE-1336",
        confidence=0.65,
        description="Server-side template is rendered from user input (SSTI).",
        patterns=[
            r"""render_template_string\s*\(""",
            r"""(?i)Environment\s*\([^)]*\)\.from_string\s*\(""",
            r"""(?i)Template\s*\(\s*(?:f["']|request|req\.)""",
            r"""(?i)template\.render\s*\(\s*(?:f["']|request|req\.)""",
        ],
    ),
    SinkRule(
        vuln_class="XXE",
        severity="HIGH",
        cwe="CWE-611",
        confidence=0.6,
        require_taint=False,
        description="XML is parsed without disabling external entity resolution.",
        patterns=[
            r"\betree\.(?:fromstring|parse|XMLParser|XMLPullParser)\s*\(",
            r"\bminidom\.parse\w*\s*\(",
            r"\bxml\.sax\.(?:parse|make_parser)\s*\(",
            r"\bxml\.dom\.minidom\.parse\w*\s*\(",
            r"\blxml\.etree\.(?:parse|fromstring|XMLParser)\s*\(",
            r"\bDocumentBuilderFactory\b",
        ],
    ),
    SinkRule(
        vuln_class="NOSQL_INJECTION",
        severity="HIGH",
        cwe="CWE-943",
        confidence=0.55,
        description="Request data is passed straight into a NoSQL query, allowing operator injection.",
        patterns=[
            r"""\$where\b""",
            r"""(?i)\.find(?:_one)?\s*\(\s*(?:request|req)\.""",
            r"""(?i)\.aggregate\s*\(\s*(?:request|req)\.""",
            r"""(?i)find\w*\s*\(\s*json\.loads\s*\(""",
            r"""(?i)\.(?:update|delete)(?:_one|_many)?\s*\(\s*(?:request|req)\.""",
        ],
    ),
    SinkRule(
        vuln_class="WEAK_CRYPTO",
        severity="MEDIUM",
        cwe="CWE-327",
        confidence=0.6,
        description="Weak hash/cipher or disabled TLS verification is used.",
        patterns=[
            r"\bhashlib\.(md5|sha1)\s*\(",
            r"\bcreateHash\s*\(\s*[\"']?(md5|sha1)",
            r"\bCrypto\.Cipher\.(DES|ARC4|RC4|Blowfish)\b",
            r"\bDES\.new\s*\(",
            r"\bverify\s*=\s*False\b",
            r"\b_CERT_NONE\b",
            r"\bcheck_hostname\s*=\s*False\b",
            r"\bcreate_unverified_context\s*\(",
            r"\bMD5\b|\bSHA1\b",
        ],
    ),
    SinkRule(
        vuln_class="INSECURE_RANDOM",
        severity="MEDIUM",
        cwe="CWE-330",
        confidence=0.55,
        description="Non-cryptographic randomness is used to build security tokens.",
        patterns=[
            r"\brandom\.(?:randint|choice|random|randrange|sample)\s*\(",
            r"\bMath\.random\s*\(",
            r"""\brandom\.(?:randint|choice|random)\s*\([^\)]*\)\s*#?\s*.*(?:token|secret|password|key)""",
        ],
    ),
    SinkRule(
        vuln_class="JWT_NONE_ALG",
        severity="CRITICAL",
        cwe="CWE-347",
        confidence=0.7,
        description="JWT signature verification is disabled or the 'none' algorithm is accepted.",
        patterns=[
            r"""jwt\.decode\s*\([^)]*verify\s*=\s*False""",
            r"""verify_signature\s*=\s*False""",
            r"""algorithms?\s*=\s*\[\s*["']none["']""",
            r"""jwt\.decode\s*\([^)]*verify\s*=\s*False""",
            r"""jwt\.decode\s*\(\s*[\w\.\[\]"'\s]{1,60}\s*\)""",
            r"""jwt\.verify\s*\(\s*[^,]+,\s*["'][^"']+["']\s*,\s*\{\s*\}""",
        ],
    ),
    SinkRule(
        vuln_class="DEBUG_MODE",
        severity="HIGH",
        cwe="CWE-489",
        confidence=0.75,
        require_taint=False,
        description="Debug mode is enabled and leaks stack traces / interactive console.",
        patterns=[
            r"\bDEBUG\s*=\s*True\b",
            r"\bdebug\s*=\s*True\b",
            r"""app\.run\s*\([^)]*debug\s*=\s*True""",
            r"""run\s*\([^)]*debug\s*=\s*True""",
            r"""app\.run\s*\([^)]*debug\s*=\s*True""",
        ],
    ),
    SinkRule(
        vuln_class="OPEN_REDIRECT",
        severity="MEDIUM",
        cwe="CWE-601",
        confidence=0.6,
        description="User input controls a redirect target, enabling phishing redirects.",
        patterns=[
            r"""(?i)redirect\s*\(\s*(?:f["'][^"']*\{|request\.|req\.|url_for|next_url)""",
            r"""(?i)RedirectResponse\s*\(\s*(?:f["'][^"']*\{|request\.|req\.)""",
            r"""(?i)res\.redirect\s*\(\s*(?:f?["'][^"']*\{|`[^`]*\$\{|req\.|request\.)""",
            r"""(?i)response\.redirect\s*\(\s*(?:f?["'][^"']*\{|`[^`]*\$\{|req\.|request\.)""",
            r"""(?i)http\.redirect\s*\(\s*(?:f?["'][^"']*\{|req\.|request\.)""",
        ],
    ),
    SinkRule(
        vuln_class="MASS_ASSIGNMENT",
        severity="HIGH",
        cwe="CWE-915",
        confidence=0.7,
        description="Request data is expanded into a model constructor, so the client can set fields it should not.",
        patterns=[
            r"\w+\s*\(\s*\*\*\s*(?:request|req)\.(?:json|form|data|body|GET|POST)\b",
            r"\w+\s*\(\s*\*\*\s*(?:await\s+)?req\.body\b",
            r"""(?i)(?:create|update|new)\w*\s*\(\s*\{\s*\*\*\s*(?:req|request)\.""",
            r"""(?i)Object\.assign\s*\(\s*\w+\s*,\s*(?:req|request)\.(?:body|json)""",
            r"\w+\s*\(\s*\*\*\s*[\w\.]+\s*[,)]",
        ],
    ),
    SinkRule(
        vuln_class="INSECURE_COOKIE",
        severity="MEDIUM",
        cwe="CWE-1004",
        confidence=0.6,
        require_taint=False,
        description="Session cookie is set without HttpOnly/Secure/SameSite protection.",
        patterns=[
            r"set_cookie\s*\((?![^)\n]*(?:httponly|HttpOnly|secure=True|SameSite|samesite))",
            r"SESSION_COOKIE_SECURE\s*=\s*False",
            r"SESSION_COOKIE_HTTPONLY\s*=\s*False",
            r"SESSION_COOKIE_SAMESITE\s*=\s*[\"']none[\"']",
            r"cookie\s*\(\s*[\"'][^\"']+[\"']\s*,\s*[^)]*\bsecure\s*=\s*False",
            r"res\.cookie\s*\([^)]*\bhttpOnly\s*:\s*false",
        ],
    ),
    SinkRule(
        vuln_class="SESSION_FIXATION",
        severity="MEDIUM",
        cwe="CWE-384",
        confidence=0.45,
        require_taint=False,
        description="Session identifier is set from client controlled data, which allows session fixation.",
        patterns=[
            r"session\s*\[\s*[\"'][^\"']+[\"']\s*\]\s*=\s*(?:request|req|params|user|input)",
            r"session_id\s*=\s*(?:request|req|params|user|input)",
            r"set_cookie\s*\(\s*[\"']session[\"']\s*,\s*(?:request|req|params|user|input)",
        ],
    ),
    SinkRule(
        vuln_class="PERMISSIVE_CORS",
        severity="MEDIUM",
        cwe="CWE-942",
        confidence=0.7,
        require_taint=False,
        description="CORS is configured to allow any origin, often combined with credentials.",
        patterns=[
            r"""Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*["']""",
            r"""origins\s*=\s*["']\*["']""",
            r"""(?i)allow_origins\s*=\s*\[\s*["']\*["']""",
            r"""(?i)cors\s*\(\s*[^)]*allow_origins\s*=\s*["']\*["']""",
        ],
    ),
]

# File based misconfiguration rules (scanned on the repository, not on code).
FILE_RULES: list[tuple[str, str, str, str, str]] = [
    # (vuln_class, severity, glob, description, regex)
    ("EXPOSED_SECRET_FILE", "HIGH", "*.env", "Environment file with populated secret values committed to the repository.",
     r"(?im)^\s*(?:[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*(?!\s*$|changeme|your[_-]?|\{\{|<|xxx|\*+$)(?P<value>.+)$"),
    ("EXPOSED_SECRET_FILE", "HIGH", "*.pem", "Private key material present in the repository.", r"-----BEGIN\s+(?:RSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"),
    ("EXPOSED_SECRET_FILE", "HIGH", "id_rsa", "SSH private key present in the repository.", r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"),
    ("EXPOSED_SECRET_FILE", "MEDIUM", ".npmrc", "npm registry credentials stored in plaintext.", r"(?i)_authToken\s*=\s*\S+"),
    ("EXPOSED_SECRET_FILE", "MEDIUM", ".pypirc", "PyPI credentials stored in plaintext.", r"(?i)password\s*=\s*\S+"),
    ("EXPOSED_SECRET_FILE", "HIGH", "*.tfstate", "Terraform state file may contain secrets in plaintext.", r"(?s).+"),
    ("EXPOSED_SECRET_FILE", "HIGH", "credentials.json", "Service account credentials file in the repository.", r"(?s).+"),
]

DOCKER_RULES: list[tuple[str, str, str]] = [
    ("DEBUG_MODE", "MEDIUM", r"(?im)^\s*ENV\s+\w*DEBUG\w*\s*[= ]\s*(?:true|1|yes)\b"),
    ("HARDCODE_SECRET", "HIGH", r"(?im)^\s*(?:ENV|ARG)\s+\w*(?:SECRET|PASSWORD|TOKEN|API_KEY)\w*\s*[= ]\s*[\"']?(?P<value>[^\s\"']+)"),
    ("INSECURE_DEPENDENCY", "LOW", r"(?im)^\s*RUN\s+.*(?:curl|wget)\b.*\|\s*(?:sh|bash)\b"),
]

NGINX_RULES: list[tuple[str, str, str]] = [
    ("MISSING_SECURITY_HEADERS", "LOW", r"(?im)^\s*server_tokens\s+on\s*;"),
    ("PERMISSIVE_CORS", "MEDIUM", r"""(?im)^\s*add_header\s+Access-Control-Allow-Origin\s+["']?\*"""),
    ("DEBUG_MODE", "LOW", r"(?im)^\s*autoindex\s+on\s*;"),
]

# Authorization patterns proving a handler performs an access-control check.
AUTH_MARKERS: list[str] = [
    r"login_required", r"@auth", r"@jwt_required", r"@login_required", r"@permission_required",
    r"@requires_auth", r"@authenticated", r"require_auth", r"verify_token", r"verify_jwt",
    r"current_user", r"request\.user", r"request\.session\[", r"session\[",
    r"get_current_user", r"authenticate", r"check_permission", r"has_permission",
    r"is_authorized", r"is_admin", r"owner_id", r"user_id\s*==", r"currentUser",
    r"passport\.authenticate", r"authenticate_request", r"api[-_]key", r"authorization",
    r"jwt\.decode", r"verify\w*_token", r"access_token",
]

# Route parameters that commonly carry a directly addressable object id.
ID_PARAM_NAMES = {
    "id", "uid", "user_id", "userid", "order_id", "orderid", "invoice_id", "document_id",
    "file_id", "item_id", "project_id", "ticket_id", "account_id", "record_id", "product_id",
    "group_id", "org_id", "tenant_id", "customer_id", "session_id", "post_id", "comment_id",
    "uuid", "guid",
}

# Route definitions per framework.
# Each pattern uses the named groups `method` and `path`; the framework entry
# may add a `default_method` for decorators without an explicit verb.
ROUTE_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    (
        "FastAPI",
        "fastapi",
        re.compile(
            r"@(?:app|router|api_router)\.(?P<method>get|post|put|patch|delete)\s*\(\s*"
            r"[\"'](?P<path>[^\"']+)[\"']"
        ),
    ),
    (
        "Flask",
        "flask",
        re.compile(
            r"@\w+\.(?P<method>route|get|post|put|patch|delete)\s*\(\s*[\"'](?P<path>[^\"']+)[\"']"
        ),
    ),
    (
        "Django",
        "django",
        re.compile(
            r"^\s*(?:path|re_path|url)\s*\(\s*r?[\"'](?P<path>[^\"']+)[\"']",
            re.MULTILINE,
        ),
    ),
    (
        "Express",
        "express",
        re.compile(
            r"\b(?:app|router)\.(?P<method>get|post|put|patch|delete)\s*\(\s*"
            r"[\"'`](?P<path>[^\"'`]+)[\"'`]"
        ),
    ),
    (
        "Laravel",
        "laravel",
        re.compile(
            r"Route::(?P<method>get|post|put|patch|delete|any|match|resource)\s*\(\s*"
            r"[\"'](?P<path>[^\"']+)[\"']"
        ),
    ),
    (
        "Spring",
        "spring",
        re.compile(
            r"@(?P<method>Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*"
            r"(?:value\s*=\s*)?[\"'](?P<path>[^\"']+)[\"']"
        ),
    ),
    (
        "Go",
        "gin/echo",
        re.compile(
            r"\.(?P<method>GET|POST|PUT|PATCH|DELETE)\s*\(\s*[\"'](?P<path>[^\"']+)[\"']"
        ),
    ),
    (
        "Python",
        "custom-router",
        re.compile(
            r"if\s+(?:parsed\.path|request\.path|path|url|route|self\.path)\s*==\s*"
            r"[\"'](?P<path>[^\"']+)[\"']"
        ),
    ),
]

# Decorator verbs that do not imply a specific HTTP method.
GENERIC_VERBS = {"ROUTE", "ANY", "MATCH", "RESOURCE", "REQUEST"}

# Files we never bother scanning.
IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env.d", "dist", "build", ".next", ".nuxt", "vendor", "site-packages",
    ".mypy_cache", ".pytest_cache", ".tox", "coverage", ".gradle", "target",
}

IGNORED_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "composer.lock", "Cargo.lock", "*.min.js", "*.map",
    "*.min.css", "*.pyc", "*.so", "*.dll", "*.exe", "*.lock",
}

# Framework detection by dependency hints found in the project.
FRAMEWORK_HINTS: list[tuple[str, tuple[str, ...]]] = [
    ("FastAPI", ("fastapi", "starlette")),
    ("Flask", ("flask",)),
    ("Django", ("django",)),
    ("Express", ("express",)),
    ("NestJS", ("@nestjs/core",)),
    ("Laravel", ("laravel/framework",)),
    ("Spring", ("spring-boot",)),
]
