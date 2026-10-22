# Changelog

All notable changes to DEX-SEC are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/) and the
project uses [Semantic Versioning](https://semver.org/).

## [0.7.0] — 2026-10-22

### Added
- **Publish pipeline** — `.github/workflows/ci.yml` (test di 4 versi Python × 3 OS +
  build paket) dan `.github/workflows/release.yml` (PyPI, 6 binary standalone,
  GitHub Release, npm wrapper). Rilis cukup dengan `git tag v0.7.0`.
- **`docs/PUBLISH.md`** — panduan setup sekali saja (akun PyPI, trusted publishing,
  Homebrew tap, Scoop bucket, rilis manual) plus checklist sebelum rilis.
- **Konfigurasi** — `dexsec init` membuat `dexsec.toml` (project) atau
  `~/.config/dexsec/config.toml` (user). Isi: `exclude`, `min_severity`, `target`,
  `output_root`, `[notify]`, `[ai]`. Perintah `dexsec config` menampilkan konfigurasi
  yang sedang dipakai.
- **Output machine-readable** — `dexsec scan --format json|sarif|md|html` mencetak
  laporan apa adanya ke stdout (tanpa layout terminal) untuk CI dan editor plugin.
- **`dexsec manual`** — panduan step-by-step dibaca langsung dari instalasi
  (offline, tanpa internet).
- **`dexsec upgrade`** — mengecek GitHub Release lalu mengganti executable
  (untuk pengguna binary); pengguna pip mendapat instruksi `pip install -U dexsec`.
- **Patch otomatis untuk PHP** — variabel yang diinterpolasi ke query SQL PHP
  di-escape dengan `mysqli_real_escape_string()`.
- `scripts/sync_manual.py` menyalin dokumentasi ke dalam paket, `scripts/release_notes.py`
  membuat release notes dari CHANGELOG.

### Fixed
- Versi paket dan versi yang ditampilkan selalu sama (dibaca dari metadata paket).
- `--format`/`--stdout` tidak lagi tercampur dengan output terminal.
- `dexsec fix` sekarang juga bisa dipakai tanpa `--target` (menemukan celah dari
  analisis kode saja).
- Folder `build/` milik PyInstaller tidak lagi menghalangi modul `build` dari PyPA.

## [0.6.0] — 2026-10-22

### Added
- **Multi-language support** (data driven, see `dexsec/sast/languages.py`):
  - **PHP** — sources (`$_GET`, `$_POST`, `$_REQUEST`, `$_FILES`, `$_COOKIE`, `filter_input`),
    sinks (mysqli/PDO, `system`/`exec`/`shell_exec`, `include` with a variable = LFI,
    `unserialize`, `extract($_GET)`, `move_uploaded_file`, `echo` of user data),
    string interpolation (`"text $var"`), and **route discovery**: every `.php` file
    below the document root becomes an endpoint with its query parameters.
  - **Java / Kotlin** — `HttpServletRequest.getParameter`, JDBC statements,
    `Runtime.exec`, `new File(...)`, `ObjectInputStream`, Spring/JAX-RS routes.
  - **Go** — `r.URL.Query().Get`, `db.Query(fmt.Sprintf(...))`, `exec.Command`,
    `os.Open`, `http.Get`, `http.HandleFunc` routes.
  - **C#** — `Request.Query`, `new SqlCommand`, `Process.Start`, `File.ReadAllText`,
    ASP.NET `[HttpGet]` routes.
  - **Ruby** — `params[:x]`, `where("...#{x}...")`, `system`, `File.read`, `raw(...)`.
  - **JavaScript / TypeScript** — extended sinks (`child_process`, `fs`, `axios`,
    `Object.assign`, `jwt.decode` without verification) and route rules.
- **PHP call graph analysis** (`dexsec/sast/php_calls.py`) — a sink inside an
  included library is reported on the page that actually calls it with request
  data, so the finding points to a reachable endpoint instead of a helper file.
- **Reflected XSS verification** — the parameter is echoed with a marker, then
  with angle brackets. Raw markup in the response means `CONFIRMED_VULNERABLE`,
  encoded output stays `POTENTIAL`.
- Test fixtures for six languages (`tests/fixtures/`) and four new test groups
  (multi language detection, PHP route mapping, PHP call graph, XSS verifier).

### Fixed
- Findings are de-duplicated globally, not per analyser, so the same issue is
  no longer reported twice when several rules match one line.
- PHP files outside the document root are no longer mapped to invalid URLs
  such as `/../config.php`.
- Taint detection understands the assignment styles of every supported
  language (`x = ...`, `Type x = ...`, `x := ...`).

## [0.5.0] — 2026-10-22

### Added
- **Dedicated output folder** — scan results are never written into the folder
  that was scanned. Everything lands in
  `<dexsec>/hasil-scan/<project>/<timestamp>-<host>/` containing
  `laporan.md`, `laporan.json`, `laporan.html`, `ringkasan.pdf`, `laporan.sarif`
  and the suggested patch. The root can be changed with `--out-dir` or the
  `DEXSEC_OUTPUT_ROOT` environment variable.
- `dexsec scan --out-dir`, `dexsec fix --out-dir` and `dexsec fuzz --out-dir`
  to choose the destination folder explicitly.

### Changed
- The report file names are now Indonesian (`laporan.*`, `ringkasan.pdf`) and
  consistent across all output formats.
- For pip/onefile installations (no source checkout) the results go to
  `~/.dexsec/hasil-scan/`.

### Fixed
- The scanned project is never modified by a scan run any more - previously a
  `dexsec-report.json` was left behind in the audited directory.

## [0.4.0] — 2026-10-22

### Added
- **`dexsec fix`** — applies the generated patches and (optionally) creates a
  conventional security commit. It uses a built-in unified diff applier, so it
  works in projects that are not git repositories. Flags: `--dry-run`,
  `--only <vuln-class>`, `--no-commit`, `--message`.
- **SARIF 2.1.0 output** (`--sarif report.sarif`) — findings appear inline in
  GitHub Code Scanning and in the Security tab of VS Code / JetBrains IDEs.
- **Baseline diffing** (`--baseline <file.json>` and `--write-baseline <file>`) —
  reports only new findings, escalated severities and resolved findings.
- **Watch mode** (`dexsec watch`) — re-runs the audit automatically whenever a
  source file changes and prints only the delta.
- **Discord & Slack notifications** (`--notify <webhook> --notify-level <SEV>`) —
  the payload format is detected from the webhook URL.
- **Interactive HTML report** (`--html report.html`) — a single self-contained
  file with search, severity/status filters and sortable columns.
- **Executive summary PDF** (`--pdf summary.pdf`) — produced by a built-in PDF
  writer, no extra dependency needed.
- **JSON schema** for the audit report (`docs/schema/audit-report.schema.json`).
- **Step-by-step operational guide** (`docs/PANDUAN-OPERASIONAL.md`).
- **Training sandbox** (`sandbox/vuln_web/`) — a deliberately vulnerable Flask
  app with a SQL injection, used to practise the tool safely.

### Fixed
- Parameterised SQL patches now respect the driver: `sqlite3` receives `?`
  placeholders, psycopg2/MySQL receive `%s`. Before, patching a sqlite3 project
  produced a broken query.
- `LIKE '%{term}%'` patterns are patched into `LIKE %s` with the wildcards moved
  into the bound parameter instead of leaving a broken `LIKE '%%s%'`.
- Report files now create their parent directory automatically.
- More database error signatures are recognised, including SQLite errors that do
  not carry the exception class name in the message.

## [0.3.0] — 2026-10-22

### Added
- **Dynamic mass-assignment probe** — a harmless marker field (`dexsec_probe_field`)
  is sent to the endpoint; if the server stores/echoes it, the whole request body
  is written to the model (`CONFIRMED_VULNERABLE`).
- **Cookie inspection at response level** — `Set-Cookie` headers are checked for
  missing `HttpOnly` / `Secure` / `SameSite`.
- **GraphQL introspection check** — the standard `/graphql`, `/api/graphql`, `/gql`
  endpoints are queried; an open introspection endpoint is reported.
- **Route detection for custom Python routers** — `if parsed.path == "/x"` inside
  `do_GET` / `do_POST` handlers, with the HTTP method taken from the handler name.
- **Mass assignment detection for Python** — `Model(**payload)` is detected by the
  AST analyser, `Object.assign(user, req.body)` for JavaScript.
- **`dexsec doctor`** — self-check command that verifies the installation, the
  dependencies, the console script and the reachability of a target.
- **JavaScript template literal support** — SQLi in `` `...${name}...` `` is now
  detected, `const/let/var` are treated as tainted assignments, and
  `res.sendFile()` / `res.download()` are path traversal sinks.
- **SQL injection proof via crash** — when the payload makes the handler fail while
  the baseline request succeeds, that is now reported as confirmed evidence.
- GitHub Action, pre-commit hook, `LICENSE`, `CHANGELOG.md`, PyInstaller spec.

### Fixed
- Routes described twice (decorator + dispatch table) are no longer counted twice.
- Windows path traversal probes now use eight `..` levels so they reach
  `C:\Windows\win.ini` from any directory depth.
- The JSON report no longer crashes on nested dataclasses.
- The `dexsec` console script no longer fails on Windows consoles using cp1252.

## [0.2.0] — 2026-10-21

### Added
- Rebranding to **DEX-SEC** (package `dexsec`, console script `dexsec`).
- Coverage expansion: NoSQLi, Code Injection, SSTI, XXE, Insecure Deserialization,
  IDOR/BOLA, Mass Assignment, CSRF, JWT `alg:none`, Weak Crypto, Insecure Random,
  Open Redirect, Debug Mode, Permissive CORS, Missing Security Headers,
  Exposed Secret Files, Insecure Cookies, Session Fixation.
- Repository level misconfiguration scanning (`.env`, private keys, Dockerfile, nginx).
- OAST listener for local proof of SSRF and XXE.
- `INSTALL.md` with seven installation methods (pip, pipx, PyPI, PyInstaller, NPM,
  Docker, GitHub Actions) and `docs/COVERAGE.md` with the vulnerability matrix.

## [0.1.0] — 2026-10-21

### Added
- Initial inside-out pipeline: static analysis, safe external verification,
  correlation, AI patch generation with offline fallback, Markdown/JSON reports.
