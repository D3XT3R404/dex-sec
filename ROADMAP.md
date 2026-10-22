# DEX-SEC DEVELOPMENT ROADMAP

## Milestone 1: Core Foundation & Hybrid MVP (SELESAI — 2026-10-21)
- [x] Desain protokol kolaborasi Multi-AI (`AI_HANDOFF.md`, `ARCHITECTURE.md`, `CURRENT_STATE.md`)
- [x] Data Models (`dexsec/models.py`)
- [x] SAST Scanner (`dexsec/sast/rules.py`, `scanner.py`): SQLi, NoSQLi, Command Injection, Code Injection, SSTI, XXE, Insecure Deserialization, Path Traversal, SSRF, Hardcoded Secret, XSS, JWT `alg:none`, Debug Mode, CORS, Weak Crypto, Insecure Random, Open Redirect
- [x] Akses kontrol (`dexsec/sast/access.py`): IDOR/BOLA + missing auth check
- [x] Scan konfigurasi (`dexsec/sast/config_scan.py`): `.env`, key files, Dockerfile, nginx
- [x] DAST Safe Verifier (`dexsec/dast/probes.py`, `verifier.py`): timing, error-signature, boolean diff, canary, file marker, redirect, SSTI, NoSQL, JWT none, IDOR diff, security headers, CORS
- [x] Hybrid Correlator (`dexsec/core/correlator.py`)
- [x] AI Patcher + fallback offline + validasi `git apply --check` (`dexsec/ai/patcher.py`)
- [x] Rich Terminal Output + ekspor MD/JSON (`dexsec/ai/reporter.py`, `dexsec/cli.py`)
- [x] Demo app + config/CD fixtures + self-test end-to-end (`tests/selftest.py`) → PASSED
- [x] Rebrand ke **DEX-SEC** + paket `dexsec` + entry point `dexsec`
- [x] Dokumentasi: `README.md`, `INSTALL.md`, `docs/COVERAGE.md`, wrapper `npm/`

## Milestone 2: Breadth & Intelligence (SEBAGIAN SELESAI — 2026-10-21)
- [x] OAST listener lokal untuk verifikasi SSRF & XXE (tanpa layanan eksternal)
- [x] Canary file lokal untuk membuktikan XXE (universal, cross-platform)
- [x] Route parser akurat: FastAPI, Flask, Django (`path`/`re_path`/`url`), Express, Laravel, Spring, Go (named groups)
- [x] Deteksi Mass Assignment (`Model(**request.json)`, `Object.assign`)
- [x] Deteksi CSRF missing pada route mutating
- [x] Next Step Advisor: rencana tindak lanjut per temuan (heuristik offline + mode LLM)
- [x] Taint lintas file sederhana (propagasi via import graph)
- [x] **AST-based taint analysis untuk Python** (interprocedural, deteksi string strategy, asal taint = nama parameter request)
- [x] **Black-box API fuzzing berbasis OpenAPI/Swagger** (`dexsec fuzz`, aman, rate-limited, allow-list)
- [x] **Attack Chain Analysis** (menggabungkan beberapa temuan jadi skenario eksploitasi)
- [x] Deteksi cookie insecure (HttpOnly/Secure/SameSite) & session fixation
- [x] Test suite fitur (`tests/test_features.py`) + guard false positive pada kode tool sendiri
- [x] **Probe dinamis Mass Assignment** (marker field yang tidak mengubah data)
- [x] **Deteksi cookie di level respons** (`Set-Cookie` header)
- [x] **Cek GraphQL introspection**
- [x] Route custom Python (`if parsed.path == ...`) + method dari `do_POST`
- [x] Taint JavaScript: template literal, `const/let/var`, `res.sendFile`, `jwt.decode`
- [ ] Probe dinamis CSRF (butuh dua sesi/akun + token)
- [ ] Taint AST penuh untuk JavaScript/TypeScript (parser JS专用)
- [ ] Black-box fuzzing juga untuk GraphQL & WebSocket
- [ ] LLM "attack chaining" lanjutan: prompt LLM untuk merangkai temuan & memprediksi jalur eksploitasi

## Milestone 2.5: Release readiness (SELESAI — 2026-10-22, v0.3.0)
- [x] `LICENSE` (MIT) + `CHANGELOG.md` + version bump ke 0.3.0
- [x] GitHub Action siap pakai (`.github/workflows/dexsec.yml`) + fail build pada temuan confirmed HIGH/CRITICAL
- [x] Pre-commit hook (`dexsec hook --install`)
- [x] Perintah `dexsec doctor` (cek instalasi, dependency, PATH, target)
- [x] PyInstaller onefile exe (`dexsec.spec` → `dist/dexsec.exe`, 14 MB) — sudah diuji jalan
- [x] Wrapper NPMglobals (tanpa postinstall, auto-install saat dipakai) — sudah diuji `npm install -g .`
- [x] Uji instalasi bersih di venv baru → `dexsec version` & scan penuh berhasil
- [x] Test end-to-end pada project pihak ketiga (sample-shop: Python + Express)

## Milestone 3: Automation & Integrations (SELESAI — 2026-10-22, v0.4.0)
Tujuan: DEX-SEC tidak lagi "sekali scan manual", tapi nempel di workflow developer
(IDE, git, CI, chat tim) dan bisa dibandingkan antar-branch.

- [x] **`dexsec fix`** — satu perintah: apply patch yang lolos validasi, lalu
      `git commit -m "fix(security): ..."`. Opsi: `--dry-run`, `--only <vuln-class>`, `--no-commit`.
      Memakai applier unified diff internal (`dexsec/ai/apply.py`) sehingga **tidak perlu git**.
- [x] **Output SARIF** (`--sarif report.sarif`) — format standar OWASP, supaya hasil
      scan muncul **inline di GitHub Code Scanning** dan di tab Security VS Code.
- [x] **Baseline diffing antar-branch** (`--baseline main.json` / `--write-baseline`) —
      hanya laporkan temuan **baru**/naik severity + yang sudah diperbaiki.
- [x] **Watch mode** (`dexsec watch --path . --target ...`) — scan ulang otomatis tiap
      file berubah, output ringkas (ala `eslint --watch`).
- [x] **Notifikasi Discord/Slack** (`--notify <webhook> --notify-level CRITICAL`) —
      format payload dipilih otomatis dari URL webhook.
- [x] **Laporan HTML interaktif** (self-contained, searchable & sortable) +
      **Executive Summary PDF** (PDF writer sendiri, tanpa dependency tambahan).
- [x] **JSON Schema output** (`docs/schema/audit-report.schema.json`).
- [x] **Panduan operasional step-by-step** (`docs/PANDUAN-OPERASIONAL.md`) +
      **sandbox web app** (`sandbox/vuln_web/`) untuk latihan mandiri.
- [ ] Notifikasi per-finding (mention orang yang owning file) — butuh integrasi VCS
- [ ] Laporan PDF dengan grafik/severity distribution

## Milestone 3.5: Distribution & Extensibility (SELESAI — 2026-10-22, v0.7.0)
- [x] Publish pipeline: CI (test multi-OS/multi-Python) + release (PyPI, 6 binary, GitHub Release, npm)
- [x] docs/PUBLISH.md — setup PyPI/trusted publishing/Homebrew/Scoop + checklist rilis
- [x] Konfigurasi dexsec.toml (exclude, min_severity, target, notify, ai) + dexsec init/dexsec config
- [x] Output machine-readable --format json|sarif|md|html (stdout bersih) untuk CI/editor
- [x] dexsec manual — panduan offline yang ikut ter-install
- [x] dexsec upgrade — update mandiri untuk pengguna binary
- [x] Patch otomatis untuk PHP (escape mysqli)
- [ ] Editor plugin (VS Code / Neovim) — ditunda, CLI dulu yang matang
- [ ] Custom rules dari file YAML (policy-as-code, sebagian di Milestone 4)

## Milestone 4: Enterprise
- [ ] Mode multi-target (banyak domain) dengan rate limiting & scheduling
- [ ] Integrasi SCA (osv-scanner / pip-audit) sebagai sumber dependency
- [ ] Policy-as-code (YAML) untuk aturan custom tim
- [ ] Multi-tenant (SaaS) bila dikembangkan jadi produk
