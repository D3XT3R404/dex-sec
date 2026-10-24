# CURRENT PROJECT STATE & AI WORKLOG

> **Panduan:** Setiap AI atau developer yang baru masuk ke sesi ini harus membaca file ini terlebih dahulu untuk mengetahui progres terakhir dan hal mendesak yang perlu diselesaikan.

---

## Status Ringkasan
- **Project Name:** **DEX-SEC** (Inside-Out Hybrid Application Security Testing CLI)
- **Active Phase:** Milestone 1 **SELESAI** (core + coverage luas). Sekarang masuk **Milestone 2**.
- **Current Health:** Pipeline end-to-end berjalan & lolos self-test otomatis.
- **Location:** `C:\Users\ASUS\dex-sec` (nama folder lama `C:\Users\ASUS\secflow` masih ada & sudah usang — hapus manual)
- **Package name:** `dexsec` · Entry point: `dexsec` · Versi: `0.7.2` (**ters publik di PyPI** — `pip install dexsec`)
- **Runtime:** Python 3.11.9 (stdlib + rich/requests/typer, semuanya sudah terpasang)
- **Next Immediate Task:** Milestone 4 (enterprise) atau sisa M2 (probe CSRF dinamis, parser JS penuh) + editor plugin.

## Cara Menjalankan

```powershell
cd C:\Users\ASUS\dex-sec

# 1. install (mode editable)
python -m pip install -e .

# 2. jalankan target uji
python demo\vulnerable_app.py            # http://127.0.0.1:8765

# 3. audit
dexsec scan --path . --target http://127.0.0.1:8765 --report report.md --json report.json
# (atau tanpa install: python -m dexsec scan ...)

# 4. uji otomatis (start/stop server, apply patch, scan ulang)
python tests\selftest.py

# 5. lihat daftar temuan saja
python tests\list_findings.py
```

## Dokumentasi Penting
| File | Isi |
| --- | --- |
| `INSTALL.md` | Cara install (pip/pipx/PyPI/exe/NPM/Docker/CI), di mana ter-install, cara menjalankan, troubleshooting |
| `docs/COVERAGE.md` | Matriks seluruh kelas kerentanan: mana yang sudah deteksi+verifikasi, mana yang statis, mana yang rencana |
| `README.md` | Ringkasan & cheat sheet |
| `ROADMAP.md` | Antrian kerja per milestone |
| `ARCHITECTURE.md` | Desain pipeline & struktur folder |
| `AI_HANDOFF.md` | Protokol kolaborasi multi-AI |

## Perintah CLI
| Perintah | Fungsi |
| --- | --- |
| `dexsec scan --path <dir> --target <url>` | Audit lengkap: SAST → safe DAST → korelasi → patch AI → laporan |
| `dexsec scan --path <dir> --skip-dast` | Hanya analisis statis |
| `dexsec routes --path <dir>` | Daftar route HTTP yang ditemukan di kode |
| `dexsec version` | Versi tool |

## Hasil Verifikasi Terakhir (2026-10-21, v0.2.0)
`python tests\selftest.py` → **SELFTEST PASSED**
```
[1] routes=7 findings=13 confirmed=4   (SQLi, Command Injection, Path Traversal, IDOR)
[2] patches generated: 3
[3] patch applied cleanly
[4] after patch: confirmed=1 not_reproducible=3   (sisa = IDOR, memang tidak auto-fixable)
```
Temuan statis pada fixture: `EXPOSED_SECRET_FILE` (3 di `.env`), `HARDCODE_SECRET` (2 di Dockerfile),
`DEBUG_MODE` (2), `INSECURE_DEPENDENCY` (1), `IDOR` (HIGH + MEDIUM).

## Log Aktivitas (Changelog Sesi)

### [2026-10-24] - RILIS PUBLIK v0.7.2 — PyPI + GitHub Release + 6 binary standalone — oleh Opencode
- **Tujuan:**用户 glandu bisa `pip install dexsec` untuk semua orang.
- **Akar masalah (3 lapis, ketiganya diperbaiki):**
  1. `release.yml` memakai `secrets` di dalam `if:` step → GitHub menolak seluruh workflow
     (*Invalid workflow file: Unrecognized named-value: 'secrets'*), jadi run gagal **0 detik** tanpa job.
     Diperbaiki di commit `d9acc45` (sesi AI lain) & dikonfirmasi di `origin/main`.
  2. Semua run `Release` gagal karena menunjuk **commit lama** (tag `v0.7.1` lama仍然 menunjuk
     versi workflow yang rusak) → tag dipindah ke commit yang sudah benar.
  3. Job `binaries` gagal di Windows: `python -m PyInstaller ... \` memakai line continuation `\`
     yang **ditolak PowerShell**. Diperbaiki dengan `shell: bash` eksplisit.
  4. CI gagal di 12 matrix job: `ModuleNotFoundError: No module named 'yaml'` — `tests/test_features.py`
     butuh PyYAML tapi `pyyaml` hanya ada di extra `yaml`. Diperbaiki: `pyyaml` masuk extra `dev`.
- **Modul yang diubah:** `pyproject.toml` (versi `0.7.1`→`0.7.2`, extra `dev` + `pyyaml`),
  `.github/workflows/release.yml` (`shell: bash` pada step build binary & release notes),
  `CHANGELOG.md` (entri `0.7.1` & `0.7.2`).
- **Hasil Verifikasi / Testing:**
  - `python tests\selftest.py` → **SELFTEST PASSED** (confirmed=6, patch apply sukses, setelah patch confirmed=2).
  - `python tests\test_features.py` → **FEATURE TESTS PASSED**.
  - `scripts\check_workflows.py` → all 3 workflow valid; **actionlint 1.7.12** → clean.
  - Workflow Release `40085212991` → **semua 9 job SUCCESS** (verify, pypi, 6 binaries, npm, release).
  - **PyPI**: https://pypi.org/project/dexsec/ → versi `0.7.2` (wheel + sdist).
  - **GitHub Release**: https://github.com/D3XT3R404/dex-sec/releases/tag/v0.7.2 → wheel, sdist,
    `dexsec-windows-x64.exe`, `dexsec-windows-arm64.exe`, `dexsec-linux-x64`, `dexsec-linux-arm64`,
    `dexsec-macos-x64`, `dexsec-macos-arm64`.
  - **Bukti "user lain":** venv bersih → `pip install dexsec==0.7.2` → `dexsec version` = 0.7.2,
    `dexsec doctor` → "Everything looks good".
- **Status Saat Ini:** **OK — DEX-SEC sudah publik di PyPI.** Pipeline Release selesai semua job SUCCESS (termasuk `verify` yang menjalankan selftest + test_features). Catatan: workflow CI terpisah masih **flaky** (selftest terkadang gagal pada beberapa matrix cell OS/Python; sudah terjadi sebelum perubahan ini dan tidak terkait rilis).
- **Tugas untuk AI Berikutnya:**
  1. Update `INSTALL.md` §2.4 (PyPI) — hapus catatan "PyPI belum ter-push".
  2. Lanjut **Milestone 4** (multi-target, SCA, policy-as-code) atau sisa M2.
  3. Ingat: `npm publish` butuh secret `NPM_TOKEN` (belum diisi — paket npm belum terbit).

### [2026-10-22 19:45] - Milestone 3.5: publish pipeline + config + machine output + manual offline (v0.7.0) — oleh Opencode
- **Deliverable:**
  - `.github/workflows/ci.yml` — test di 4 versi Python × 3 OS + build paket + `twine check`.
  - `.github/workflows/release.yml` — PyPI (OIDC/trusted publishing), 6 binary standalone (win/linux/mac × x64/arm64), GitHub Release + release notes dari CHANGELOG, publish npm wrapper.
  - `docs/PUBLISH.md` — setup sekali saja (akun PyPI, token, trusted publishing, Homebrew tap, Scoop bucket, rilis manual, checklist, troubleshooting).
  - `scripts/sync_manual.py` (dokumentasi → `dexsec/manual/`) & `scripts/release_notes.py`.
  - `dexsec/config.py` — konfigurasi TOML (`dexsec.toml` project / `~/.config/dexsec/config.toml` user): `exclude`, `min_severity`, `target`, `output_root`, `[notify]`, `[ai]`.
  - Perintah baru: `dexsec manual`, `dexsec init`, `dexsec config`, `dexsec upgrade`.
  - `dexsec scan --format json|sarif|md|html` → output machine-readable ke stdout.
  - Patch otomatis PHP (escape `mysqli_real_escape_string`) di `dexsec/ai/patcher.py`.
- **Bukti "user lain":** wheel dibangun → di-install di **venv bersih** → `dexsec version` = 0.7.0, `doctor` OK, `manual` terbaca offline, scan 6 bahasa (21 temuan), `--format json` & `--format sarif` valid, `init`/`config` jalan, `fix --dry-run` jalan, **folder target tetap bersih**.
- **Bug yang difix:** versi paket vs `__init__` beda (sekarang satu sumber: metadata); output `--format` tercampur terminal; `fix` tanpa `--target` tidak bisa dipakai; folder `build/` (PyInstaller) menutupi modul `build` PyPA.
- **Status Saat Ini:** Milestone 1, 2, 2.5, 3, 3.5 selesai. Sisa: M2 kecil (probe CSRF dinamis, parser JS penuh), M4 (enterprise: multi-target, SCA, policy-as-code), editor plugin (ditunda).
- **Tugas untuk AI Berikutnya:** ikuti `docs/PUBLISH.md` untuk benar-benar mem-publish ke PyPI (butuh akun & token dari maintainer), atau lanjut M4. Update `CURRENT_STATE.md` + `ROADMAP.md` + `CHANGELOG.md`.

### [2026-10-22 19:00] - Milestone 3.5: multi-bahasa (PHP/JS/Java/Go/C#/Ruby) + call graph PHP + XSS verifier (v0.6.0) — oleh Opencode
- **Motif:** diuji pada lab PHP milik pengguna (`OneDrive\Desktop\DZAKY\Lab\DEX-LABS`) → sebelumnya DEX-SEC hanya menemukan 3 temuan & 1 FP karena tidak mendukung PHP.
- **Modul baru:**
  - `dexsec/sast/languages.py` — **mesin analisis data-driven per bahasa**: `LanguageSpec` (sources, sinks, interpolations, routes, param readers). Menambah bahasa = menambah satu blok spec, tanpa mengubah engine.
  - `dexsec/sast/php_calls.py` — **call graph PHP**: sink di dalam fungsi library (mis. `config.php`) dilaporkan di **halaman pemanggil** yang benar-benar bisa diakses + nama variabel tainted-nya.
- **Modul yang diubah:**
  - `dexsec/sast/scanner.py` — `find_language_sinks()`, `_php_routes()` (file `.php` → URL + parameter), dedupe global, `_iter_source_files` perluas ekstensi.
  - `dexsec/dast/verifier.py` — `verify_xss()` (marker → cek raw markup vs ter-escape).
  - `dexsec/sast/languages.py` — `tainted_variables()` mendukung `x =`, `Type x =`, `x :=`.
  - `tests/fixtures/` — fixture sendiri (PHP, JS, Java, Go, C#, Ruby) — **bukan** dari lab pengguna.
  - `tests/test_features.py` — 4 test group baru (multi-bahasa, route PHP, call graph PHP, XSS verifier).
- **Hasil nyata di lab PHP pengguna:** 11 route, 48 temuan statis, **XSS REFLECTED CONFIRMED** (PoC: `curl '.../modules/xss_reflected.php?q=%3Cdexsec-xss-probe%3E'`), **IDOR CONFIRMED** (`/modules/profile.php?id=1` vs `id=999999999`), CORS/missing headers confirmed. Bandingkan: sebelum ini hanya 2 confirmed.
- **Bug yang difix:** route PHP di luar document root memetakan ke `/../config.php`; duplikasi temuan antar analis; deteksi taint gagal untuk Java/Go (gaya assignment berbeda).
- **Verifikasi:** `tests\selftest.py` → PASSED; `tests\test_features.py` → FEATURE TESTS PASSED (20 test group); EXE v0.6.0 dibangun.
- **Tugas untuk AI Berikutnya:** residu M2 (probe CSRF dinamis, parser JS penuh), M4 (enterprise), atau perluasan `LanguageSpec` (mis. Kotlin/Dart/Elixir). Update `CURRENT_STATE.md` + `ROADMAP.md` + `CHANGELOG.md`.

### [2026-10-22 03:30] - Milestone 3 selesai (v0.4.0) + sandbox + panduan operasional — oleh Opencode
- **Fitur M3 (semua selesai):**
  - `dexsec fix` (`dexsec/cli.py` + `dexsec/ai/apply.py`): applier unified diff **internal** (tanpa git), `--dry-run`, `--only`, `--no-commit`, `--message`, commit otomatis `fix(security): ...`.
  - **SARIF 2.1.0** (`dexsec/ai/sarif.py`) → `--sarif`; rule id `DEXSEC/<VULN_CLASS>`, `partialFingerprints` stabil.
  - **Baseline diffing** (`dexsec/core/baseline.py`) → `--baseline` / `--write-baseline`; laporkan baru, naik severity, dan yang sudah diperbaiki.
  - **Watch mode** (`dexsec/core/watcher.py`) → `dexsec watch`; polling mtime, output delta saja.
  - **Notifikasi** (`dexsec/core/notify.py`) → `--notify` / `--notify-level`; payload Slack/Discord/generic dipilih dari URL webhook.
  - **HTML interaktif** (`dexsec/ai/html_report.py`) → `--html`; self-contained, search + filter + sort.
  - **Executive PDF** (`dexsec/ai/pdf.py`) → `--pdf`; PDF writer sendiri (tanpa reportlab/fpdf).
  - **JSON Schema** → `docs/schema/audit-report.schema.json`.
- **Dokumentasi & latihan:**
  - `docs/PANDUAN-OPERASIONAL.md` — panduan step-by-step untuk pemula (8 bagian: konsep, install, latihan, pakai di project sendiri, workflow harian, penjelasan teknis, troubleshooting, referensi perintah).
  - `sandbox/vuln_web/app.py` + `README.md` — aplikasi Flask latihan dengan **satu** kerentanan (SQL Injection) di `/search`.
- **Refactor:** pipeline dipindah ke fungsi `perform_audit()` sehingga dipakai bersama oleh `scan`, `fix`, dan `watch`.
- **Bug yang difix (penting!):**
  - Patch parameterised SQL untuk **sqlite3** memakai placeholder `%s` → SQL rusak (`near "%": syntax error`). Kini placeholder ditentukan per driver (`?` untuk sqlite3, `%s` untuk psycopg2/MySQL).
  - Pola `LIKE '%{term}%'` jadi `LIKE '%%s%'` (rusak). Kini wildcard pindah ke parameter: `LIKE %s` + `f"%{term}%"`.
  - Param `f"%{keyword}%"` sempat kehilangan kurung kurawal → diperbaiki.
  - File laporan tidak bisa ditulis ke folder yang belum ada → parent dibuat otomatis.
  - Deteksi error SQL SQLite tanpa nama kelas exception ("unrecognized token") → pola signature diperluas.
- **Verifikasi:**
  - `tests\selftest.py` → SELFTEST PASSED; `tests\test_features.py` → FEATURE TESTS PASSED (16 test, termasuk M3).
  - Sandbox: scan → SQL_INJECTION CONFIRMED → `dexsec fix` → app patched → scan ulang → NOT_REPRODUCIBLE, dan fungsi pencarian tetap benar ("kaos" ketemu).
  - EXE `dist\dexsec.exe` (v0.4.0) menjalankan scan + 5 format laporan + `fix --dry-run` dengan hasil identik.
- **Status Saat Ini:** Milestone 1, 2, 2.5, 3 selesai. Sisa: M2 kecil (probe CSRF dinamis, parser JS penuh) & M4 (enterprise).
- **Tugas untuk AI Berikutnya:** Milestone 4 (multi-target, integrasi SCA, policy-as-code) atau sisa M2 (probe CSRF dinamis, parser JS penuh); selalu update `CURRENT_STATE.md` + `ROADMAP.md` + `CHANGELOG.md`.

### [2026-10-22 02:20] - Release readiness v0.3.0 + sisa Milestone 2 — oleh Opencode
- **Fitur M2 yang diselesaikan:**
  - Probe dinamis **Mass Assignment** (`verify_mass_assignment`): mengirim marker field `dexsec_probe_field`; kalau server store/echo → CONFIRMED, tanpa mengubah data nyata.
  - Deteksi **cookie di level respons** (`Verifier.check_cookies`): `Set-Cookie` tanpa HttpOnly/Secure/SameSite.
  - **GraphQL introspection** check (`Verifier.check_graphql`): `/graphql`, `/api/graphql`, `/gql`.
  - Route **custom router Python** (`if parsed.path == "/x"`) dengan method dari `def do_POST`.
  - Taint **JavaScript**: template literal SQLi, `const/let/var`, `res.sendFile`/`res.download`, `jwt.decode` tanpa verifikasi.
  - `Model(**payload)` (Python) & `Object.assign(user, req.body)` (JS) dideteksi sebagai Mass Assignment.
- **Release readiness:**
  - `LICENSE` (MIT), `CHANGELOG.md`, version bump **0.3.0** di `pyproject.toml` & `dexsec/__init__.py`.
  - `.github/workflows/dexsec.yml` — static analysis selalu jalan, upload artifact, **fail build** bila ada confirmed HIGH/CRITICAL.
  - `dexsec/hooks.py` + `dexsec hook --install` — pre-commit hook yang memblokir HIGH/CRITICAL.
  - `dexsec doctor` — cek versi, dependency, PATH, dan keterjangkauan target.
  - `dexsec.spec` + `run_dexsec.py` → **PyInstaller onefile `dist/dexsec.exe` (14.4 MB)** — sudah diuji: `dexsec.exe scan` menghasilkan hasil identik dengan versi Python.
  - Wrapper NPM disederhanakan (tanpa postinstall; auto-install saat dipakai) + `npm/README.md`.
- **Verifikasi:**
  - `python tests\selftest.py` → SELFTEST PASSED; `python tests\test_features.py` → **FEATURE TESTS PASSED (32 assertion, 11 test)**.
  - Instalasi bersih di **venv baru** → `dexsec version` = 0.3.0, scan penuh 13 route & 5 confirmed.
  - `npm install -g .` → `dexsec` global via node berhasil.
  - Audit project pihak ketiga (sample-shop) → SQLi, Path Traversal, **Mass Assignment**, CORS, missing headers terkonfirmasi.
- **Status Saat Ini:** Milestone 1 selesai, Milestone 2 selesai kecuali probe CSRF dinamis & parser JS penuh, Milestone 2.5 (release readiness) selesai.
- **Tugas untuk AI Berikutnya:** Milestone 3 (auto-apply patch + commit helper, laporan HTML/PDF, notifikasi Discord/Slack) dan Milestone 4 (mode multi-target, integrasi SCA, policy-as-code).

### [2026-10-22 01:45] - Validasi pada project pihak ketiga ("sample-shop") + perbaikan genericity — oleh Opencode
- **Tujuan:** membuktikan DEX-SEC generic (bukan hardcode ke file demo) dengan audit project baru: `app.py` (Flask-ish custom router) + `server.js` (Express).
- **Hasil:** 11 route & 12 temuan terdeteksi di project baru, lalu 4 temuan terkonfirmasi lewat fase luar (SQLi via crash, Path Traversal via `Windows\win.ini`, CORS wildcard, missing security headers).
- **Perbaikan yang lahir dari validasi ini:**
  - Route detector untuk custom router Python (`if parsed.path == "/x"`) — belum ada sebelumnya.
  - SQLi pada JavaScript template literal (`` `...${name}...` ``) — sebelumnya hanya f-string Python yang tertangkap.
  - `const/let/var` pada deteksi taint JS.
  - `res.sendFile()`/`res.download()` ikut jadi sink path traversal.
  - `jwt.decode(token)` tanpa verifikasi → JWT_NONE_ALG.
  - Verifier SQLi: **crash server setelah payload** (baseline normal → payload bikin handler mati) kini jadi bukti CONFIRMED, sebelumnya salahReported NOT_REPRODUCIBLE.
  - Probe path traversal Windows memakai 8 level `..` agar menjangkau `C:\Windows\win.ini` dari depth berapa pun.
  - Dedup route per (method, path, file) agar decorator + dispatch table tidak terhitung dua kali.
- **Verifikasi:** `tests\selftest.py` → PASSED; `tests\test_features.py` → PASSED; audit sample-shop → 4 confirmed.
- **Status Saat Ini:** OK — tool terbukti generic pada project Python + Node.js.

### [2026-10-22 01:10] - Finalisasi: PATH global, tutorial README, verifikasi akhir — oleh Opencode
- **Perubahan:**
  - `dexsec.exe` (console script) sudah terpasang, dan folder `Scripts` **ditambahkan ke PATH user** sehingga `dexsec` bisa dipanggil dari terminal baru tanpa setting manual.
  - `README.md` — ditambah bagian **"TUTORIAL: 5 menit pakai DEX-SEC"** (langkah 1-5, cara baca hasil, workflow harian & CI, cheat sheet) dan tabel perintah duplikat dibersihkan.
  - `INSTALL.md` — sudah mencakup 7 metode instalasi, lokasi folder `Scripts` (Python.org vs Microsoft Store), troubleshooting `bdist_wheel`, dan cara menambahkan PATH.
- **Verifikasi akhir:** `python tests\selftest.py` → **SELFTEST PASSED**; `python tests\test_features.py` → **FEATURE TESTS PASSED**; `dexsec --help` & `dexsec version` berfungsi dari PATH global.
- **Status Saat Ini:** Milestone 1 selesai, Milestone 2 ~80% (sisa: probe dinamis Mass Assignment/CSRF, AST taint JS/TS, fuzzing GraphQL/WebSocket, deteksi cookie di level response).
- **Tugas untuk AI Berikutnya:** ambil item sisa Milestone 2 di `ROADMAP.md`; wajib update `CURRENT_STATE.md` + `ROADMAP.md` + `docs/COVERAGE.md`.

### [2026-10-22 00:35] - Milestone 2 (bagian 2): AST taint, OpenAPI fuzzing, attack chain, cookie rules — oleh Opencode
- **Modul baru:**
  - `dexsec/sast/ast_taint.py` — analisis taint berbasis AST untuk Python: scope taint per fungsi, propagasi **interprocedural** (argumen tainted → parameter fungsi), pelacakan *strategy* string (fstring/concat/format), dan **asal taint = nama parameter request** (asal `params.get("q")` → `q`).
  - `dexsec/dast/openapi.py` — black-box fuzzer berbasis OpenAPI/Swagger: hanya metode idempoten secara default, rate limit, batas jumlah request, allow-list path, payload read-only (quote, ssti, traversal, long, unicode, marker), deteksi anomali (5xx, stack trace, SQL error, SSTI, traversal, refleksi).
  - `dexsec/ai/chaining.py` — attack chain analysis (9 template chain).
  - `tests/test_features.py` — test suite fitur (AST, FP guard, route mapping, chains, advisor, spec, cookie rules).
- **Modul yang diubah:**
  - `dexsec/sast/scanner.py` — `_refine_with_ast()` (hasil AST menggantikan hasil regex untuk kelas yang dipahami AST), `attach_routes()` memakai route pembungkus di atas finding, `propagate_taint_across_files()`.
  - `dexsec/sast/rules.py` — `GENERIC_TAINT_NAMES` (anti false positive), `ID_PARAM_NAMES` dipangkas, aturan `INSECURE_COOKIE` & `SESSION_FIXATION`, pola route baru (Django re_path/url, Express router, Laravel, Spring).
  - `dexsec/dast/verifier.py` — `_pick_param` memakai `handler_params` sebagai fallback.
  - `dexsec/ai/patcher.py` — fallback patch XXE diperbaiki (tidak lagi `defusedxml.defusedxml`).
  - `dexsec/ai/reporter.py` + `dexsec/cli.py` — PHASE 5 Attack Chain, PHASE 6 Next Step, PHASE 7 Report; perintah baru `dexsec fuzz`.
  - `demo/vulnerable_app.py` (route `/missing` untuk uji fuzzing), `demo/openapi.yaml` (spec contoh).
  - `ROADMAP.md`, `docs/COVERAGE.md`.
- **Bug yang difix:** SQLi di file yang sudah diparameterisasi tetap terflag (AST menganggap tuple params sebagai taint) → kini hanya argumen query yang diperiksa; `taint_var` menunjuk variabel antara (`query`) sehingga probe ke parameter yang salah → kini berasal dari literal `.get("q")`; patch XXE menghasilkan `defusedxml.defusedxml`; route mapping salah pilih handler.
- **Verifikasi:** `python tests\selftest.py` → **PASSED** (confirmed=6, 4 patch apply sukses, setelah patch confirmed=2); `python tests\test_features.py` → **FEATURE TESTS PASSED**; live scan → 7 confirmed; `dexsec fuzz` → 32 request, 7 anomali (5xx stack trace terdeteksi).
- **Status Saat Ini:** OK — Milestone 2 ~80% selesai.
- **Tugas untuk AI Berikutnya:**
  1. Sisa M2: probe dinamis Mass Assignment & CSRF, AST taint untuk JS/TS, fuzzing GraphQL/WebSocket, deteksi cookie di level response.
  2. Tambahkan `dexsec fuzz` ke `tests/selftest.py` (butuh server demo + spec).
  3. Update `CURRENT_STATE.md`, `ROADMAP.md`, `docs/COVERAGE.md` setelah perubahan.

### [2026-10-21 23:45] - Milestone 2 (bagian 1): OAST, Next Step Advisor, parser route, taint lintas file — oleh Opencode
- **Modul yang disentuh (baru):**
  - `dexsec/dast/oast.py` — HTTP callback listener lokal (127.0.0.1) untuk membuktikan SSRF & XXE
  - `dexsec/ai/advisor.py` — Next Step Advisor (heuristik offline + mode LLM dengan JSON output)
- **Modul yang diubah:**
  - `dexsec/dast/verifier.py` — `verify_ssrf_oast()`, `verify_xxe_oast()` (canary file lokal + OAST), XXE/SSRF dikeluarkan dari daftar non-probeable
  - `dexsec/dast/probes.py` — tetap sebagai fallback marker
  - `dexsec/sast/rules.py` — ROUTE_PATTERNS ditulis ulang dengan named groups (`method`/`path`) + framework baru (Django re_path/url, Express router, Laravel, Spring); aturan baru MASS_ASSIGNMENT; XXE jadi non-taint-required
  - `dexsec/sast/scanner.py` — `propagate_taint_across_files()` (import graph), `_module_level_tainted()`, `_imported_names()`, dedupe per (class,file,line) dengan sink terpanjang
  - `dexsec/sast/access.py` — deteksi CSRF missing
  - `dexsec/models.py` — enum `MASS_ASSIGNMENT`, `CSRF_MISSING`; field `AuditReport.next_steps`
  - `dexsec/core/correlator.py` — impact/remediation untuk Mass Assignment & CSRF
  - `dexsec/ai/patcher.py` — fallback patch XXE (defusedxml)
  - `dexsec/ai/reporter.py` — tabel & panel Next Steps
  - `dexsec/cli.py` — PHASE 5 = Next Step Advisor, report jadi PHASE 6
  - `demo/vulnerable_app.py` — route `/fetch` (SSRF), `/xml` (XXE, `do_POST`), `do_POST` handler
  - `docs/COVERAGE.md`, `ROADMAP.md`, `README.md`, `ARCHITECTURE.md` — sinkronisasi
- **Bug yang difix:** pola Django terlalu longgar sehingga mendeteksi `oast.url("ssrf")` sebagai route → now anchored ke awal baris; SSRF/XXE tertahan daftar NON_PROBEABLE; server demo lama masih jalan sehingga hasil scan menyesatkan (proses bernama `python3.11.exe`, bukan `python.exe`).
- **Verifikasi:** `python tests\selftest.py` → **PASSED** (`[1] confirmed=6` SQLi/Cmd/Path/IDOR/SSRF/XXE, `[2] 4 patch`, `[3] apply sukses`, `[4] setelah patch confirmed=2` = IDOR + SSRF yang memang tidak auto-fixable).
- **Status Saat Ini:** OK — Milestone 2 parsial (7 dari 12 item selesai).
- **Tugas untuk AI Berikutnya:**
  1. Selesaikan sisa Milestone 2: black-box OpenAPI fuzzing, LLM attack-chaining, taint AST-based, probe dinamis Mass Assignment/CSRF, deteksi cookie flags.
  2. Semua fitur baru wajib menambah assertion di `tests/selftest.py`.
  3. Update `CURRENT_STATE.md` + `ROADMAP.md` + `docs/COVERAGE.md`.

### [2026-10-21 22:10] - Verifikasi instalasi CLI + finalisasi rebranding — oleh Opencode
- **Modul yang disentuh:** `pyproject.toml` (entry point `dexsec.cli:main`), `dexsec/ai/reporter.py` (reconfigure stdout UTF-8 saat import), `dexsec/cli.py`, `dexsec/dast/probes.py`, `dexsec/dast/verifier.py`, `tests/selftest.py`, `demo/vulnerable_app.py` (env var `DEXSEC_DEMO_PORT`), `.gitignore` (BARU).
- **Bug yang difix:**
  - `dexsec` console script crash `UnicodeEncodeError` (cp1252) → reconfigure stream di `reporter.py` + entry point diarahkan ke `cli:main`.
  - `pip install -e .` gagal `invalid command 'bdist_wheel'` → butuh `setuptools>=70` + `wheel` (dokumentasi di `INSTALL.md` §2.2).
  - Selftest gagal start server → env var demoapp tidak sinkron (`DEX-SEC_DEMO_PORT` vs `DEXSEC_DEMO_PORT`).
  - Sisa referensi "SecFlow"/"secflow" di docstring & env key dibersihkan (`DEXSEC_AI_KEY`, `dexsec-oast`).
- **Verifikasi:** `pip install -e .` sukses → `dexsec version` = "DEX-SEC 0.2.0"; `dexsec scan --path . --target http://127.0.0.1:8765` → 7 route, 13 temuan, 4 confirmed, deployment-level `MISSING_SECURITY_HEADERS` muncul, laporan MD+JSON+patch tertulis; `python tests\selftest.py` → **SELFTEST PASSED**.
- **Catatan:** folder lama `C:\Users\ASUS\secflow` masih ada karena terkunci oleh sesi aktif — hapus manual (sudah usang, semua isinya sudah dipindah ke `C:\Users\ASUS\dex-sec`).
- **Tugas untuk AI Berikutnya:** lanjutkan **Milestone 2** sesuai `ROADMAP.md`; jangan lupa update `CURRENT_STATE.md` + `ROADMAP.md` + `docs/COVERAGE.md` bila menambah kelas celah baru.

### [2026-10-21 21:30] - Rebrand DEX-SEC + perluasan coverage — oleh Opencode
- **Modul yang disentuh:**
  - `dexsec/` (paket di-rename dari `secflow/`), `pyproject.toml` (name `dexsec`, script `dexsec`)
  - `dexsec/models.py` — 25 kelas celah baru
  - `dexsec/sast/rules.py` — 14 aturan baru (deserialization, code injection, SSTI, XXE, NoSQL, weak crypto, insecure random, JWT none, debug, open redirect, CORS) + aturan file/config
  - `dexsec/sast/access.py` (BARU) — IDOR/BOLA & missing auth check
  - `dexsec/sast/config_scan.py` (BARU) — `.env`, key files, Dockerfile, nginx
  - `dexsec/dast/probes.py` — probe open redirect, SSTI, NoSQL, JWT none
  - `dexsec/dast/verifier.py` — verifier baru + `verify_base_url()` (security headers & CORS)
  - `dexsec/core/correlator.py` — impact/remediation text untuk semua kelas baru + `standalone_findings()`
  - `dexsec/ai/patcher.py` — fallback patch untuk debug/weak crypto/insecure random/JWT/deserialization/CORS
  - `demo/vulnerable_app.py` — tambah route IDOR, open redirect, SSTI, profile; `demo/configs/.env`, `demo/configs/Dockerfile`
  - `tests/selftest.py` — ekspektasi baru (IDOR harus confirmed, secret file terdeteksi)
  - `INSTALL.md` (BARU), `docs/COVERAGE.md` (BARU), `npm/` (BARU), `README.md`, `ROADMAP.md`
- **Bug yang difix:** IDOR salah taint karena komentar demo mengandung kata "owner"; duplikasi baris enum di `models.py`; `_enclosing_window` melewati batas blok fungsi; query terparameterisasi salah dilaporkan sebagai SQLi.
- **Status Saat Ini:** OK — Milestone 1 lengkap, coverage 21 kelas terverifikasi.
- **Tugas untuk AI Berikutnya:**
  1. Baca `AI_HANDOFF.md` + `docs/COVERAGE.md` dulu.
  2. Ambil **Milestone 2** (lihat `ROADMAP.md`): OAST/Interactsh, parser Express/Django, Mass Assignment, CSRF, LLM next-step advisor, taint lintas file.
  3. Tiap aturan/fitur baru wajib menambah test di `tests/` dan tidak boleh menaikkan false positive pada `dexsec/` sendiri.
  4. Update `CURRENT_STATE.md` (tambah entry) + centang `ROADMAP.md`.
  5. Ingat: rename sudah selesai, jangan pakai nama "secflow" lagi di kode baru (nama lama hanya untuk referensi historis).
