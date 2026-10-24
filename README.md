# DEX-SEC

**Inside-Out Hybrid Application Security Testing CLI** — membaca kode dari dalam, memverifikasi exploitability dari luar, lalu menghasilkan patch perbaikan otomatis.

```
KODE (dalam)  ──►  ROUTE MAP + TAINTED SINKS  ──►  TARGETED SAFE PROBE (luar)
                                                        │
                                     CONFIRMED / POTENTIAL / NOT REPRODUCIBLE
                                                        │
                            ┌───────────────────────────┼───────────────────────────┐
                            ▼                           ▼                           ▼
                     AI PATCH (git diff)      ATTACK CHAIN ANALYSIS      NEXT STEP ADVISOR
                            │                           │                           │
                            └────────────►  REPORT (terminal + MD + JSON)  ◄──────┘
```

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.3.0-orange.svg)](CHANGELOG.md)

## Kenapa berbeda dari scanner biasa

| Tool biasa | DEX-SEC |
| --- | --- |
| SAST hanya baca kode, banyak false positive | Kode + bukti eksploitasi eksternal = status `CONFIRMED_VULNERABLE` |
| DAST buta, tidak tahu struktur aplikasi | Hanya menguji endpoint yang memang mencurigai dari kode |
| Laporan PDF abstrak | Diff patch siap pakai + PoC `curl` yang aman |
| Butuh API key untuk hasil berguna | Patching heuristik offline sebagai fallback |
| Hanya bisa scan satu mode | Static **dan** black-box (OpenAPI fuzzing) dalam satu tool |

## Bahasa yang didukung

| Bahasa | Deteksi kode | Deteksi route | Catatan |
| --- | --- | --- | --- |
| **Python** | ✅ AST (alur data nyata, interprocedural) | FastAPI, Flask, Django, custom router | paling akurat |
| **PHP** | ✅ `$_GET/$_POST/$_REQUEST/$_FILES`, mysqli/PDO, `system`, `include`, `unserialize`, `echo` | ✅ setiap file `.php` = endpoint (dengan parameter query) | + call graph: sink di library dilaporkan di halaman pemanggilnya |
| **JavaScript / TypeScript** | ✅ template literal, `const/let/var`, `child_process`, `fs`, `axios` | Express, Next.js, Fastify | |
| **Java / Kotlin** | ✅ `getParameter`, JDBC, `Runtime.exec`, `ObjectInputStream` | Spring, JAX-RS | |
| **Go** | ✅ `r.URL.Query().Get`, `db.Query(fmt.Sprintf)`, `exec.Command` | `http.HandleFunc` | |
| **C#** | ✅ `Request.Query`, `SqlCommand`, `Process.Start`, `File.ReadAllText` | ASP.NET `[HttpGet]` | |
| **Ruby** | ✅ `params[:x]`, `where("...")`, `system`, `raw(...)` | Rails | |

Tambah bahasa baru? Cukup tambahkan satu blok `LanguageSpec` di
`dexsec/sast/languages.py` — mesin analysenya tidak perlu diubah.

## Bentuk tool

CLI, bukan GUI/web app. Sekali di-install perintahnya `dexsec` tersedia di terminal mana pun.
Sudah terbit di PyPI: <https://pypi.org/project/dexsec/>
Detail lengkap: **[INSTALL.md](INSTALL.md)**.

## TUTORIAL: 5 menit pakai DEX-SEC

### Langkah 1 — Install (sekali saja)
```bash
pip install dexsec
dexsec version          # harus keluar: DEX-SEC 0.7.2
```
Untuk developer yang mau mengubah kodenya sendiri (mode editable):
```powershell
# Clone/ekstrak source dulu, lalu jalankan dari folder projectnya:
git clone https://github.com/D3XT3R404/dex-sec.git
cd dex-sec
python -m pip install --upgrade setuptools wheel
python -m pip install -e .
```
Alternatif tanpa Python di mesin target: unduh `dexsec-windows-x64.exe` (atau varian Linux/macOS)
dari [Releases](https://github.com/D3XT3R404/dex-sec/releases/latest) — satu file, tanpa instalasi.
> Kalau `dexsec` "tidak dikenali", buka terminal baru (PATH baru berlaku di terminal baru),
> atau pakai `python -m dexsec ...` (fungsinya identik).

Cek kondisi instalasi kapan saja:
```powershell
dexsec doctor                                  # versi, dependency, PATH
dexsec doctor --target http://localhost:3000   # + target bisa dijangkau?
```

### Langkah 2 — Jalankan target uji (opsional, buat lihat hasilnya)
```powershell
python demo\vulnerable_app.py       # aplikasi sengaja rentan, http://127.0.0.1:8765
```

### Langkah 3 — Audit
```powershell
# A. Static only (tanpa server jalan) — aman untuk repo mana pun
dexsec scan --path .

# B. Static + verifikasi eksploitasi ke target hidup
dexsec scan --path . --target http://127.0.0.1:8765

# C. Lengkap: laporan + file patch
dexsec scan --path . --target http://127.0.0.1:8765 --report report.md --json report.json

# D. Black-box fuzzing dari OpenAPI spec
dexsec fuzz --spec demo\openapi.yaml --target http://127.0.0.1:8765

# E. Daftar route API yang terdeteksi di kode
dexsec routes --path .
```

### Langkah 4 — Baca hasilnya
1. **Tabel hasil** → status tiap temuan: `CONFIRMED_VULNERABLE` (bukti eksploitasi ada),
   `POTENTIAL` (menarik, belum terbukti), `NOT_REPRODUCIBLE` (sudah aman).
2. **Panel detail** → dampak, cara perbaikan, bukti eksploitasi, dan PoC `curl` siap pakai.
3. **Attack Chains** → beberapa temuan digabung jadi skenario eksploitasi nyata.
4. **Next Steps** → rencana tindak lanjut + perintah aman yang bisa dijalankan.
5. **Patch otomatis** → `dexsec-fixes.patch`, cek dulu: `git apply --check dexsec-fixes.patch`.

### Langkah 5 — Terapkan patch (opsional)
```powershell
git apply --check dexsec-fixes.patch   # pastikan aman dulu
git apply dexsec-fixes.patch
# atau langsung: dexsec scan --path . --target ... --apply-patches
```

### Blocker commit otomatis
```powershell
dexsec hook --install     # pasang pre-commit hook (blokir HIGH/CRITICAL)
```

### Cara pakai di harian / CI
```powershell
# sebelum commit
dexsec scan --path . --target http://localhost:3000 --apply-patches
git diff
```
```yaml
# GitHub Actions (siap pakai di .github/workflows/dexsec.yml)
- run: pip install ./
- run: dexsec scan --path . --target ${{ secrets.STAGING_URL }} --json dexsec.json
```

### Kalau butuh patch yang lebih"contextual" (opsional)
```powershell
$env:DEXSEC_AI_KEY = "sk-..."          # OpenAI / Anthropic / Gemini
dexsec scan --path . --target http://127.0.0.1:8765 --ai-provider openai --ai-model gpt-4o-mini
```
Tanpa API key pun tool tetap jalan (patch pakai heuristik offline).

### Perintah cheat sheet
| Perintah | Fungsi |
| --- | --- |
| `dexsec scan --path <dir> --target <url>` | Audit lengkap 7 fase |
| `dexsec scan --path <dir> --skip-dast` | Analisis statis saja |
| `dexsec scan --format json\|sarif\|md\|html` | Output machine-readable ke stdout (untuk CI/editor) |
| `dexsec fix --path <dir> [--dry-run]` | **Terapkan patch otomatis** (+ commit git opsional) |
| `dexsec watch --path <dir> --target <url>` | Scan ulang otomatis saat file berubah |
| `dexsec fuzz --spec <openapi> --target <url>` | Black-box API fuzzing (aman) |
| `dexsec routes --path <dir>` | Daftar route HTTP di kode |
| `dexsec config` / `dexsec init` | Lihat / buat file konfigurasi (`dexsec.toml`) |
| `dexsec manual` | Baca panduan lengkap **offline** (ikut ter-install) |
| `dexsec hook --install` | Pasang pre-commit hook |
| `dexsec doctor [--target <url>]` | Cek instalasi & target |
| `dexsec upgrade` | Cek versi terbaru & perbarui (untuk binary) |
| `dexsec version` | Info versi |

## Konfigurasi (opsional)

Buat file konfigurasi supaya tidak mengulang opsi di setiap perintah:

```powershell
dexsec init              # membuat dexsec.toml di project ini
dexsec init --scope user # atau di ~/.config/dexsec/config.toml
```

```toml
exclude = ["vendor", "storage"]   # folder tambahan yang dilewati
min_severity = "MEDIUM"           # sembunyikan temuan di bawah ini
target = "http://127.0.0.1:3000"  # target default

[notify]
url = "https://hooks.slack.com/services/..."
level = "CRITICAL"

[ai]
provider = "openai"
model = "gpt-4o-mini"
key_env = "DEXSEC_AI_KEY"
```
Semua nilai bisa ditimpa per perintah (`--target`, `--min-severity`, dst).

## 7 Fase Pipeline

1. **Inside Inspection** — route discovery (FastAPI/Flask/Django/Express/Laravel/Spring/Go + custom router Python) + deteksi sink bertaint (**AST-based untuk Python**, regex untuk bahasa lain) + taint lintas file + analisis access control (IDOR/BOLA) + scan file konfigurasi (`.env`, Dockerfile, nginx) + cookie/session checks.
2. **Outside Safe Verification** — probe read-only: timing (blind SQLi), error-signature, boolean differential, canary echo, file marker, open redirect, SSTI, NoSQL operator, JWT `alg:none`, IDOR object diff, **OAST lokal (SSRF/XXE)**, mass-assignment marker, security headers, CORS, GraphQL introspection.
3. **Correlation** — menggabungkan status kode & bukti eksternal → `CONFIRMED_VULNERABLE` / `POTENTIAL` / `NOT_REPRODUCIBLE` + severity akhir.
4. **AI Remediation** — LLM menghasilkan unified diff; jika tanpa API key, heuristik offline membuatkan patch. Semua patch divalidasi sebelum ditawarkan.
5. **Attack Chain Analysis** — menggabungkan beberapa temuan menjadi skenario eksploitasi nyata (SSRF→metadata→kredensial, IDOR→write, JWT none→impersonasi, dst).
6. **Next Step Advisor** — rencana tindak lanjut per temuan: apa yang harus dicek berikutnya, apa risikonya, dan perintah aman yang bisa dijalankan. Mode heuristik offline (default) atau mode LLM.
7. **Report** — ringkasan Rich di terminal + **Markdown, JSON, HTML interaktif, Executive Summary PDF, dan SARIF** (untuk GitHub Code Scanning & IDE).

## Panduan lengkap

📘 **[docs/PANDUAN-OPERASIONAL.md](docs/PANDUAN-OPERASIONAL.md)** — panduan step-by-step untuk pemula: install → latihan dengan aplikasi contoh → memakai di project sendiri → workflow harian & CI.
🎓 **[sandbox/vuln_web/README.md](sandbox/vuln_web/README.md)** — aplikasi web latihan yang sengaja rentan (SQL Injection) untuk mencoba DEX-SEC sendiri.
📊 **[docs/COVERAGE.md](docs/COVERAGE.md)** — matriks seluruh kelas kerentanan.
🧩 **[docs/schema/audit-report.schema.json](docs/schema/audit-report.schema.json)** — skema JSON laporan (untuk integrasi tool lain).

## Coverage kerentanan

Lihat **[docs/COVERAGE.md](docs/COVERAGE.md)** untuk matriks lengkap (21 kelas sudah deteksi + verifikasi, 4 statis saja, 13 terjadwal, sisanya milik tool lain).

## Keamanan

Semua probe **non-destruktif**: tidak ada `DROP`/`DELETE`/`rm`; hanya mengukur delay, membaca error, dan mencocokkan canary/penanda file.

## Gimana tool ini memindai & di mana hasilnya

**Pemindaian = rekursif penuh.**Diberi satu folder, DEX-SEC membaca **seluruh
pohon folder** (root + semua subfolder, tanpa batas kedalaman), lalu melewati
folder yang memang tidak relevan: `.git`, `node_modules`, `__pycache__`,
`venv/.venv`, `dist/build`, `vendor`, `site-packages`, dan sejenisnya.

```
dexsec scan --path C:\path\ke\project
  └─ dibaca: project\file.py
     project\sub\file.py
     project\sub\module\file.php     ← subfolder ikut
     project\sub\deep\nested\file.js ← nested ikut
```

**Hasil scan tidak pernah ditulis ke folder yang discan.** Semua laporan
diletakkan di folder khusus:

```
<folder-projek>\hasil-scan\<nama-project>\<timestamp>-<host>\
   ├── laporan.md      ringkasan Markdown
   ├── laporan.json    data lengkap (untuk CI / tool lain)
   ├── laporan.html    laporan interaktif (search & sort)
   ├── ringkasan.pdf   ringkasan eksekutif
   ├── laporan.sarif   format SARIF (GitHub Code Scanning / IDE)
   └── dexsec-fixes.patch   usulan perbaikan
```
Ganti lokasi dengan `--out-dir <folder>` atau env `DEXSEC_OUTPUT_ROOT`.

## Self-test

```powershell
python tests\selftest.py
```
Mendemonstrasikan round-trip: celah confirmed → patch otomatis → `git apply` → scan ulang → celah tersebut hilang.

## Struktur

```
dexsec/         paket Python (sast/ dast/ core/ ai/ cli.py models.py hooks.py)
demo/           aplikasi uji yang sengaja rentan + contoh config/CD + openapi.yaml
docs/           COVERAGE.md
npm/            wrapper NPM
.github/        GitHub Action
dist/           dexsec.exe (file tunggal, hasil PyInstaller)
tests/          selftest.py, test_features.py, list_findings.py
INSTALL.md      panduan instalasi & penggunaan
CHANGELOG.md    riwayat rilis
ROADMAP.md      antrian kerja      CURRENT_STATE.md   log sinkronisasi
AI_HANDOFF.md   protokol kolaborasi multi-AI            ARCHITECTURE.md  desain
```

## Lisensi

MIT — lihat [LICENSE](LICENSE). Jalankan hanya pada sistem yang kamu miliki atau
yang kamu punya izin untuk mengujinya.
