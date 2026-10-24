# DEX-SEC — Panduan Instalasi & Penggunaan

> **DEX-SEC** = *Inside-Out Hybrid Application Security Testing CLI*
> Membaca kode dari dalam → memverifikasi exploitability dari luar → menghasilkan patch perbaikan.

---

## 1. Bentuk toolnya: apa yang sebenarnya di-install?

DEX-SEC adalah **CLI (Command Line Interface)**, bukan aplikasi GUI dan bukan web app.

| Pertanyaan | Jawaban |
| --- | --- |
| Bentuk file | Satu paket Python bernama `dexsec` + satu entry point `dexsec` (file `.exe` shim di Windows / symlink script di Linux-macOS) |
| Ter-install di mana | Di environment Python milik user: `C:\Users\<user>\AppData\Roaming\Python\Python311\Scripts\dexsec.exe` (Windows) atau `~/.local/bin/dexsec` (Linux/macOS) |
| Package-nya di mana | `site-packages/dexsec/` — misal `C:\Users\<user>\AppData\Local\Programs\Python\Python311\Lib\site-packages\dexsec\` |
| Dijalankan di mana | **Di mana saja** — terminal mana pun di laptop developer, atau di runner CI/CD. Tidak perlu server, tidak perlu database, tidak perlu Docker. |
| Butuh target hidup? | Tidak wajib. Tanpa `--target` tool hanya melakukan static analysis. Dengan `--target` tool melakukan verifikasi eksploitasi yang aman. |
| Butuh internet? | Tidak. Semua analisis berjalan offline. Internet hanya dipakai kalau Anda mengaktifkan generator patch berbasis LLM. |
| Butuh API key? | Tidak wajib. Tanpa API key, patch dibuat dengan heuristik offline. Dengan `--ai-key`, patch dibuat oleh LLM. |

Intinya: **DEX-SEC di-install sekali di mesin Anda, lalu dipanggil dari terminal kapan pun**, seperti `git` atau `eslint`.

---

## 2. Cara instalasi

### 2.1 Persiapan ( sekali saja )

Butuh **Python 3.10+**. Cek dulu:

```powershell
python --version     # harus >= 3.10
```

Belum punya? Unduh dari python.org (centang *Add to PATH*). Alternatif: install via winget.

```powershell
winget install Python.Python.3.11
```

### 2.2 Metode A — Dari source (paling umum untuk developer)

```powershell
# Clone source dulu (atau ekstrak ZIP dari GitHub Releases),
# lalu jalankan dari folder projectnya:
git clone https://github.com/D3XT3R404/dex-sec.git
cd dex-sec
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .            # mode editable: kode bisa kamu ubah langsung
```

> **Penting (Windows / Microsoft Store Python):** paket `wheel` dan `setuptools` modern
> wajib ada, tanpa itu `pip install -e .` gagal dengan `error: invalid command 'bdist_wheel'`.
> Perintah di atas memasang keduanya.

Verifikasi:

```powershell
dexsec version
# atau tanpa install:
python -m dexsec version
```

Perintah `dexsec` sekarang tersedia di terminal. Kalau PowerShell bilang *"tidak dikenali sebagai cmdlet"*, folder `Scripts` belum ada di PATH. Lokasi `Scripts` berbeda tergantung edition Python:

| Python yang dipakai | Lokasi `Scripts` |
| --- | --- |
| Python.org (installer biasa) | `C:\Users\<user>\AppData\Roaming\Python\Python311\Scripts` |
| Microsoft Store | `C:\Users\<user>\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_<hash>\LocalCache\local-packages\Python311\Scripts` |

Tambahkan ke PATH secara permanen (untuk user saat ini):

```powershell
$scripts = "C:\Users\ASUS\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\LocalCache\local-packages\Python311\Scripts"
[Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH","User") + ";$scripts", "User")
```

Alternatif tanpa mengubah PATH: selalu pakai `python -m dexsec ...` (berfungsi identik).

### 2.3 Metode B — pipx (isolasi, recommended untuk tool CLI)

```powershell
pipx install .          # dari folder project
# atau dari paket PyPI später: pipx install dexsec
```

Pipx membuat virtualenv khusus sehingga tidak bentrok dengan dependency project lain.

### 2.4 Metode C — Dari PyPI (untuk pengguna akhir)

```powershell
pip install dexsec
```

Paket ini sudah terbit di PyPI: <https://pypi.org/project/dexsec/>

```powershell
pip install dexsec          # versi terbaru
pip install dexsec==0.7.2   # versi tertentu
```

Setelan upgrade: `pip install -U dexsec`.

Rilis manual dari source tetap tersedia bila perlu: `python -m build && twine upload dist/*`
(panduan lengkap ada di `docs/PUBLISH.md`).

### 2.5 Metode D — File executable tunggal (Windows / Linux / macOS)

Tidak butuh Python ter-install di mesin target. Build dari source:

```powershell
pip install pyinstaller
pyinstaller dexsec.spec --noconfirm --clean
# hasil: dist\dexsec.exe   (satu file, sekitar 14 MB)
```

Verifikasi:

```powershell
.\dist\dexsec.exe version
.\dist\dexsec.exe scan --path . --target http://localhost:3000
```

Untuk Linux/macOS, jalankan build di OS tersebut (atau lewat GitHub Actions
dengan `matrix.os`), lalu distribusikan `dist/dexsec`.

### 2.6 Metode E — NPM (wrapper untuk tim JS/Node)

Folder `npm/` berisi wrapper NPM resmi:

```powershell
cd npm
npm install -g .          # mendaftarkan perintah global `dexsec`
dexsec scan --path . --target http://localhost:3000
```

Cara kerjanya: paket NPM berisi `bin/dexsec.js` yang memasang & memanggil
paket Python DEX-SEC. Kalau Python tidak ada, wrapper memberi pesan instalasi
yang jelas. Detail: `npm/README.md`.

> Untuk toolbox JavaScript murni, bandingkan dengan tool JS stateless seperti
> Semgrep (SAST) dan ZAP (DAST). DEX-SEC sengaja memakai Python karena parsing
> AST, diff patching, dan HTTP probing jauh lebih matang di ekosistem itu.

### 2.7 Metode F — Docker (untuk CI, tanpa mengotori host)

```powershell
docker build -t dexsec .
docker run --rm -v "${PWD}:/app" -v "${PWD}:/src" dexsec scan --path /src --target http://host.docker.internal:3000
```

### 2.8 Metode G — GitHub Actions (scan otomatis setiap push)

Sudah ada workflow siap pakai di `.github/workflows/dexsec.yml`. Salin ke repo
tujuan, lalu isi target staging lewat secret `STAGING_URL`:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with: { python-version: "3.11" }
- run: pip install ./
- run: dexsec scan --path . --target ${{ secrets.STAGING_URL }} --json dexsec.json
- uses: actions/upload-artifact@v4
  with: { name: dexsec-report, path: dexsec.json }
```

Workflow yang disertakan juga: menjalankan static analysis selalu, mengunggah
laporan sebagai artifact, dan **gagalkan build** bila ada temuan HIGH/CRITICAL
yang terkonfirmasi.

### 2.9 Metode H — Pre-commit hook (blokir commit berbahaya)

```powershell
dexsec hook --install     # menulis .git/hooks/pre-commit
```

Hook menjalankan analisis statis pada file yang di-staging dan menolak commit
bila ada temuan HIGH/CRITICAL baru. Matikan dengan menghapus file hook.

---

## 3. Cara menjalankan (cheat sheet)

```powershell
# 1. Audit statis saja (tanpa server yang jalan)
dexsec scan --path .

# 2. Audit statis + verifikasi eksploitasi ke target hidup
dexsec scan --path . --target http://localhost:3000

# 3. Laporan lengkap (Markdown + JSON) + file patch
dexsec scan --path . --target http://localhost:3000 --report report.md --json report.json

# 4. Terapkan patch otomatis (hanya yang lolos `git apply --check`)
dexsec scan --path . --target http://localhost:3000 --apply-patches

# 5. Pakai LLM untuk membuat patch yang lebih kontekstual
$env:DEXSEC_AI_KEY = "sk-..."
dexsec scan --path . --target http://localhost:3000 --ai-provider openai --ai-model gpt-4o-mini

# 6. Daftar route API yang terdeteksi di dalam kode
dexsec routes --path .

# 7. Black-box fuzzing berbasis OpenAPI spec
dexsec fuzz --spec openapi.yaml --target http://localhost:3000

# 8. Pasang pre-commit hook (blokir HIGH/CRITICAL)
dexsec hook --install

# 9. Cek instalasi & target
dexsec doctor --target http://localhost:3000
```

### Flag lengkap `dexsec scan`

| Flag | Default | Fungsi |
| --- | --- | --- |
| `--path`, `-p` | `.` | Folder project yang di-audit |
| `--target`, `-t` | — | Base URL aplikasi yang hidup untuk verifikasi |
| `--skip-dast` | off | Hanya analisis statis (tanpa probe) |
| `--report`, `-r` | — | Tulis laporan Markdown |
| `--json` | — | Tulis laporan JSON |
| `--patch-out` | `dexsec-fixes.patch` | Nama file unified diff |
| `--apply-patches` | off | Terapkan patch dengan `git apply` (dicek dulu) |
| `--timeout` | `8.0` | Timeout per request (detik) |
| `--ai-key` | env `DEXSEC_AI_KEY` | API key LLM |
| `--ai-provider` | `openai` | `openai` \| `anthropic` \| `gemini` |
| `--ai-model` | `gpt-4o-mini` | Model id |

---

## 4. Contoh workflow harian developer

```powershell
# Saat mau commit
dexsec scan --path . --target http://localhost:3000 --apply-patches
git diff          # review patch yang dihasilkan
git add -A && git commit -m "fix: parameterise SQL query in user search"
```

## 5. Contoh workflow di tim / CI

```powershell
dexsec scan --path . --target https://staging.kampus.ac.id `
            --json dexsec.json --report dexsec.md
# lalu unggah sebagai artifact / kirim ke Slack
```

## 6. Pemecahan masalah

| Gejala | Penyebab & Solusi |
| --- | --- |
| `dexsec` tidak ditemukan | Scripts folder belum di PATH → lihat 2.2, atau pakai `python -m dexsec` |
| `error: invalid command 'bdist_wheel'` | `wheel`/`setuptools` lama → `pip install --upgrade setuptools wheel` |
| `UnicodeEncodeError` saat output | Jalankan `chcp 65001` di cmd / gunakan PowerShell 7+ |
| Probe timeout | Target tidak hidup / URL salah → coba `--skip-dast` |
| `git apply` gagal | File target sudah berubah → jalankan ulang `dexsec scan` (patch dibuat dari kode terkini) |
| LLM error | API key salah / provider tidak terpasang → `pip install -e ".[llm]"` |
| Ditemukan terlalu banyak finding | Naikkan ambang: filter `--json` lalu lihat `status != CONFIRMED_VULNERABLE` |
| `dexsec doctor` bilang "console script not on PATH" |install ulang dengan `pip install .` atau pakai `python -m dexsec` |
| NPM: `dexsec` tidak ada | `npm install -g .` dari folder `npm/`, lalu buka terminal baru |

## 7. Uninstall

```powershell
pip uninstall dexsec          # atau
pipx uninstall dexsec
npm uninstall -g dexsec        # kalau memakai wrapper NPM
```

Hapus konfigurasi: `C:\Users\<user>\AppData\Roaming\Python\Python311\Scripts\dexsec.exe`
dan hook pre-commit: `.git/hooks/pre-commit`

---

## 8. Struktur folder setelah instalasi

```
C:\Users\ASUS\dex-sec\                 # folder source project
├── dexsec\                            # paket Python (ter-install ke site-packages)
│   ├── cli.py  models.py
│   ├── sast\  dast\  core\  ai\
├── demo\       # aplikasi uji yang sengaja rentan
├── tests\      # self-test otomatis
├── docs\       # COVERAGE.md (matriks celah)
├── npm\        # wrapper NPM
├── INSTALL.md  README.md  ROADMAP.md  ARCHITECTURE.md
├── AI_HANDOFF.md  CURRENT_STATE.md   # protokol kolaborasi multi-AI
└── pyproject.toml requirements.txt
```
