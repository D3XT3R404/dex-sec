# PANDUAN OPERASIONAL DEX-SEC
### Panduan lengkap, step-by-step, untuk mulai memakai DEX-SEC

Dokumen ini untuk kamu yang **baru pertama kali** memakai DEX-SEC.
Tidak perlu paham security lebih dulu — cukup ikuti urutan langkah di bawah.

---

## BAGIAN 1 — PIKIRKAN APA ITU DEX-SEC (1 menit baca)

DEX-SEC adalah **alat cek keamanan untuk developer**. Analoginya seperti `eslint`
untuk kode, tapi untuk celah keamanan.

DEX-SEC bekerja dalam **dua arah**:

```
        KODE KAMU (dalam)                  WEBSITE KAMU (luar)
        ┌───────────────┐                  ┌────────────────┐
        │  app.py       │  ──1. baca──►   │  server jalan  │
        │  routes/       │                  │  di port 8080  │
        │  query SQL     │  ◄─3. buktikan─┤                │
        └───────────────┘                  └────────────────┘
                 │  2. tester aman (payload tidak merusak)
                 ▼
        "SQL Injection TERKONFIRMASI di baris 79"
        + PoC curl + patch otomatis
```

| Istilah | Artinya (bahasa sederhana) |
| --- | --- |
| **SAST** | Membaca kode sumber, mencari pola berbahaya |
| **DAST** | Mengirim request ke server yang hidup, melihat perilakunya |
| **Taint** | "Data user nyasar ke tempat berbahaya" (misal input user masuk query SQL) |
| **CONFIRMED_VULNERABLE** | **Terbukti bisa dieksploitasi** (ada buktinya, bukan cuma suspects) |
| **POTENTIAL** | Menarik, tapi belum bisa dibuktikan dari luar |
| **NOT_REPRODUCIBLE** | Sudah aman / tidak bisa ditembus dari luar |
| **PoC** | Proof of Concept — perintah curl yang membuktikan bug-nya |
| **Patch** | Perbaikan kode otomatis (format unified diff, bisa di-`git apply`) |

**Yang membuat DEX-SEC beda:** scanner biasa hanya menebak dari kode (banyak
false positive). DEX-SEC **membuktikan** setiap temuan dengan probe aman ke
server, jadi status "CONFIRMED" berarti memang bisa dieksploitasi.

---

## BAGIAN 2 — INSTALL (5 menit, sekali saja)

### 2.1 Cek Python
```powershell
python --version
```
Harus **3.10 atau lebih baru**. Kalau belum ada:
```powershell
winget install Python.Python.3.11
```

### 2.2 Install DEX-SEC
```powershell
cd C:\Users\ASUS\dex-sec
python -m pip install --upgrade setuptools wheel
python -m pip install -e .
```

### 2.3 Pastikan jalan
```powershell
dexsec version
```
Kalau muncul `DEX-SEC 0.3.0` → **berhasil**.

Kalau muncul *"dexsec tidak dikenali"*:
```powershell
python -m dexsec version
```
Itu cara yang sama persis, hanya prefixed `python -m`.

Atau cek kondisi instalasi:
```powershell
dexsec doctor
```
Outputnya akan menampilkan "OK" untuk dependency dan "OK" untuk console script.

### 2.4 (Opsional) Pakai tanpa Python sama sekali
Kalau mau menjalankan di komputer lain yang tidak ada Python-nya:
```powershell
pyinstaller dexsec.spec --noconfirm --clean
.\dist\dexsec.exe version
```
File `dist\dexsec.exe` (14 MB) bisa dipakai sendiri di mana saja.

---

## BAGIAN 3 — LATIHAN DENGAN APLIKASI CONTOH (10 menit)

Folder `sandbox\vuln_web` berisi aplikasi web **sengaja rentan** (SQL Injection)
yang aman dijalankan di komputermu sendiri.

### 3.1 Jalankan aplikasinya (Terminal 1)
```powershell
cd C:\Users\ASUS\dex-sec
pip install flask
python sandbox\vuln_web\app.py
```
Akan terlihat di terminal:
```
============================================================
 APLIKASI LATIHAN DEX-SEC (Sengaja rentan: SQL Injection)
 Buka:  http://127.0.0.1:8080
============================================================
```

### 3.2 Cek dengan browser
Buka http://127.0.0.1:8080 → ketik "kaos" di kotak pencarian → klik Cari.
Akan muncul daftar produk. (Normalnya begini.)

### 3.3 Jalankan DEX-SEC (Terminal 2 — baru)
```powershell
cd C:\Users\ASUS\dex-sec
dexsec scan --path sandbox\vuln_web --target http://127.0.0.1:8080
```

**Baca hasilnya dari atas ke bawah:**

1. **PHASE 1 — Inside Inspection**
   ```
   OK 3 route(s) and 2 tainted sink(s) found.
     GET  /                Flask - app.py:43
     GET  /search          Flask - app.py:75
     GET  /product/{id}    Flask - app.py:95
   ```
   → DEX-SEC menemukan 3 endpoint dan 2 titik berbahaya di kodemu.

2. **PHASE 2 — Outside Verification**
   ```
   OK 3 probe(s) executed, 1 confirmed exploitable.
   ```
   → DEX-SEC mengirim payload aman ke servermu, dan **satu bug terbukti bisa dieksploitasi**.

3. **PHASE 3 — Correlation**
   Tabel menunjukkan temuan dengan **status**:
   | Status | Arti | Tindakan |
   |---|---|---|
   | `CONFIRMED_VULNERABLE` | Terbukti exploitable | **Perbaiki sekarang** |
   | `POTENTIAL` | Menarik, belum terbukti | Periksa manual |
   | `NOT_REPRODUCIBLE` | Tidak bisa ditembus dari luar | Tidak ada aksi |
   | `SKIPPED` | Hanya analisis kode | Review manual |

4. **Panel detail** —-impact, cara memperbaiki, **bukti** (evidence), dan **PoC curl**:
   ```
   Safe PoC:
   curl -i -X GET 'http://127.0.0.1:8080/search?q=%27'
   ```
   → coba salin perintah itu di browser/terminal, kamu akan lihat error database. Itulah buktinya.

5. **PHASE 4 — AI Remediation** → diff patch otomatis
6. **PHASE 5 — Attack Chain** → kalau ada beberapa temuan, DEX-SEC menyambungkannya jadi skenario serangan.
7. **PHASE 6 — Next Step Advisor** → apa yang harus dicek berikutnya.

### 3.4 Buktikan sendiri (manual)
Di browser, buka:
```
http://127.0.0.1:8080/search?q='
```
Kamu akan melihat halaman "Database error". Itulah SQL Injection-nya.

### 3.5 Perbaiki otomatis, lalu buktikan
```powershell
# 1) lihat dulu apa yang akan berubah (tidak mengubah file)
dexsec fix --path sandbox\vuln_web --target http://127.0.0.1:8080 --dry-run

# 2) terapkan
dexsec fix --path sandbox\vuln_web --target http://127.0.0.1:8080

# 3) scan ulang → SQL_INJECTION harus jadi NOT_REPRODUCIBLE
dexsec scan --path sandbox\vuln_web --target http://127.0.0.1:8080
```
Hasilnya di `app.py` berubah dari:
```python
query = f"SELECT id, name, price FROM products WHERE name LIKE '%{keyword}%'"
```
menjadi:
```python
query = "SELECT id, name, price FROM products WHERE name LIKE ?"
rows = conn.execute(query, (f"%{keyword}%",)).fetchall()
```
Nowa **tidak bisa diinjeksi** — `keyword` jadi parameter, bukan bagian dari SQL.

Untuk mengembalikan sandbox ke kondisi semula (agar bisa latihan ulang):
```powershell
# hapus database contoh & salinan app yang terpatch
Remove-Item sandbox\vuln_web\products.db -ErrorAction SilentlyContinue
```

---

## BAGIAN 4 — PAKAI DI PROJECT ASLI KAMU (langkah penting)

### 4.1 Static analysis dulu (paling aman, tanpa server)
```powershell
dexsec scan --path .
```
Cukup untuk dipakai di repo mana pun, bahkan yang tidak kamu jalankan.

### 4.2 Dengan verifikasi ke server hidup
```powershell
# jalankan app-mu dulu di terminal lain, misal http://127.0.0.1:3000
dexsec scan --path . --target http://127.0.0.1:3000
```
> **Penting:** `--target` hanya boleh ke server yang **milikmu sendiri** atau yang
> kamu punya izin untuk mengujinya. Semua probe DEX-SEC dirancang read-only,
> tapi kamu tetap bertanggung jawab.

### 4.3 Laporan lengkap (untuk dibagikan / diarsipkan)
```powershell
dexsec scan --path . --target http://127.0.0.1:3000
```
Semua laporan otomatis dibuat di folder khusus **di dalam folder DEX-SEC**
(bukan di project yang kamu scan):
```
C:\Users\ASUS\dex-sec\hasil-scan\<nama-project>\<tanggal>/
   laporan.md   laporan.json   laporan.html   ringkasan.pdf   laporan.sarif
```
Kalau mau menentukan sendiri:
```powershell
dexsec scan --path . --target http://127.0.0.1:3000 --out-dir D:\laporan-keamanan
# atau set sekali untuk semua folder:
$env:DEXSEC_OUTPUT_ROOT = "D:\laporan-keamanan"
```

| File | Isi | Untuk siapa |
| --- | --- | --- |
| `laporan.md` | Laporan teks (Markdown) | Dokumentasi / PR |
| `laporan.json` | Data lengkap (bisa diparse) | Otomasi / CI |
| `laporan.html` | Laporan interaktif (bisa search & sort) | Dibuka di browser, dikirim via email |
| `ringkasan.pdf` | Ringkasan eksekutif 1-2 halaman | Ke atasan / manager |
| `laporan.sarif` | Format standar SARIF | GitHub Code Scanning & VS Code |

> **Catatan:** folder project yang kamu scan **tidak pernah diubah** oleh DEX-SEC.
> Semua hasil dikumpulkan di folder `hasil-scan`.

### 4.4 Menampilkan temuan langsung di PR (GitHub)
Tambahkan file `.github/workflows/dexsec.yml` (sudah ada contohnya di repo ini),
lalu taruh file SARIF-nya ke `github/codeql-action/upload-sarif`:
```yaml
      - uses: actions/upload-artifact@v4
        with:
          name: dexsec-report
          path: dexsec.sarif
```
Hasilnya: temuan muncul **inline di halaman Pull Request**.

### 4.5 Memakai di Terminal (dengan cepat)
```powershell
dexsec routes --path .        # daftar semua endpoint yang terdeteksi di kode
dexsec fuzz --spec openapi.yaml --target http://127.0.0.1:3000   # fuzzing berbasis API spec
```

---

## BAGIAN 5 — MENCEGAH REGRESI (workflow harian)

### 5.1 Pre-commit hook (blokir commit berbahaya)
```powershell
dexsec hook --install
```
Sekarang setiap `git commit` akan menjalankan analisis otomatis dan **menolak
commit** kalau ada temuan HIGH/CRITICAL baru. Untuk mematikan: hapus file
`.git\hooks\pre-commit`.

### 5.2 Bandingkan dengan baseline (untuk PR)
```powershell
# 1) di branch main, simpan kondisi sekarang sebagai baseline
dexsec scan --path . --skip-dast --write-baseline baseline.json

# 2) di branch feature, bandingkan
dexsec scan --path . --baseline ..\main\baseline.json
```
Outputnya:
```
Baseline comparison vs baseline.json: 1 baru, 0 naik severity, 2 sudah diperbaiki, 5 tidak berubah
  + [CRITICAL] SQL_INJECTION in app.py:79
```
→ **hanya temuan baru** yang ditampilkan. Tepat untuk gerbang PR.

### 5.3 Watch mode (scan otomatis saat kamu ngoding)
```powershell
dexsec watch --path . --target http://127.0.0.1:3000
```
Setiap kali file berubah → scan ulang otomatis, terminal menampilkan hanya yang
berubah. Tekan `Ctrl+C` untuk berhenti.

### 5.4 Notifikasi ke tim (Discord/Slack)
```powershell
dexsec scan --path . --target http://127.0.0.1:3000 `
    --notify "https://hooks.slack.com/services/XXX/YYY/ZZZ" --notify-level CRITICAL
```
DEX-SEC mendeteksi sendiri apakah itu webhook Slack atau Discord.

---

## BAGIAN 6 — MEMAHAMI TEKNISNYA (baca kalau mau tahu detail)

### 6.1 Alur kerja internal DEX-SEC
```
FASE 1  INSIDE (baca kode)
  ├─ Route discovery      : pola @app.route, @router.get, path(), Route::get, ...
  ├─ Taint analysis       : Python → AST (ast module), interprocedural
  │                         JS/TS → regex + const/let/var + template literal
  ├─ Access control       : IDOR/BOLA (route param id tanpa ownership check)
  ├─ Config scanning      : .env, *.pem, id_rsa, Dockerfile, nginx
  └─ Cookie/session rules : HttpOnly/Secure/SameSite, session fixation

FASE 2  OUTSIDE (probe aman ke server)
  ├─ SQLi      : timing probe (SLEEP), error signature DB, boolean differential,
  │              dan "payload bikin server crash" sebagai bukti
  ├─ Cmd inj   : canary echo (echo dexsec-canary-xxx)
  ├─ Path trav : marker file (/etc/passwd, C:\Windows\win.ini)
  ├─ SSRF/XXE  : OAST lokal — server dipaksa memanggil listener kita
  ├─ IDOR      : bandingkan id=1 vs id=999999999
  ├─ Mass assg : marker field dexsec_probe_field (tidak mengubah data)
  ├─ JWT none  : token unsigned vs token signature invalid
  ├─ SSTI      : aritmetika {{7*7}} harus jadi 49
  └─ Deployment: security headers, CORS, cookie, GraphQL introspection

FASE 3  KORELASI
  kode + bukti eksternal → CONFIRMED / POTENTIAL / NOT_REPRODUCIBLE

FASE 4  AI REMEDIATION
  LLM (OpenAI/Anthropic/Gemini) atau heuristik offline → unified diff
  → divalidasi (git apply --check ATAU applier internal) → baru ditawarkan

FASE 5  ATTACK CHAIN     : menggabungkan beberapa temuan jadi skenario
FASE 6  NEXT STEP        : rencana tindak lanjut + perintah aman
FASE 7  REPORT           : terminal + MD/JSON/HTML/PDF/SARIF
```

### 6.2 Kenapa probe-nya "aman"?
Semua payload designed read-only:
- Tidak ada `DROP`, `DELETE`, `rm`, atau perintah merusak.
- SQLi: hanya mengukur waktu respons & membaca pesan error.
- Command injection: hanya `echo` dengan marker, tidak menjalankan perintah lain.
- Mass assignment: mengirim field yang **tidak ada** di model, jadi tidak mengubah data.
- SSRF/XXE: callback ke listener lokal (127.0.0.1), bukan ke server pihak ketiga.

### 6.3 Kenapa pakai AST untuk Python?
Regex bisa salah paham. Contoh nyata yang pernah ditemukan saat pengembangan:
```python
# Vulnerability:
query = f"SELECT ... WHERE name = '{q}'"
rows = conn.execute(query).fetchall()

# Setelah dipatch (aman):
query = "SELECT ... WHERE name = ?"
rows = conn.execute(query, (q,)).fetchall()
```
Versi yang sudah diparameterisasi **tidak boleh** dilaporkan lagi. AST bisa
membedakan "nilai masuk ke dalam teks SQL" vs "nilai jadi parameter".
Dan AST bisa menelusuri antar-fungsi (`request.args` di satu fungsi → parameter
di fungsi lain).

### 6.4 Kapan DEX-SEC salah (batasan)?
- **False negative** mungkin terjadi pada pola yang sangat tidak biasa
  (misal query dibangun lewat obfuscasi atau reflection).
- **IDOR, CSRF, dan mass assignment**: deteksi utamanya berbasis analisis
  kode + heuristik; konfirmasi eksternal butuh dua akun/sesi.
- **CORS & header** dicek pada respons halaman utama; kalau header hanya muncul
  di route tertentu, belum ter-cover.
- **Tidak** mencakup: kelemahan dependency (itu pekerjaan `pip-audit`/`npm audit`),
  fuzzing biner, dan WAF.

---

## BAGIAN 7 — TROUBLESHOOTING

| Gejala | Penyebab & Solusi |
| --- | --- |
| `dexsec` tidak dikenali | Tutup & buka terminal baru (PATH baru), atau pakai `python -m dexsec` |
| `error: invalid command 'bdist_wheel'` | `python -m pip install --upgrade setuptools wheel` lalu ulangi install |
| `UnicodeEncodeError` | Jalankan `chcp 65001` di cmd, atau pakai PowerShell 7+ |
| Semua temuan `SKIPPED` | `--target` tidak diisi → hanya analisis kode |
| Semua temuan `NOT_REPRODUCIBLE` | Server tidak jalan / URL salah → cek `dexsec doctor --target ...` |
| `Connection refused` | Server belum start, atau port berbeda |
| Temuan yang sebenarnya bukan bug-mu | Beberapa rule terlalu umum → pakai `--json` lalu filter `status == "CONFIRMED_VULNERABLE"` |
| `dexsec fix` tidak mengubah apa pun | Patch tidak cocok dengan kode → edit manual memakai Diff yang ditampilkan |
| Unicode/emoji di output rusak | Sudah diperbaiki di v0.3.0; update: `pip install -e .` |

---

## BAGIAN 8 — REFERENSI PERINTAH LENGKAP

```powershell
dexsec scan  --path <dir> --target <url>   # audit lengkap 7 fase
dexsec scan  --path <dir> --skip-dast      # hanya statis
dexsec fix   --path <dir> [--dry-run]      # terapkan patch otomatis (+ commit)
dexsec watch --path <dir> --target <url>   # scan ulang saat file berubah
dexsec fuzz  --spec <openapi> --target <url>  # black-box fuzzing
dexsec routes --path <dir>                 # daftar endpoint di kode
dexsec hook  --install                     # pasang pre-commit hook
dexsec doctor [--target <url>]             # cek instalasi & target
dexsec version                             # versi tool
```

Flag `scan` yang berguna:
| Flag | Fungsi |
| --- | --- |
| `--report` / `--json` / `--html` / `--pdf` / `--sarif` | Keluarkan laporan dalam format berbeda |
| `--patch-out` | Nama file unified diff |
| `--apply-patches` | Terapkan patch langsung |
| `--baseline` / `--write-baseline` | Bandingkan / simpan baseline |
| `--notify` / `--notify-level` | Kirim notifikasi webhook |
| `--ai-key` / `--ai-provider` / `--ai-model` | Patch dengan LLM |
| `--timeout` | Timeout per request |

---

## RINGKASAN 5 BARIS

1. Install: `pip install -e .` → cek `dexsec version`
2. Latihan: `python sandbox\vuln_web\app.py` + `dexsec scan --path sandbox\vuln_web --target http://127.0.0.1:8080`
3. Project sendiri: `dexsec scan --path . --target http://127.0.0.1:PORT`
4. Perbaiki: `dexsec fix --path . --dry-run` → `dexsec fix --path .`
5. Cegah regresi: `dexsec hook --install` + `--baseline` di CI

Selamat mencoba! Kalau ada yang error, cek `dexsec doctor` dulu — itu biasanya
memberi tahu penyebabnya.
