# Sandbox — Aplikasi Latihan DEX-SEC

Folder ini berisi aplikasi web **sengaja rentan** untuk kamu latihan memakai DEX-SEC.
Semua ada di lokal computer kamu, tidak ada yang dikirim ke internet.

## Isi

| File | Keterangan |
| --- | --- |
| `vuln_web/app.py` | Aplikasi Flask dengan **satu** kerentanan: **SQL Injection** pada `/search` |

## Langkah 1 — Jalankan aplikasinya

```powershell
cd C:\Users\ASUS\dex-sec
pip install flask
python sandbox\vuln_web\app.py
```

Terlihat di terminal:
```
============================================================
 APLIKASI LATIHAN DEX-SEC (Sengaja rentan: SQL Injection)
 Buka:  http://127.0.0.1:8080
============================================================
```

Buka browser → http://127.0.0.1:8080 → coba cari "kaos".

## Langkah 2 — Jalankan DEX-SEC (terminal kedua)

```powershell
cd C:\Users\ASUS\dex-sec
dexsec scan --path sandbox\vuln_web --target http://127.0.0.1:8080
```

Yang seharusnya terlihat:
- **Inside**: route `/`, `/search`, `/product/<id>` ditemukan, dan **SQL Injection** terdeteksi
  di `app.py` (query dirangkai dari `request.args.get("q")`).
- **Outside**: DEX-SEC mengirim payload aman ke `/search?q=...` dan melihat error
  `sqlite3.OperationalError` → status berubah jadi **CONFIRMED_VULNERABLE**.
--after itu: **Attack Chain**, **Next Step**, dan **patch otomatis**.

## Langkah 3 — Buktikan sendiri (manual)

Contoh payload yang **aman** (hanya membaca data dummy lokal):

```
http://127.0.0.1:8080/search?q='
```
→ muncul halaman "Database error".

Contoh payload **injeksi data** (aman untuk data latihan — hanya membaca baris yang sudah ada):
```
http://127.0.0.1:8080/search?q=%25%27+OR+%271%27%3D%271
```
→ error berubah / jumlah hasil bertambah, tanpa merusak data.

## Langkah 4 — Perbaiki otomatis, lalu buktikan

```powershell
dexsec fix --path sandbox\vuln_web --target http://127.0.0.1:8080 --dry-run   # lihat dulu
dexsec fix --path sandbox\vuln_web --target http://127.0.0.1:8080             # terapkan
dexsec scan --path sandbox\vuln_web --target http://127.0.0.1:8080            # scan ulang
```
Setelah patch, `SQL_INJECTION` berubah menjadi `NOT_REPRODUCIBLE`.

Untuk mengembalikan app ke kondisi semula: hapus file `sandbox/vuln_web/products.db`
lalu jalankan ulang `python sandbox\vuln_web\app.py`.

## Catatan etika

- Aplikasi ini hanya berjalan di `127.0.0.1` (tidak bisa diakses dari jaringan lain).
- Jangan pernah mengirim payload seperti ini ke server yang bukan milikmu.
- Kalau mau latihan di server sungguhan, pakai environment staging milikmu sendiri.

## Perintah DEX-SEC berguna di sandbox

```powershell
dexsec scan --path sandbox\vuln_web --skip-dast                 # static only
dexsec scan --path sandbox\vuln_web --target http://127.0.0.1:8080 --html report.html
dexsec scan --path sandbox\vuln_web --target http://127.0.0.1:8080 --sarif report.sarif
dexsec routes --path sandbox\vuln_web
```
