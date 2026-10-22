# DEX-SEC — Matriks Coverage Kerentanan

Status legend:
- ✅ **Selesai** — deteksi + verifikasi eksternal + rekomendasi perbaikan
- 🟡 **Terimplementasi (statis saja)** — deteksi kode/config + rekomendasi, tanpa probe eksternal
- 🔜 **Rencana** — sudah masuk antrian `ROADMAP.md`
- ⛔ **Di luar cakupan** — ditangani tool lain ( SCA, WAF, fuzzing, dll.)

---

## A. Injection & Eksekusi Kode

| Celah | CWE | Status | Cara DEX-SEC mendeteksinya | Verifikasi eksternal |
| --- | --- | --- | --- | --- |
| SQL Injection | CWE-89 | ✅ | Deteksi query yang dirangkai/di-format dari variabel tainted | Timing probe (blind), error-signature DB, boolean differential |
| NoSQL Injection | CWE-943 | ✅ | `$where`, `find(request…)`, `$ne`/`$gt`/`$regex` | Probe operator ke body JSON, cek refleksi operator |
| Command Injection | CWE-78 | ✅ | `os.system`, `subprocess`, `exec`, `child_process` | Canary `echo` (harmless) |
| Code Injection (eval/exec) | CWE-94 | ✅ | `eval`, `exec`, `new Function`, `setTimeout("…")` | Tidak diprobe (berisiko) — relies on static evidence |
| Server-Side Template Injection | CWE-1336 | ✅ | `render_template_string`, `Template(user_input)`, `from_string` | Probe aritmetika `{{7*7}}` → harus render `49` |
| XXE | CWE-611 | ✅ | `etree`, `minidom`, `xml.sax`, `lxml` tanpa `resolve_entities=False` | **Canary file lokal** (`file://`) + OAST callback |
| Insecure Deserialization | CWE-502 | ✅ | `pickle.loads`, `yaml.load`, `marshal`, `jsonpickle` | Tidak diprobe (berisiko) |

## B. Path, File & File Disclosure

| Celah | CWE | Status | Cara mendeteksi | Verifikasi |
| --- | --- | --- | --- | --- |
| Path Traversal / LFI | CWE-22 | ✅ | `open(user)`, `os.remove`, `fs.readFile` | Marker file sistem (`/etc/passwd`, `Windows\win.ini`) |
| Exposed Secret File | CWE-798 | ✅ | `.env` berisi nilai, `*.pem`, `id_rsa`, `.npmrc`, `.pypirc`, `*.tfstate`, `credentials.json` | — (statis) |
| Arbitrary File Write | CWE-73 | 🔜 | `open(..., 'w')` dengan path tainted | — |
| Zip Slip | CWE-22 | 🔜 | `ZipFile.extract` tanpa validasi path | — |

## C. Access Control (IDOR/BOLA & friends)

| Celah | CWE | Status | Cara mendeteksi | Verifikasi |
| --- | --- | --- | --- | --- |
| IDOR / BOLA | CWE-639 | ✅ | Route dengan param id **tanpa** ownership/role check di handler | Bandingkan `id=1` vs `id=999999999` (tanpa kredensial) |
| Missing Authentication on mutating route | CWE-306 | 🟡 | Route POST/PUT/PATCH/DELETE tanpa marker auth | — |
| Broken Object Level Authorization (role only) | CWE-862 | ✅ | Hanya ada role check, tanpa scoping per objek | IDS di atas |
| Privilege Escalation (role dari body) | CWE-269 | 🔜 | Field `role`/`is_admin` diambil dari request | — |
| Mass Assignment | CWE-915 | ✅ | `Model(**request.json)`, `Object.assign(user, req.body)` | Probe marker field (`dexsec_probe_field`) — data tidak berubah |
| JWT `alg:none` / signature disabled | CWE-347 | ✅ | `verify=False`, `algorithms=["none"]` | Kirim token unsigned vs token invalid, bandingkan status |
| Session fixation / weak cookie | CWE-384 | ✅ | Cookie tanpa `httponly`/`secure`/`samesite` | `Set-Cookie` di respons diperiksa langsung |

## D. Kripto, Session & Secrets

| Celah | CWE | Status | Cara mendeteksi | Verifikasi |
| --- | --- | --- | --- | --- |
| Hardcoded secret | CWE-798 | ✅ | Pola `api_key/secret/password/token = "..."` | — |
| Weak hash/cipher | CWE-327 | ✅ | `md5`, `sha1`, `DES`, `RC4` | — |
| TLS verification disabled | CWE-295 | ✅ | `verify=False`, `_create_unverified_context`, `CERT_NONE` | — |
| Insecure randomness untuk token | CWE-330 | ✅ | `random.*` di dekat token/secret | — |
| ECB mode / static IV | CWE-329 | 🔜 | `MODE_ECB`, `iv=0` | — |
| Missing password hashing (plaintext compare) | CWE-256 | 🔜 | `password ==` | — |

## E. Konfigurasi & Deployment

| Celah | CWE | Status | Cara mendeteksi | Verifikasi |
| --- | --- | --- | --- | --- |
| Debug mode aktif | CWE-489 | ✅ | `DEBUG=True`, `debug=True`, `ENV DEBUG=true` | — |
| Container jalan sebagai root | CWE-250 | ✅ | Dockerfile tanpa `USER` | — |
| Secret di Dockerfile/ENV | CWE-798 | ✅ | `ENV/ARG *SECRET*=` | — |
| CORS wildcard (dengan credentials) | CWE-942 | ✅ | `Access-Control-Allow-Origin: *`, `allow_origins=['*']` | Kirim `Origin` header, cek pantulan |
| Missing security headers | CWE-693 | ✅ | HSTS/CSP/X-Content-Type-Options/X-Frame-Options/Referrer-Policy | Cek header respons |
| Open redirect | CWE-601 | ✅ | `redirect(user_input)` | Minta redirect ke `example.com` marker |
| Directory listing aktif | CWE-548 | 🟡 | `autoindex on` | — |
| Insecure build step (`curl \| sh`) | CWE-494 | ✅ | Pola di Dockerfile | — |
| Cloud metadata SSRF | CWE-918 | ✅ | `requests/httpx/fetch` dengan URL tainted | **OAST lokal**: server dipaksa memanggil callback listener kita |
| Known vulnerable dependency | — | ⛔ | Milik SCA (pip-audit / npm audit / Trivy) — integrasi planned | — |

## F. Output & Client Side

| Celah | CWE | Status | Cara mendeteksi | Verifikasi |
| --- | --- | --- | --- | --- |
| Reflected XSS | CWE-79 | 🟡 | `innerHTML`, `document.write`, `\|safe`, `render_template_string` | — |
| SSTI | CWE-1336 | ✅ | Lihat bagian A | ✅ |
| Missing CSRF protection | CWE-352 | ✅ | Route mutating tanpa marker `csrf`/`xsrf` | — (statis; probe dinamis butuh dua sesi/akun) |
| Clickjacking | CWE-1021 | ✅ | melalui `MISSING_SECURITY_HEADERS` (X-Frame-Options) | ✅ |
| Open redirect | CWE-601 | ✅ | Lihat bagian E | ✅ |

## G. Yang sengaja DI LUAR cakupan

| Topik | Alasan |
| --- | --- |
| Fuzzing (AFL, libFuzzer) | Butuh instrumentation & waktu lama; khusus untuk tools fuzzer |
| SCA / audit dependency | Data CVE besar; pakai `pip-audit`, `npm audit`, `osv-scanner` |
| WAF / IDS / IPS | Marker yang berbeda: tool ini fokus pada cacat aplikasi |
| Fuzzing API (schema-based) | Black-box API fuzzing — rencana lanjutan (Fase 3) |
| Binary / native (C/C++) reversing | Butuh analisis biner; fokus DEX-SEC pada source code aplikasi web |
| Black-box-only pentest | DEX-SEC butuh source code sebagai sumber kebenaran |

---

## Ringkasan angka

| Status | Jumlah kelas |
| --- | --- |
| ✅ Deteksi + verifikasi eksternal | 23 |
| 🟡 Deteksi statis + rekomendasi | 3 |
| 🔜 Rencana (Milestone 2–3) | 10 |
| ⛔ Milik tool lain | 6 |

## Kemampuan pendukung (Milestone 2 & release readiness)

| Fitur | Status | Keterangan |
| --- | --- | --- |
| **Dukungan bahasa** | ✅ | Python (AST), PHP, JavaScript/TypeScript, Java/Kotlin, Go, C#, Ruby — semuanya data-driven di `dexsec/sast/languages.py` |
| **Route discovery PHP** | ✅ | Setiap file `.php` di bawah document root = endpoint, parameter diambil dari `$_GET/$_POST/$_REQUEST` |
| **PHP call graph** | ✅ | Sink di file library dilaporkan di halaman yang memanggilnya dengan data request |
| OAST listener lokal | ✅ | `dexsec/dast/oast.py` — HTTP callback server di 127.0.0.1 untuk membuktikan SSRF/XXE tanpa layanan eksternal |
| Next Step Advisor | ✅ | `dexsec/ai/advisor.py` — rencana tindak lanjut per temuan (heuristik offline + mode LLM) |
| Attack Chain Analysis | ✅ | `dexsec/ai/chaining.py` — menggabungkan temuan menjadi skenario eksploitasi (SSRF→metadata, IDOR→write, JWT none→impersonate, dst.) |
| Parser route multi-framework | ✅ | FastAPI, Flask, Django (`path`/`re_path`/`url`), Express, Laravel, Spring, Go, custom router Python (`do_POST`) |
| Taint lintas file | ✅ | Propagasi via import graph (`from x import y`) |
| AST taint analysis (Python) | ✅ | `dexsec/sast/ast_taint.py` — alur data nyata, interprocedural, aware bahwa query terparameterisasi aman |
| Taint JavaScript/TypeScript | ✅ | `const/let/var`, template literal, `req.*`, `res.sendFile`, `jwt.decode` |
| Black-box API fuzzing | ✅ | `dexsec fuzz --spec openapi.yaml` — payload read-only, rate limit, allow-list path/method |
| Deteksi cookie insecure | ✅ | Static (kode) + respons (`Set-Cookie` header) |
| Probe dinamis Mass Assignment | ✅ | Marker field `dexsec_probe_field` — tidak mengubah data |
| Cek GraphQL introspection | ✅ | Query standar ke `/graphql`, `/api/graphql`, `/gql` |
| Pre-commit hook | ✅ | `dexsec hook --install` — memblokir commit HIGH/CRITICAL |
| GitHub Action | ✅ | `.github/workflows/dexsec.yml` — artifact + fail build |
| Executable tunggal | ✅ | `pyinstaller dexsec.spec` → `dist/dexsec.exe` (tanpa Python di mesin target) |
| Wrapper NPM | ✅ | `npm install -g .` → perintah `dexsec` global |
| `dexsec doctor` | ✅ | Cek versi, dependency, PATH, dan keterjangkauan target |
