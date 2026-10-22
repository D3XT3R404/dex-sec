# DEX-SEC — NPM wrapper

Wrapper resmi untuk tool **DEX-SEC** (Inside-Out Hybrid Application Security Testing CLI).

Tool intinya adalah Python; paket ini membuat perintah `dexsec` tersedia untuk
tiga Maven/Node/JS project tanpa harusremember langkah instalasi Python.

## Install

```bash
npm install -g dexsec
```

Wrapper akan memasang paket Python DEX-SEC secara otomatis pada pemakaian
pertama (butuh Python 3.10+ di PATH). Kalau ingin memasang manual:

```bash
pip install dexsec
```

## Pakai

```bash
dexsec scan --path . --target http://localhost:3000
dexsec scan --path . --skip-dast
dexsec fuzz --spec openapi.yaml --target http://localhost:3000
dexsec routes --path .
dexsec doctor
```

## Uninstall

```bash
npm uninstall -g dexsec
pip uninstall dexsec     # opsional
```

## Kenapa bukan tool JavaScript murni?

DEX-SEC butuh parsing AST, diff patching yang presisi, dan HTTP probing yang
mature. Ekosistem Python punya semua itu matang (ast, difflib, requests), jadi
implementasi intinya dibuat di Python dan NPM Distribution ini hanya
membungkuskannya. Kalau kamu butuh tool JS murni, bandingkan dengan Semgrep
(SAST) dan ZAP (DAST) — keduanya punya kekuatan di area yang berbeda.

MIT License.
