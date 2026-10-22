# PANDUAN PUBLISH DEX-SEC

Dokumen ini berisi setup sekali saja untuk maintainer, lalu cara rilis berikutnya.

Kanal distribusi yang didukung:

| Kanal | Perintah untuk user | Peran |
| --- | --- | --- |
| **PyPI** | `pip install dexsec` | kanal utama |
| **Binary** | unduh dari GitHub Release | untuk user tanpa Python |
| **NPM** | `npm install -g dexsec` | untuk tim JavaScript |
| **Docker / GH Action** | lihat `INSTALL.md` | untuk CI |

---

## 1. Persiapan sekali saja

### 1.1 Repository GitHub
Buat repo (misal `your-org/dex-sec`), push semua isi:

```powershell
cd C:\Users\ASUS\dex-sec
git init
git add .
git commit -m "feat: DEX-SEC 0.7.0"
git branch -M main
git remote add origin https://github.com/your-org/dex-sec.git
git push -u origin main
```

> Pastikan `dexsec.egg-info/`, `build/`, `dist/`, `hasil-scan/` tidak ikut ter-commit.
> `.gitignore` di repo ini sudah mengecualikan folder-folder tersebut.

### 1.2 Akun PyPI
1. Daftar di <https://pypi.org/account/register/> (butuh 2FA).
2. Buat API token: **Account → API tokens → Add token** (scope: *Entire account* atau
   *Project: dexsec*).
3. **PENTING:** simpan token sebagai secret di GitHub:
   **Settings → Secrets and variables → Actions → New repository secret** → `PYPI_API_TOKEN`.
   (Alternatif yang lebih aman: **Trusted Publishing** seperti di bagian 3.)

### 1.3 GitHub Release
Aktifkan **Settings → Actions → General → Workflow permissions → Read and write**.
Workflow `release.yml` memakai `id-token: write` (untuk PyPI Trusted Publishing) dan
`contents: write` (untuk membuat release).

### 1.4 NPM (opsional)
Buat token di npmjs.com → **Access Tokens → Generate Token** (scope: *Publish*),
lalu simpan sebagai GitHub secret `NPM_TOKEN`.

---

## 2. Rilis biasa (per releases)

```powershell
# 1. naikkan versi
#    pyproject.toml  -> version = "0.8.0"
#    (dexsec/__init__.py membaca versi dari metadata, jadi tidak perlu diubah)

# 2. catat perubahannya di CHANGELOG.md

# 3. jalankan test lokal
python tests\selftest.py
python tests\test_features.py

# 4. tag & push -> seluruh pipeline berjalan otomatis
git add -A
git commit -m "release: v0.8.0"
git tag v0.8.0
git push origin main --tags
```

Yang terjadi otomatis:

1. **verify** — test suite dijalankan di 4 versi Python × 3 OS.
2. **pypi** — wheel + sdist dibangun dan di-upload ke PyPI.
3. **binaries** — 6 executable dibangun (Windows/Linux/macOS × x64/arm64).
4. **release** — GitHub Release dibuat dengan lampiran binary + paket Python +
   release notes dari `CHANGELOG.md`.
5. **npm** — wrapper NPM dipublish (kalau `NPM_TOKEN` diset).

Cek hasilnya:
```powershell
pip install -U dexsec
npm view dexsec version
```

---

## 3. Alternatif: PyPI Trusted Publishing (tanpa token)

Lebih aman karena tidak ada token yang tersimpan:

1. Di PyPI, buka project `dexsec` → **Manage → Publishing → Add a GitHub publisher**.
2. Masukkan: owner `your-org`, repository `dex-sec`, workflow `release.yml`,
   environment `pypi`.
3. Di workflow, ganti langkah publish:

```yaml
      - name: Publish
        uses: pypa/gh-action-pypi-publish@release/v1
        # tanpa password: -> memakai OIDC token
```

4. Di GitHub, buat **environment** bernama `pypi` (Settings → Environments) dan
   tambahkan reviewer bila mau ada kontrol manual.

---

## 4. Homebrew & Scoop (opsional)

### Homebrew (macOS/Linux)
Buat repo tap: `your-org/homebrew-dexsec` dengan file
`Formula/dexsec.rb`:

```ruby
class Dexsec < Formula
  desc "Inside-out hybrid application security testing CLI"
  homepage "https://github.com/your-org/dex-sec"
  version "0.7.0"
  url "https://github.com/your-org/dex-sec/releases/download/v#{version}/dexsec-macos-arm64"
  on_macos do
    if Hardware::CPU.arm?
      url ".../dexsec-macos-arm64"
    else
      url ".../dexsec-macos-x64"
    end
  end
  on_linux do
    url ".../dexsec-linux-x64"
  end
  license "MIT"
  def install
    bin.install "dexsec" => "dexsec"
  end
end
```

Lalu di `release.yml` tambahkan job yang commit formula itu ke tap.

### Scoop (Windows)
Buat bucket: `your-org/scoop-bucket` dengan `bucket/dexsec.json`:

```json
{
  "version": "0.7.0",
  "description": "Inside-out hybrid application security testing CLI",
  "homepage": "https://github.com/your-org/dex-sec",
  "license": "MIT",
  "url": "https://github.com/your-org/dex-sec/releases/download/v0.7.0/dexsec-windows-x64.exe",
  "bin": "dexsec.exe",
  "checkver": "https://github.com/your-org/dex-sec/releases/latest"
}
```

---

## 5. Rilis manual (tanpa GitHub Actions)

Kalau tidak mau pakai CI:

```powershell
python -m pip install --upgrade build twine
python scripts\sync_manual.py
python -m build
twine check dist\*
twine upload dist\*

# binary manual
python -m PyInstaller dexsec.spec --noconfirm --clean --workpath .pyinstaller-build
# unggah dist\dexsec.exe ke GitHub Release secara manual
```

---

## 6. Checklist sebelum rilis

- [ ] `python tests\selftest.py` → PASSED
- [ ] `python tests\test_features.py` → FEATURE TESTS PASSED
- [ ] `python -m build` → wheel + sdist terbentuk
- [ ] `twine check dist/*` → tidak ada error
- [ ] Versi di `pyproject.toml` sudah naik
- [ ] `CHANGELOG.md` punya entri untuk versi ini
- [ ] `python scripts\sync_manual.py` dijalankan (dokumentasi ikut ke dalam paket)
- [ ] Tag GitHub dimulai dengan `v` (misal `v0.8.0`)

---

## 7. Kalau ada masalah

| Gejala | Penyebab & Solusi |
| --- | --- |
| `error: invalid command 'bdist_wheel'` | `pip install --upgrade setuptools wheel` |
| `No module named build` | Ada folder `build/` lokal yang menutupi modul → hapus `build/`, atau pakai `python -m PyInstaller --workpath .pyinstaller-build` |
| PyPI: `403 Invalid or non-existent authentication information` | Token salah/kedaluwarsa, atau Trusted Publishing belum dikonfigurasi |
| PyPI: `File already exists` | Versi sudah dipakai → naikkan nomor versi |
| Release: artifact tidak muncul | Job `binaries` gagal → cek log; pastikan `dist/dexsec` ada di tiap OS |
| NPM publish gagal | `NPM_TOKEN` belum diset atau versi sudah dipakai |
