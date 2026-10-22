# AI HANDOFF PROTOCOL & MULTI-AGENT COLLABORATION GUIDE

> **PENTING UNTUK SEMUA AI AGENT (ChatGPT, Claude, Gemini, DeepSeek, Opencode, Cursor, Windsurf, Copilot, dll):**
> Dokumen ini adalah panduan protokol kerja sama antar-AI agar siapapun model AI yang melanjutkan project ini bisa langsung sinkron tanpa kebingungan dan tanpa merusak kode yang sudah ditulis sebelumnya.

---

## 1. Aturan Kerja Bersama (Collaboration Rules)

1. **Baca Dokumen Kunci Sebelum Melakukan Apapun:**
   - Baca `CURRENT_STATE.md` untuk mengetahui apa yang baru saja dikerjakan dan apa tugas berikutnya.
   - Baca `ARCHITECTURE.md` untuk memahami aliran data dan batas tanggung jawab tiap modul.
   - Baca `ROADMAP.md` untuk melihat prioritas fitur.

2. **Perbarui Log Setelah Selesai Bekerja (Wajib):**
   - Setiap kali AI menyelesaikan sebuah modul, bugfix, atau pengujian, AI **WAJIB** memperbarui file `CURRENT_STATE.md` di bagian `Recent Updates` dan `Next Steps`.
   - Cantumkan tanggal/waktu dan nama/identitas model yang mengubahnya (misal: `[2026-10-21] Opencode: Selesai membangun modul DAST verifier`).

3. **Prinsip Modularity & Zero-Breakage:**
   - Jangan menulis ulang file dari nol jika hanya butuh perbaikan kecil.
   - Semua modul berkomunikasi melalui tipe data terstruktur yang ada di `DEX-SEC/models.py`. Jangan passing unstructured dictionary tanpa type hint.
   - Semua pengecekan DAST harus bersifat **SAFE / NON-DESTRUCTIVE** (tidak boleh merusak database atau menjalankan shell command berbahaya).

4. **Self-Verification Mandatori:**
   - Setelah membuat atau mengubah kode, jalankan pengujian menggunakan `demo/vulnerable_app.py` atau unit test yang tersedia untuk memastikan kode berjalan tanpa error.

---

## 2. Struktur Data Utama (Single Source of Truth)

Semua komponen berbagi objek standar di `DEX-SEC/models.py`:
- `CodeFinding`: Hasil analisis kode dari modul SAST (file, line, sink, endpoint, route param).
- `VerificationResult`: Hasil pengujian dari modul DAST luar (status: `CONFIRMED_VULNERABLE`, `POTENTIAL`, `SAFE_OR_UNREACHABLE`, response time, safe evidence).
- `PatchResult`: Hasil patch AI berupa unified diff (`git diff` format) dan penjelasan mitigasi.
- `AuditReport`: Ringkasan lengkap eksekusi luar-dalam.

---

## 3. Format Update Log di `CURRENT_STATE.md`

Gunakan format ini saat memperbarui `CURRENT_STATE.md`:
```markdown
### [YYYY-MM-DD HH:MM] - Update by <AI_NAME>
- **Modul yang disentuh:** <daftar file>
- **Fitur yang ditambahkan / Bug yang difix:** <penjelasan ringkas>
- **Hasil Verifikasi / Testing:** <perintah test yang dijalankan dan outputnya>
- **Status Saat Ini:** <OK / Ada Blocker>
- **Tugas untuk AI Berikutnya:** <tindakan spesifik 1, 2, 3>
```

---

## 4. Status terpakai saat ini (ringkas)

- **Milestone 1 (fungsional inti): SELESAI.** Pipeline SAST → Safe DAST → Korelasi → Patch AI → Laporan sudah jalan dan lolos `python tests/selftest.py`.
- **Fokus berikutnya: Milestone 2** — route parser Express.js & Django, deteksi NoSQLi & SSTI, integrasi OAST/Interactsh untuk verifikasi SSRF/RCE.
- **Bukti kebenaran (round-trip test) yang wajib dijaga saat menambah fitur baru:**
  > aplikasi demo rentan → 3 temuan CONFIRMED → patch otomatis → `git apply` sukses → scan ulang → 0 CONFIRMED.
  Jika fitur baru membuat angka ini rusak, itu regresi.

### Aturan tambahan untuk AI yang menambah fitur
1. **Jangan pernah** mengirim probe yang merusak (write/delete/drop). Semua payload baru wajib read-only.
2. **Fals-positive guard wajib:** setiap aturan deteksi baru harus diuji terhadap `demo/vulnerable_app.py` (harus mendeteksi) dan terhadap kode tool sendiri (harus TIDAK mendeteksi).
3. **Windows-safe:** output terminal harus ASCII/UTF-8 aman, dan file patch harus memakai line ending yang sama dengan file target.
4. **Tambah aturan baru = tambah test.** Lengkapi `tests/selftest.py` atau buat file test baru di `tests/`.
5. **Hindari ketergantungan baru** yang belum terpasang di environment (numpy, pandas, rich, requests, typer, pydantic, flask, fastapi, django, matplotlib, selenium sudah ada; `semgrep`, `interactsh-client`, `openai`, `anthropic` BELUM terpasang — jangan di-import tanpa fallback).
