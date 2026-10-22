# ARCHITECTURE & DESIGN SPECIFICATION

## Project Overview
**DEX-SEC** adalah *Inside-Out Hybrid Application Security Testing CLI*. Tool ini menggabungkan analisis kode sumber statis (SAST) dengan verifikasi eksploitasi eksternal yang aman (Safe DAST) dan pembuatan patch perbaikan otomatis berbasis AI (Auto-Remediation).

---

## High-Level Architecture Flow

```
+--------------------------------------------------------------------------+
|                             USER CLI INVOCATION                          |
|         `DEX-SEC scan --path ./my-app --target http://localhost:8000`    |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| PHASE 1: INSIDE INSPECTION (SAST ENGINE - `DEX-SEC.sast.scanner`)        |
| - Parse routes & endpoints (FastAPI, Flask, Express, Django, etc.)       |
| - Scan code sinks (Raw SQL, system commands, dynamic file opens, SSRF)  |
| - Output: List of `CodeFinding` mapped to targeted routes & params       |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| PHASE 2: OUTSIDE SAFE VERIFICATION (DAST ENGINE - `DEX-SEC.dast`)        |
| - Target ONLY the endpoints flagged by Phase 1 (no blind noisy fuzzing)  |
| - Send non-destructive probe payloads:                                   |
|     * SQLi: Time-delay probes & error delta analysis                     |
|     * Command Injection: echo math canary calculation / time sleep       |
|     * Path Traversal: Safe dummy canary checks                           |
| - Output: List of `VerificationResult` with reproduction cURL & evidence |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| PHASE 3: CORRELATION & CLASSIFICATION (`DEX-SEC.core.correlator`)         |
| - Match internal line of code with external confirmed exploitability     |
| - Status:                                                                |
|     [CRITICAL] CONFIRMED_VULNERABLE (Code flaw + DAST proof confirmed)   |
|     [WARNING]  POTENTIAL_CODE_SINK (Code flaw exists, external blocked)  |
|     [INFO]     EXTERNAL_ANOMALY                                          |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| PHASE 4: AI AUTO-REMEDIATION & PATCHER (`DEX-SEC.ai.patcher`)            |
| - Feed vulnerable code snippet + vulnerability context into LLM Engine   |
| - Generate clean unified diff (`git patch`)                              |
| - Optional: Auto-apply patch to codebase if approved by user             |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| PHASE 5: ATTACK CHAIN ANALYSIS (`dexsec.ai.chaining`)                      |
| - Menggabungkan beberapa temuan menjadi skenario eksploitasi nyata        |
| - Output: chain (judul, severity, langkah, dampak, temuan terkait)         |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| PHASE 6: NEXT STEP ADVISOR (`dexsec.ai.advisor`)                            |
| - Offline heuristics per vuln class + opsi mode LLM (JSON output)         |
| - Output: rencana tindak lanjut (judul, alasan, prioritas, perintah aman)  |
+--------------------------------------------------------------------------+
                                     |
                                     v
+--------------------------------------------------------------------------+
| PHASE 7: INTERACTIVE REPORTING (`dexsec.ai.reporter`)                       |
| - Beautiful CLI output (Rich tables, syntax highlighting, progress bars)   |
| - Export to JSON or Markdown audit report (`dexsec-report.json`)           |
+--------------------------------------------------------------------------+
```

## Perintah Tambahan

| Perintah | Fungsi |
| --- | --- |
| `dexsec scan` | Pipeline 7 fase di atas |
| `dexsec fuzz --spec <openapi>` | Black-box API fuzzing (`dexsec/dast/openapi.py`) — metode idempoten, rate limit, allow-list |
| `dexsec routes` | Daftar route yang ditemukan di kode |

---

## Directory Structure

```
dexsec/
├── AI_HANDOFF.md             # Standard Operating Procedure untuk kolaborasi AI
├── ROADMAP.md                # Roadmap milestone dan status checklist
├── ARCHITECTURE.md           # Dokumen arsitektur teknis (file ini)
├── CURRENT_STATE.md          # Real-time synchronization log
├── README.md                 # Panduan pemakaian ringkas
├── INSTALL.md                # Panduan instalasi (pip/pipx/exe/npm/docker/CI)
├── requirements.txt          # Dependensi Python
├── pyproject.toml            # Packaging + entry point `dexsec`
├── dexsec/
│   ├── __init__.py
│   ├── __main__.py           # `python -m dexsec`
│   ├── cli.py                # CLI commands & argument parsing
│   ├── models.py             # Data classes & type definitions (25 kelas celah)
│   ├── sast/
│   │   ├── __init__.py
│   │   ├── scanner.py        # Static analysis engine & route discovery
│   │   ├── rules.py          # Sink & taint rules + file/config rules
│   │   ├── ast_taint.py      # AST based taint analysis (Python, interprocedural)
│   │   ├── access.py         # IDOR / BOLA & missing authorisation heuristics
│   │   └── config_scan.py    # .env, key files, Dockerfile, nginx
│   ├── dast/
│   │   ├── __init__.py
│   │   ├── verifier.py       # Targeted HTTP safe probing engine
│   │   ├── probes.py         # Non-destructive proof-of-concept generators
│   │   ├── oast.py           # Local callback listener (SSRF/XXE proof)
│   │   └── openapi.py        # Schema driven black-box API fuzzing
│   ├── core/
│   │   ├── __init__.py
│   │   └── correlator.py     # Menghubungkan temuan SAST dengan verifikasi DAST
│   └── ai/
│       ├── __init__.py
│       ├── patcher.py        # AI Diff/Patch generator + fallback heuristik
│       ├── advisor.py        # Next Step Advisor (rencana tindak lanjut)
│       ├── chaining.py       # Attack chain analysis
│       └── reporter.py       # Rich terminal UI & report exports
├── demo/
│   ├── vulnerable_app.py     # Aplikasi target tiruan (SQLi, cmd, LFI, IDOR, redirect, SSTI)
│   └── configs/              # Fixture misconfiguration (.env, Dockerfile)
├── docs/
│   └── COVERAGE.md           # Matriks coverage seluruh kelas kerentanan
├── npm/                      # Wrapper NPM (bin/dexsec.js)
└── tests/
    ├── selftest.py           # Round-trip test: vulnerable → patched → clean
    └── list_findings.py      # Utilitas melihat seluruh temuan statis
```

---

## Security Invariants (Aturan Keamanan Tool)

1. **Safety First (Non-Destructive):**
   - Dilarang membuat probe DAST yang melakukan modifikasi permanen (misal: `DROP`, `DELETE`, `UPDATE`, `rm -rf`).
   - Probe harus menggunakan safe canary (seperti timing response terukur atau arithmetic assertion seperti `expr 1337 + 7331`).
2. **Offline-Capable Fallback:**
   - AI patch generator harus menyediakan fallback template patching berbasis best-practice rules jika user tidak menyediakan LLM API Key (OpenAI/Anthropic/Gemini).
