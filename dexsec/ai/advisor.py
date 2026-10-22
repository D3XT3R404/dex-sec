"""Next-step advisor.

Turns confirmed findings into an actionable, prioritised investigation plan:
what to check next, why it matters and which safe command to run.

Two engines are available:
  * `offline`  - deterministic heuristics, always available.
  * `llm`      - a language model reasons over the evidence and produces a
                 ranked plan (requires an API key, falls back to offline).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..models import CorrelatedFinding, VerificationStatus, VulnClass


@dataclass
class NextStep:
    title: str
    rationale: str
    priority: str  # HIGH | MEDIUM | LOW
    commands: list[str] = field(default_factory=list)
    relates_to: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "rationale": self.rationale,
            "priority": self.priority,
            "commands": self.commands,
            "relates_to": self.relates_to,
        }


# ---------------------------------------------------------------- offline
HEURISTICS: dict[VulnClass, list[tuple[str, str, list[str]]]] = {
    VulnClass.SQL_INJECTION: [
        (
            "Cek apakah sink yang sama ada di endpoint lain",
            "Satu pola query bocor biasanya direplikasi di banyak endpoint. Jalankan DEX-SEC pada modul lain "
            "atau grep assinatura query yang sama.",
            ["dexsec scan --path ./src --target http://localhost:8000"],
        ),
        (
            "Uji second-order injection",
            "Data yang tersimpan (nama, komentar, profil) sering dipakai ulang di query lain tanpa sanitasi.",
            ["grep -rn \"SELECT\" ./src | head -50"],
        ),
        (
            "Petakan hak akses database aplikasi",
            "Menilai dampak butuh tahu apakah akun aplikasi punya akses tulis pada tabel sensitif.",
            ["# periksa di environment dev, jangan di produksi"],
        ),
    ],
    VulnClass.COMMAND_INJECTION: [
        (
            "Cari parameter lain yang masuk ke shell",
            "Satu argumen bocor biasanya ada argumen lain di endpoint yang sama atau berbeda.",
            ["grep -rn \"subprocess\\|os.system\\|shell=True\" ./src"],
        ),
        (
            "Periksa hak akses service account",
            "Dampak command injection bergantung pada user proses aplikasi dan akses jaringan internal.",
            ["# periksa deployment manifest / container user"],
        ),
    ],
    VulnClass.PATH_TRAVERSAL: [
        (
            "Uji operasi tulis pada path yang sama",
            "Jika file bisa dibaca di luar direktori, operasi tulis (upload, log, cache) mungkin juga bisa.",
            ["grep -rn \"open(.*['\\\"]w\\|writeFile\\|shutil.copy\\|os.remove\" ./src"],
        ),
        (
            "Verifikasi apakah path dinormalisasi di satu tempat saja",
            "Perbaikan harus diterapkan di layer yang benar, bukan di setiap handler.",
            ["grep -rn \"basename\\|normpath\\|resolve(\" ./src"],
        ),
    ],
    VulnClass.SSRF: [
        (
            "Uji jangkauan jaringan internal",
            "SSRF yang terbukti sering juga menjangkau metadata cloud dan layanan internal.",
            ["# uji hanya di environment yang diizinkan (staging milik sendiri)"],
        ),
        (
            "Cek red-team URL parser & redirect service",
            "Komponen seperti requests/httpx/urllib ada di banyak tempat; parser yang berbeda bisa memblokir URL berbeda.",
            ["grep -rn \"requests\\.\\|httpx\\.\\|urlopen\\|fetch(\" ./src"],
        ),
    ],
    VulnClass.XXE: [
        (
            "Cek semua parser XML di project",
            "Minidom, lxml, SAX dan ElementTree punya perilaku entity yang berbeda; semuanya perlu diaudit.",
            ["grep -rn \"minidom\\|etree\\|lxml\\|xml.sax\\|ElementTree\" ./src"],
        ),
    ],
    VulnClass.IDOR: [
        (
            "Enumerasi objek milik user lain",
            "IDOR yang terbukti biasanya berlaku untuk semua koleksi yang memakai pola query sama.",
            ["# gunakan dua akun uji milik sendiri"],
        ),
        (
            "Periksa endpoint tulis (PUT/PATCH/DELETE) dengan pola sama",
            "Membaca objek milik orang lain biasanya lebih ringan, menulisnya biasanya lebih berbahaya.",
            ["dexsec routes --path ."],
        ),
    ],
    VulnClass.OPEN_REDIRECT: [
        (
            "Periksa dampaknya pada alur OAuth/SSO",
            "Open redirect pada callback OAuth，很多时候 berarti token bocor ke domain penyerang.",
            ["grep -rn \"redirect\\|RedirectResponse\\|return_to\\|next=\" ./src"],
        ),
    ],
    VulnClass.TEMPLATE_INJECTION: [
        (
            "Cari semua pemakaian template dinamis",
            "Satu template yang dirender dari input biasanya punya saudara di modul lain.",
            ["grep -rn \"render_template_string\\|from_string\\|Template(\" ./src"],
        ),
    ],
    VulnClass.INSECURE_DESERIALIZATION: [
        (
            "Petakan sumber data tidak tepercaya",
            "Deserialisasi hanya berbahaya bila inputnya bisa dikendalikan pengguna.",
            ["grep -rn \"pickle\\|yaml.load\\|marshal\\|jsonpickle\" ./src"],
        ),
    ],
    VulnClass.MASS_ASSIGNMENT: [
        (
            "Cek field sensitif pada model",
            "Cari field seperti role, is_admin, is_staff, balance, verified yang bisa di-set client.",
            ["grep -rn \"role\\|is_admin\\|is_staff\\|balance\\|verified\" ./models ./src"],
        ),
    ],
    VulnClass.HARDCODE_SECRET: [
        (
            "Nilai dampak & rotasi kredensial",
            "Kredensial yang bocor di repo harus dianggap sudah kompromi, bukan hanya dihapus.",
            ["git log --all -S \"<nilai_yang_terdeteksi>\" --oneline"],
        ),
    ],
    VulnClass.EXPOSED_SECRET_FILE: [
        (
            "Bersihkan dari history git",
            "Menghapus file di commit terbaru tidak menghapus jejaknya di history.",
            ["git filter-repo --path <file> --invert-paths"],
        ),
    ],
    VulnClass.JWT_NONE_ALG: [
        (
            "Audit issuance token",
            "Periksa apakah server ikut memverifikasi signature saat membuat token (bukan hanya saat memvalidasi).",
            ["grep -rn \"jwt.encode\\|jwt.decode\\|HS256\\|RS256\" ./src"],
        ),
    ],
    VulnClass.PERMISSIVE_CORS: [
        (
            "Uji dampak dengan Origin acak",
            "CORS yang memantulkan origin membuat situs mana pun bisa membaca response terotorisasi.",
            ["curl -i <target> -H \"Origin: https://attacker.example\""],
        ),
    ],
    VulnClass.MISSING_SECURITY_HEADERS: [
        (
            "Terapkan header keamanan di reverse proxy",
            "Header ini paling mudah dikontrol di nginx/Cloudflare/ALB tanpa menyentuh kode aplikasi.",
            ["# tambahkan add_header X-Content-Type-Options nosniff; dll"],
        ),
    ],
    VulnClass.DEBUG_MODE: [
        (
            "Pastikan debug dimatikan di seluruh environment",
            "Flag debug sering diaktifkan lewat variabel lingkungan di staging tapi tidak di produksi.",
            ["grep -rn \"DEBUG\\|debug=\" ./src ./.env* 2>/dev/null"],
        ),
    ],
}

GENERIC_STEPS = [
    (
        "Ulangi scan pada branch/PR berikutnya",
        "Jalankan DEX-SEC di pre-commit hook atau CI agar regresi langsung terlihat.",
        ["dexsec scan --path . --target http://localhost:3000 --json dexsec.json"],
    ),
    (
        "Dokumentasikan temuan & tetapkan pemilik",
        "Temuan tanpa owner akan terulang. Sertakan PoC curl dari laporan ke issue tracker.",
        [],
    ),
]


def _commands_for(item: CorrelatedFinding) -> list[str]:
    commands: list[str] = []
    verification = item.verification
    if verification and verification.safe_poc_curl:
        commands.append(verification.safe_poc_curl)
    return commands


def build_next_steps(
    correlated: list[CorrelatedFinding],
    target_url: str = "",
    api_key: Optional[str] = None,
    provider: str = "openai",
    model: str = "gpt-4o-mini",
) -> list[NextStep]:
    """Produce a prioritised follow-up plan for the confirmed findings."""
    actionable = [
        item for item in correlated
        if item.status in (VerificationStatus.CONFIRMED_VULNERABLE, VerificationStatus.POTENTIAL)
    ]

    steps: list[NextStep] = []
    if api_key:
        llm_steps = _llm_next_steps(actionable, target_url, api_key, provider, model)
        if llm_steps:
            return llm_steps

    for item in actionable[:8]:
        heuristics = HEURISTICS.get(item.finding.vuln_class, [])
        for title, rationale, commands in heuristics[:2]:
            steps.append(
                NextStep(
                    title=title,
                    rationale=rationale,
                    priority="HIGH" if item.status == VerificationStatus.CONFIRMED_VULNERABLE else "MEDIUM",
                    commands=commands + _commands_for(item),
                    relates_to=item.title,
                )
            )

    if not steps:
        for title, rationale, commands in GENERIC_STEPS:
            steps.append(NextStep(title=title, rationale=rationale, priority="LOW", commands=commands))

    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    steps.sort(key=lambda s: priority_order.get(s.priority, 3))
    return steps


# ------------------------------------------------------------------- llm
LLM_SYSTEM_PROMPT = (
    "You are a senior application security consultant. You are given confirmed findings of an "
    "application security test. Produce a concise, prioritised plan of what to investigate NEXT, "
    "so the tester can assess the real impact and chain the findings. "
    "Rules: only use safe, read-only, non-destructive actions that the tester is authorised to run "
    "on their own systems. Never suggest destructive payloads, data exfiltration of real user data, "
    "or anything that would damage the target. "
    "Output JSON: {\"steps\": [{\"title\": str, \"rationale\": str, \"priority\": \"HIGH|MEDIUM|LOW\", "
    "\"commands\": [str]}]}"
)


def _llm_next_steps(
    correlated: list[CorrelatedFinding],
    target_url: str,
    api_key: str,
    provider: str,
    model: str,
) -> list[NextStep]:
    import json

    summary = []
    for item in correlated[:12]:
        summary.append(
            {
                "vulnerability": item.finding.vuln_class.value,
                "severity": item.final_severity.value,
                "status": item.status.value,
                "location": f"{item.finding.file}:{item.finding.line}",
                "route": item.finding.route.path if item.finding.route else None,
                "evidence": item.verification.evidence if item.verification else "",
            }
        )
    prompt = (
        f"Target: {target_url}\n"
        f"Confirmed findings:\n{json.dumps(summary, indent=2, default=str)}\n\n"
        "Give the next investigation steps."
    )

    raw = ""
    try:
        if provider == "openai":
            from openai import OpenAI  # type: ignore

            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": LLM_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            raw = resp.choices[0].message.content or ""
        elif provider == "anthropic":
            import anthropic  # type: ignore

            client = anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model=model,
                max_tokens=2000,
                system=LLM_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        elif provider == "gemini":
            import google.generativeai as genai  # type: ignore

            genai.configure(api_key=api_key)
            raw = genai.GenerativeModel(model).generate_content([LLM_SYSTEM_PROMPT, prompt]).text or ""
    except Exception:
        return []

    if not raw:
        return []
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end < start:
        return []
    try:
        data = json.loads(raw[start: end + 1])
    except json.JSONDecodeError:
        return []

    steps: list[NextStep] = []
    for entry in data.get("steps", []):
        steps.append(
            NextStep(
                title=str(entry.get("title", "")).strip(),
                rationale=str(entry.get("rationale", "")).strip(),
                priority=str(entry.get("priority", "MEDIUM")).upper(),
                commands=[str(c) for c in entry.get("commands", [])][:5],
                relates_to="LLM analysis",
            )
        )
    return steps
