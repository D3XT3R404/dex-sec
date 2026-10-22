"""Minimal PDF writer for the executive summary.

DEX-SEC should not force an extra dependency on the user, so the executive
summary PDF is produced with a small self-contained PDF writer.  It supports
the classic Helvetica fonts, multiple pages and simple text wrapping.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import AuditReport, VerificationStatus

PAGE_WIDTH = 595  # A4 in points
PAGE_HEIGHT = 842
MARGIN = 48


def _escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


@dataclass
class Line:
    text: str
    size: int = 10
    bold: bool = False
    gap: int = 4
    color: tuple[float, float, float] = (0.1, 0.1, 0.1)


class PdfWriter:
    """Builds a simple multi page text PDF."""

    def __init__(self) -> None:
        self.pages: list[list[Line]] = [[]]
        self.y = PAGE_HEIGHT - MARGIN

    def add(self, line: Line) -> None:
        if self.y - (line.size + line.gap) < MARGIN:
            self.pages.append([])
            self.y = PAGE_HEIGHT - MARGIN
        self.pages[-1].append(line)
        self.y -= line.size + line.gap

    def space(self, amount: int = 10) -> None:
        self.y -= amount

    def _content(self) -> bytes:
        parts = ["BT"]
        for page in self.pages:
            parts.append("1 0 0 1 0 0 cm")
            current_color = None
            for line in page:
                y = PAGE_HEIGHT - MARGIN - line.size
                # recompute the vertical position from the top of the page
                y = self._line_y(page, line)
                font = "F2" if line.bold else "F1"
                color = line.color
                if color != current_color:
                    parts.append(f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg")
                    current_color = color
                parts.append(f"/{font} {line.size} Tf")
                parts.append(f"1 0 0 1 {MARGIN} {y:.1f} Tm")
                parts.append(f"({_escape(line.text)}) Tj")
            parts.append("0 0 0 rg")
        parts.append("ET")
        return "\n".join(parts).encode("latin-1", "replace")

    @staticmethod
    def _line_y(page: list[Line], target: Line) -> float:
        y = PAGE_HEIGHT - MARGIN
        for line in page:
            y -= line.size + line.gap
            if line is target:
                return y
        return y

    def save(self, path: str) -> str:
        objects: list[bytes] = []

        def add_object(data: bytes) -> int:
            objects.append(data)
            return len(objects)

        font_regular = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        font_bold = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        content_id = add_object(self._content())

        pages_id = len(objects) + 1
        objects.append(b"")  # placeholder for the Pages object
        page_ids: list[int] = []
        for _ in self.pages:
            page_id = add_object(
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                f"/Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R >> >> "
                f"/Contents {content_id} 0 R >>".encode()
            )
            page_ids.append(page_id)

        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()
        catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
        info_id = add_object(b"<< /Producer (DEX-SEC) >>")

        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, data in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{index} 0 obj\n".encode() + data + b"\nendobj\n"

        xref_pos = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for offset in offsets[1:]:
            out += f"{offset:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R /Info {info_id} 0 R >>\n".encode()
        out += f"startxref\n{xref_pos}\n%%EOF\n".encode()

        with open(path, "wb") as fh:
            fh.write(bytes(out))
        return path


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def build_executive_summary(report: AuditReport) -> PdfWriter:
    writer = PdfWriter()
    confirmed = [c for c in report.correlated if c.status == VerificationStatus.CONFIRMED_VULNERABLE]
    stats = report.stats

    writer.add(Line("DEX-SEC - Ringkasan Eksekutif Audit Keamanan", size=16, bold=True, gap=10))
    writer.add(Line(f"Project : {report.project_path}", size=10))
    writer.add(Line(f"Target  : {report.target_url}", size=10))
    writer.add(Line(f"Waktu   : {report.started_at} s/d {report.finished_at}", size=10))
    writer.space(14)

    writer.add(Line("Ringkasan", size=13, bold=True, gap=8))
    for label, value in (
        ("Total temuan static", stats.get("total", 0)),
        ("Terkonfirmasi exploitable", stats.get("confirmed", 0)),
        ("Perlu review manual", stats.get("potential", 0)),
        ("Tidak dapat direproduksi", stats.get("not_reproducible", 0)),
        ("Serangan berantai terdeteksi", len(report.chains)),
    ):
        writer.add(Line(f"  - {label}: {value}", size=10))

    severity = stats.get("by_severity", {})
    if severity:
        writer.add(Line("  - Berdasarkan severity: " + ", ".join(f"{k}={v}" for k, v in severity.items()), size=10))
    writer.space(12)

    if confirmed:
        writer.add(Line("Temuan Terkonfirmasi (dengan bukti eksploitasi)", size=13, bold=True, gap=8))
        for item in confirmed[:20]:
            writer.add(Line(f"  [{item.final_severity.value}] {item.title}", size=10, bold=True, gap=2))
            for chunk in _wrap(item.impact, 95)[:2]:
                writer.add(Line(f"      {chunk}", size=9, color=(0.35, 0.35, 0.35), gap=2))
            writer.add(Line(f"      Perbaikan: {item.remediation_hint}", size=9, color=(0.2, 0.4, 0.2), gap=6))
    else:
        writer.add(Line("Tidak ada temuan yang terkonfirmasi exploitable.", size=10, gap=8))

    if report.chains:
        writer.space(8)
        writer.add(Line("Skenario Serangan Berantai", size=13, bold=True, gap=8))
        for chain in report.chains[:8]:
            writer.add(Line(f"  [{chain.get('severity')}] {chain.get('title')}", size=10, bold=True, gap=2))
            for chunk in _wrap(str(chain.get("impact", "")), 95)[:2]:
                writer.add(Line(f"      {chunk}", size=9, color=(0.35, 0.35, 0.35), gap=2))
            writer.add(Line("", size=6))

    if report.next_steps:
        writer.space(6)
        writer.add(Line("Tindak Lanjut Prioritas", size=13, bold=True, gap=8))
        for step in report.next_steps[:8]:
            writer.add(Line(f"  [{step.get('priority')}] {step.get('title')}", size=10, bold=True, gap=2))
            for chunk in _wrap(str(step.get("rationale", "")), 95)[:2]:
                writer.add(Line(f"      {chunk}", size=9, color=(0.35, 0.35, 0.35), gap=2))
            writer.add(Line("", size=6))

    writer.space(10)
    writer.add(Line("Hanya gunakan DEX-SEC pada sistem yang Anda miliki atau berwenang.", size=8,
                    color=(0.5, 0.5, 0.5), gap=2))
    return writer


def write_executive_pdf(report: AuditReport, path: str) -> str:
    build_executive_summary(report).save(path)
    return path
