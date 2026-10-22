import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dexsec.sast import scanner  # noqa: E402

base = sys.argv[1] if len(sys.argv) > 1 else "."
routes, findings, frameworks = scanner.scan_project(base)
print(f"routes={len(routes)} findings={len(findings)}")
for f in sorted(findings, key=lambda i: (i.vuln_class.value, i.file)):
    rel = os.path.relpath(f.file, base)
    route = f.route.path if f.route else "-"
    print(f"{f.vuln_class.value:28} {f.severity.value:8} {rel:34}:{f.line:<4} {route}")
