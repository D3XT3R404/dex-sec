"""End-to-end self test for DEX-SEC.

Run with:  python tests/selftest.py

The test proves the core promise of the tool:
  1. the vulnerable demo app yields CONFIRMED findings,
  2. the generated patch applies cleanly,
  3. re-scanning the patched app yields no confirmed finding.

The demo application is started in a subprocess on a free port, so the test
never touches anything outside a temporary directory.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

from dexsec.ai import patcher  # noqa: E402
from dexsec.core import correlator  # noqa: E402
from dexsec.dast import verifier  # noqa: E402
from dexsec.models import VerificationStatus  # noqa: E402
from dexsec.sast import scanner  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demo", "vulnerable_app.py")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_server(script: str, port: int) -> subprocess.Popen:
    env = dict(os.environ, DEXSEC_DEMO_PORT=str(port))
    proc = subprocess.Popen([sys.executable, script], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            if requests.get(f"http://127.0.0.1:{port}/health", timeout=1).status_code == 200:
                return proc
        except requests.RequestException:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError("demo server did not start")


def audit(path: str, base_url: str):
    routes, findings, _ = scanner.scan_project(path)
    results = verifier.verify_findings(base_url, findings, timeout=5.0)
    correlated = correlator.correlate(findings, results)
    return routes, findings, results, correlated


def main() -> int:
    failures: list[str] = []
    workdir = tempfile.mkdtemp(prefix="dexsec-selftest-")
    try:
        target_dir = os.path.join(workdir, "demo")
        shutil.copytree(os.path.join(ROOT, "demo"), target_dir,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        script = os.path.join(target_dir, "vulnerable_app.py")

        # --- 1. baseline -------------------------------------------------
        port = free_port()
        server = start_server(script, port)
        try:
            routes, findings, results, correlated = audit(workdir, f"http://127.0.0.1:{port}")
            confirmed = [c for c in correlated if c.status == VerificationStatus.CONFIRMED_VULNERABLE]
            classes = {c.finding.vuln_class.value for c in confirmed}
            print(f"[1] routes={len(routes)} findings={len(findings)} confirmed={len(confirmed)}")
            if len(routes) < 3:
                failures.append(f"expected at least 3 routes, found {len(routes)}")
            for expected in ("SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "IDOR", "SSRF", "XXE"):
                if expected not in classes:
                    failures.append(f"{expected} was not confirmed as exploitable")
            # misconfiguration scanning must also work
            detected = {f.vuln_class.value for f in findings}
            if "EXPOSED_SECRET_FILE" not in detected:
                failures.append("EXPOSED_SECRET_FILE was not detected in the demo config folder")
        finally:
            server.terminate()
            server.wait(timeout=10)

        # --- 2. generate and apply the patch -----------------------------
        port = free_port()
        server = start_server(script, port)
        try:
            _routes, findings, _results, correlated = audit(workdir, f"http://127.0.0.1:{port}")
        finally:
            server.terminate()
            server.wait(timeout=10)

        patches = [
            patcher.generate_patch(item, workdir)
            for item in correlated
            if item.status in (VerificationStatus.CONFIRMED_VULNERABLE, VerificationStatus.POTENTIAL)
        ]
        patch_path = os.path.join(workdir, "fix.patch")
        patcher.write_patch_file(patches, patch_path)
        print(f"[2] patches generated: {sum(1 for p in patches if p.diff.strip())}")
        if not os.path.getsize(patch_path):
            failures.append("no patch content was produced")

        proc = subprocess.run(["git", "apply", "--check", patch_path], cwd=workdir,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            failures.append(f"git apply --check failed: {proc.stderr.strip()[:300]}")
        else:
            proc = subprocess.run(["git", "apply", patch_path], cwd=workdir,
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                failures.append(f"git apply failed: {proc.stderr.strip()[:300]}")
            else:
                print("[3] patch applied cleanly")

        # --- 3. re-scan the patched application --------------------------
        port = free_port()
        server = start_server(script, port)
        try:
            _routes, findings, results, correlated = audit(workdir, f"http://127.0.0.1:{port}")
            still_confirmed = [c for c in correlated if c.status == VerificationStatus.CONFIRMED_VULNERABLE]
            print(f"[4] after patch: confirmed={len(still_confirmed)} "
                  f"not_reproducible={len([c for c in correlated if c.status == VerificationStatus.NOT_REPRODUCIBLE])}")
            # Only the classes that were patched must be gone; the access
            # control issue is not auto-fixable and must stay visible.
            patched_classes = {"SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL"}
            for item in still_confirmed:
                if item.finding.vuln_class.value in patched_classes:
                    failures.append(f"still exploitable after patch: {item.title}")
            if not any(c.finding.vuln_class.value == "IDOR" for c in still_confirmed):
                failures.append("IDOR disappeared although no patch was generated for it")
            if not any(c.finding.vuln_class.value == "SSRF" for c in still_confirmed):
                failures.append("SSRF disappeared although no patch was generated for it")
        finally:
            server.terminate()
            server.wait(timeout=10)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if failures:
        print("\nSELFTEST FAILED")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nSELFTEST PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
