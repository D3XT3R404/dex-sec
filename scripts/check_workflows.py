"""Validate the GitHub Actions workflow files.

Checks that every workflow is valid YAML and that the expressions/contexts
used inside them are allowed by GitHub.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# Contexts GitHub allows in job level `if:` conditions.
JOB_IF_CONTEXTS = {"github", "needs", "vars", "inputs"}


def check_workflow(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"{path.name}: invalid YAML ({exc})"]

    if not isinstance(data, dict):
        return [f"{path.name}: the workflow must be a mapping"]
    if "jobs" not in data:
        return [f"{path.name}: no jobs section"]
    # YAML 1.1 turns the key "on" into the boolean True
    triggers = data.get("on", data.get(True))
    if triggers is None:
        problems.append(f"{path.name}: missing the 'on' section")

    for job_id, job in (data.get("jobs") or {}).items():
        condition = job.get("if")
        if condition:
            for context in re.findall(r"secrets\.|vars\.|inputs\.|needs\.|github\.", condition):
                name = context.rstrip(".")
                if name == "secrets" and name not in JOB_IF_CONTEXTS:
                    problems.append(
                        f"{path.name}: job '{job_id}' uses the secrets context in a job level 'if' "
                        "(not allowed) - move the condition to the step"
                    )
        for step in job.get("steps") or []:
            step_if = step.get("if")
            if step_if and "secrets." in step_if:
                pass  # allowed at step level
    return problems


def main() -> int:
    files = sorted(WORKFLOWS.glob("*.yml"))
    if not files:
        print("no workflow files found")
        return 1
    problems: list[str] = []
    for path in files:
        found = check_workflow(path)
        if found:
            problems.extend(found)
        else:
            print(f"  OK   {path.name}")
    if problems:
        print("\nPROBLEMS:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"\nall {len(files)} workflow files are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
