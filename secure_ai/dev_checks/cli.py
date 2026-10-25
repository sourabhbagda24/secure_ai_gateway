"""Run all development-phase checks against a project directory."""
from __future__ import annotations

import sys
from pathlib import Path

from . import dependency_check, secret_scanner, workflow_lint


def run(root: str = ".") -> int:
    root_p = Path(root)
    errors = 0
    print("== secret scan ==")
    found = secret_scanner.scan_path(root_p, exclude=("tests",))
    for f in found:
        print(f"  ERROR {f.path}:{f.line} {f.kind}")
    print(f"  {len(found)} finding(s)")
    errors += len(found)

    print("== dependency check ==")
    adv_path = root_p / "data" / "advisories.example.json"
    adv = dependency_check.load_advisories(str(adv_path)) if adv_path.exists() else {}
    for req in ("requirements.txt", "requirements-dev.txt"):
        fp = root_p / req
        if fp.exists():
            for i in dependency_check.check_requirements(fp.read_text(encoding="utf-8"), adv):
                print(f"  {i.level.upper()} {req}: {i.package}: {i.message}")
                errors += i.level == "error"

    print("== workflow lint ==")
    for wf in sorted((root_p / ".github" / "workflows").glob("*.y*ml")):
        for f in workflow_lint.lint_workflow(wf.read_text(encoding="utf-8")):
            print(f"  {f.level.upper()} {wf.name}:{f.line} {f.message}")
            errors += f.level == "error"
    print("RESULT:", "FAIL" if errors else "PASS")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else "."))
