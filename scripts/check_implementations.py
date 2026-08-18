"""Validate the recognized-implementations registry (KGP-RFC-0004 test plan).

Checks:

- implementations/RECOGNITION.md exists;
- every row in the "Recognized independent implementations" table in
  implementations/README.md (except the placeholder and header rows) has an
  Evidence column containing a Markdown link.

Exits non-zero when the registry is inconsistent.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "implementations" / "README.md"
GUIDE = ROOT / "implementations" / "RECOGNITION.md"

PLACEHOLDER = "_open for applications_"


def main() -> int:
    errors: list[str] = []
    if not GUIDE.is_file():
        errors.append("implementations/RECOGNITION.md is missing")
    if not README.is_file():
        errors.append("implementations/README.md is missing")
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    lines = README.read_text(encoding="utf-8").splitlines()
    in_table = False
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("| Implementation |"):
            in_table = True
            continue
        if in_table and stripped.startswith("| ---"):
            continue
        if in_table:
            if not stripped.startswith("|"):
                in_table = False
                continue
            if not stripped.startswith("|") or not stripped.endswith("|"):
                continue
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if len(cells) < 5:
                continue
            name, evidence = cells[0], cells[3]
            if name == PLACEHOLDER or name.startswith("_"):
                continue
            if not re.search(r"\[[^\]]+\]\([^)]+\)", evidence):
                errors.append(
                    f"implementations/README.md:{index}: row {name!r} has no "
                    f"Markdown evidence link (got {evidence!r})"
                )
    if not in_table:
        errors.append("implementations/README.md has no recognized-implementations table")
    for error in errors:
        print(f"ERROR: {error}")
    if not errors:
        print("implementations registry OK")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())