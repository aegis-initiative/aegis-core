#!/usr/bin/env python3
"""Generate machine-readable security testing coverage data.

Outputs a JSON file that downstream sites (aegis-docs, aegis-governance)
can ingest at build time to display security testing results.

Usage:
    python scripts/generate_coverage_data.py

Output:
    data/security-testing.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add core-py to path so we can import the coverage tracker
core_py_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(core_py_root))

from tests.security.coverage import build_coverage


def main() -> None:
    tracker = build_coverage()
    data = tracker.to_dict()

    output_dir = core_py_root / "data"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "security-testing.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    # Print summary to stdout
    s = data["summary"]
    print(f"Generated: {output_path}")
    print(f"  Tests:        {s['total_tests']}")
    print(f"  Rounds:       {s['red_blue_rounds']}")
    print(
        f"  ATX-1:        {s['atx1']['covered']}/{s['atx1']['applicable']} "
        f"({s['atx1']['coverage_percent']}%)"
    )
    print(
        f"  ATM-1:        {s['atm1']['covered']}/{s['atm1']['applicable']} "
        f"({s['atm1']['coverage_percent']}%)"
    )
    print(
        f"  Properties:   {s['security_properties']['covered']}/{s['security_properties']['total']}"
    )
    print(f"  Deferred:     {s['findings_deferred']}")


if __name__ == "__main__":
    main()
