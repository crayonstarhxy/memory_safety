from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .cases import CASES
from .models import Profile
from .runner import run_all, run_case


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="amslab", description="Agent memory security lab")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="List available cases")
    run = subparsers.add_parser("run", help="Run one or all cases")
    run.add_argument("--case", choices=tuple(CASES), help="Run a single case")
    run.add_argument("--profile", choices=("vulnerable", "hardened", "both"), default="both")
    run.add_argument("--output", type=Path, help="Write JSON report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "list":
        for case in CASES.values():
            print(f"{case.case_id:22} {case.title} - {case.theory}")
        return 0

    profiles = list(Profile) if args.profile == "both" else [Profile(args.profile)]
    results = []
    for profile in profiles:
        results.extend([run_case(args.case, profile)] if args.case else run_all(profile))
    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            profile.value: {
                "cases": sum(result.profile is profile for result in results),
                "successful_attacks": sum(
                    result.profile is profile and result.attack_succeeded for result in results
                ),
            }
            for profile in profiles
        },
        "results": [result.to_dict() for result in results],
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

