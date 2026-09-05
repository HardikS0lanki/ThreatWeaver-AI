from __future__ import annotations

import argparse
from pathlib import Path

from .core import load_json, load_policy, render_markdown, validate


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="threatweaver", description="Validate and render ThreatWeaver AI models")
    sub = root.add_subparsers(dest="command", required=True)
    check = sub.add_parser("validate", help="validate a canonical threat model")
    check.add_argument("model")
    check.add_argument("--policy")
    report = sub.add_parser("report", help="validate and render a Markdown report")
    report.add_argument("model")
    report.add_argument("--policy")
    report.add_argument("--output", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    model = load_json(args.model)
    policy = load_policy(args.policy)
    errors = validate(model, policy)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Threat model is valid.")
    if args.command == "report":
        output = Path(args.output)
        output.write_text(render_markdown(model), encoding="utf-8")
        print(f"Report written to {output}")
    return 0
