"""
python -m llvm_ir_context path/to/function.ll --function foo [--json]

Thin CLI wrapper around llvm_ir_context.api.get_vulnerability_context().
All business logic lives in api.py; sys.exit lives here.
"""

import argparse
import json
import sys

from llvm_ir_context.api import get_vulnerability_context
from llvm_ir_context.slice_context import format_for_llm


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="python -m llvm_ir_context",
        description="Extract vulnerability context from a compiled .ll file.",
    )
    ap.add_argument("ir_file", help="Path to unoptimised .ll file")
    ap.add_argument("--function", "-f", required=True,
                    help="Target function name")
    ap.add_argument("--json", action="store_true",
                    help="Output raw JSON instead of formatted block")
    args = ap.parse_args()

    try:
        ir_text = open(args.ir_file, errors="replace").read()
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    result = get_vulnerability_context(ir_text, args.function)

    if "error" in result:
        print(f"ERROR: {result['error']}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        # score is a plain float; guard_density may be None (was inf).
        print(json.dumps(
            {k: v for k, v in result.items() if k != "sinks"},
            indent=2, default=str,
        ))
    else:
        print(format_for_llm(result, score=result.get("score")))


if __name__ == "__main__":
    main()
