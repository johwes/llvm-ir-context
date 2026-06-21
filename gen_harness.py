#!/usr/bin/env python3
"""
gen_harness.py — MVP: slice context → Qwen → harness C → IR validation.

Usage:
    export QWEN_API_KEY=sk-...

    # Explicit target
    python gen_harness.py --ll <target.ll> --function <fn> [--header <header.h>]

    # Auto-pick top-ranked function from a directory
    python gen_harness.py --ir-dir <dir/> [--no-gep-only] [--header <header.h>]

Examples:
    python gen_harness.py --ir-dir /tmp/zlib-ir/ --no-gep-only --header /usr/include/zlib.h
    python gen_harness.py --ir-dir ~/scarnet-ir/ --header ~/scarnet/scarnet.h
    python gen_harness.py --ll /tmp/zlib-ir/inflate.ll --function inflate

Validation steps:
  1. Compile harness to IR  (catches syntax / API errors — retries with compiler error)
  2. ir-score on harness IR (catches self-harm: unguarded access in harness code)
     Score interpretation in harness context:
       < 60%  — expected: unguarded malloc/GEP is normal in fuzzing harnesses
       60-89% — review: check what the slicer flagged
       ≥ 90%  — warning: likely a real bug in the harness itself
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

import requests

ENDPOINT    = "https://litellm-litemaas.apps.prod.rhoai.rh-aiservices-bu.com/v1/chat/completions"
MODEL       = "Qwen3.6-35B-A3B"
MAX_RETRIES = 3

# Self-harm score threshold: below this is expected harness noise.
SELF_HARM_WARN = 0.90


def get_context(ll_path: str, fn_name: str) -> str:
    r = subprocess.run(["ir-context", ll_path, "--function", fn_name],
                       capture_output=True, text=True)
    return r.stdout.strip()


def pick_top_function(ir_dir: str, no_gep_only: bool) -> tuple[str, str]:
    """Run ir-score over a directory and return (ll_path, fn_name) for rank 1."""
    cmd = ["ir-score", "--ir-dir", ir_dir]
    if no_gep_only:
        cmd.append("--no-gep-only")
    r = subprocess.run(cmd, capture_output=True, text=True)
    # Parse the ranked table — first data row after the header separator.
    for line in r.stdout.splitlines():
        # Matches lines like:  "     1  inflate   88.0%  ..."
        m = re.match(r"\s+1\s+(\S+)\s+[\d.]+%.*\((\S+\.ll)\)", line)
        if m:
            fn_name = m.group(1)
            src_file = m.group(2)
            # Reconstruct full path from the directory and the source filename.
            ll_path = str(Path(ir_dir) / src_file)
            return ll_path, fn_name
    sys.exit("Could not parse top-ranked function from ir-score output:\n" + r.stdout)


def ask_qwen(messages: list[dict]) -> str:
    key = os.environ.get("QWEN_API_KEY", "")
    if not key:
        sys.exit("Set QWEN_API_KEY env var first.")
    r = requests.post(
        ENDPOINT,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={"model": MODEL, "messages": messages},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def extract_c(text: str) -> str:
    m = re.search(r"```(?:c|cpp)?\n(.*?)```", text, re.DOTALL)
    return m.group(1).strip() if m else text.strip()


def compile_to_ir(src: Path) -> tuple[Path | None, str]:
    """Returns (ir_path, stderr). ir_path is None on failure."""
    out = src.with_suffix(".ll")
    r = subprocess.run(
        ["clang-20", "-O0", "-fno-inline", "-S", "-emit-llvm", "-w", str(src), "-o", str(out)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return None, r.stderr
    return out, ""


def self_harm_verdict(score: float) -> str:
    if score >= SELF_HARM_WARN:
        return f"WARNING ({score:.0%}) — likely real bug in harness, review before fuzzing"
    if score >= 0.60:
        return f"REVIEW ({score:.0%}) — elevated; check flagged sinks"
    return f"OK ({score:.0%}) — expected harness noise"


def parse_top_score(ir_score_output: str) -> float | None:
    """Extract the score for LLVMFuzzerTestOneInput from ir-score output."""
    for line in ir_score_output.splitlines():
        if "LLVMFuzzerTestOneInput" in line:
            m = re.search(r"([\d.]+)%", line)
            if m:
                return float(m.group(1)) / 100
    return None


def main():
    ap = argparse.ArgumentParser(description="Generate and validate a libFuzzer harness via Qwen.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ll",       metavar="FILE", help="Path to .ll file")
    src.add_argument("--ir-dir",   metavar="DIR",  help="IR directory — auto-picks top-ranked function")
    ap.add_argument("--function",  metavar="FN",   help="Function name (required with --ll)")
    ap.add_argument("--no-gep-only", action="store_true", help="Pass --no-gep-only to ir-score when auto-picking")
    ap.add_argument("--header",    metavar="FILE", help="Header file to include in prompt")
    args = ap.parse_args()

    if args.ll and not args.function:
        ap.error("--function is required when using --ll")

    header = Path(args.header).read_text() if args.header else ""

    # ── 1. resolve target ─────────────────────────────────────────────────────
    if args.ir_dir:
        print(f"── auto-picking top function from {args.ir_dir} ────────")
        ll_path, fn_name = pick_top_function(args.ir_dir, args.no_gep_only)
        print(f"   → {fn_name}  ({ll_path})")
    else:
        ll_path, fn_name = args.ll, args.function

    # ── 2. slice context ──────────────────────────────────────────────────────
    print(f"\n── slice context: {fn_name} ──────────────────────────")
    ctx = get_context(ll_path, fn_name)
    print(ctx)

    # ── 3. build initial prompt ───────────────────────────────────────────────
    header_block = f"\n## API reference\n```c\n{header}\n```" if header else ""
    initial_prompt = f"""Write a libFuzzer harness in C for security testing.

## Static analysis (IR slicer output)
{ctx}
{header_block}
## Task
Write `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)` targeting `{fn_name}`.

Requirements:
- Pass `Data` and `Size` into `{fn_name}` — do not add artificial caps on Size
- Initialize any required state before the call; clean it up after
- Return 0

Output C code only, no explanation."""

    messages = [{"role": "user", "content": initial_prompt}]
    out_c = Path(f"harness_{fn_name}.c")

    # ── 4. call Qwen with compile-error retry loop ────────────────────────────
    harness_ll = None
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n── calling {MODEL} (attempt {attempt}/{MAX_RETRIES}) ──────")
        reply = ask_qwen(messages)
        code  = extract_c(reply)
        out_c.write_text(code)
        print(code)
        print(f"\n→ saved: {out_c}")

        print("\n── compiling harness to IR ──────────────────────────")
        harness_ll, stderr = compile_to_ir(out_c)
        if harness_ll:
            print(f"OK → {harness_ll}")
            break

        print("COMPILE ERROR:\n" + stderr)
        if attempt == MAX_RETRIES:
            sys.exit("VALIDATION: FAIL — compile errors after all retries")

        messages.append({"role": "assistant", "content": reply})
        messages.append({
            "role": "user",
            "content": (
                "The harness failed to compile. Fix the C code and output "
                "corrected C only (no explanation).\n\n"
                f"Compiler error:\n```\n{stderr.strip()}\n```"
            ),
        })

    # ── 5. self-harm check ───────────────────────────────────────────────────
    print("\n── ir-score on harness (self-harm check) ────────────")
    r = subprocess.run(
        ["ir-score", "--ir-dir", str(harness_ll)],
        capture_output=True, text=True,
    )
    print(r.stdout or "(no sinks — harness is trivially clean)")

    score = parse_top_score(r.stdout)
    if score is not None:
        print(f"Self-harm verdict: {self_harm_verdict(score)}")
    print("\nDone. To fuzz:")
    print(f"  clang-20 -fsanitize=fuzzer,address {out_c} <target_lib> -o fuzzer_{fn_name}")
    print(f"  ./fuzzer_{fn_name}")


if __name__ == "__main__":
    main()
