#!/usr/bin/env python3
"""
gen_harness.py — MVP: slice context → Qwen → harness C → IR validation.

Usage:
    export QWEN_API_KEY=sk-...

    # Auto-pick top public function from a directory (preferred)
    python gen_harness.py --ir-dir <dir/> [--no-gep-only] [--header <header.h>]

    # Explicit target
    python gen_harness.py --ll <target.ll> --function <fn> [--header <header.h>]

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
SELF_HARM_WARN = 0.90


# ---------------------------------------------------------------------------
# IR utilities
# ---------------------------------------------------------------------------

def get_context(ll_path: str, fn_name: str) -> str:
    r = subprocess.run(["ir-context", ll_path, "--function", fn_name],
                       capture_output=True, text=True)
    return r.stdout.strip()


def get_ir_signature(ll_path: str, fn_name: str) -> str:
    """Extract the function signature line from the .ll file."""
    try:
        text = Path(ll_path).read_text(errors="replace")
    except OSError:
        return ""
    # Match 'define ... @fn_name(...)'
    m = re.search(
        rf'^define\b[^@]*@{re.escape(fn_name)}\s*\([^)]*\)',
        text, re.MULTILINE
    )
    return m.group(0) if m else ""


def fn_in_header(fn_name: str, header_text: str) -> bool:
    """True if fn_name appears as a declaration in the header text."""
    return bool(re.search(rf'\b{re.escape(fn_name)}\s*\(', header_text))


def ranked_functions(ir_dir: str, no_gep_only: bool) -> list[tuple[str, str]]:
    """Return list of (ll_path, fn_name) in score order from ir-score output."""
    cmd = ["ir-score", "--ir-dir", ir_dir]
    if no_gep_only:
        cmd.append("--no-gep-only")
    r = subprocess.run(cmd, capture_output=True, text=True)
    results = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s+(\d+)\s+(\S+)\s+[\d.]+%.*\((\S+\.ll)\)", line)
        if m:
            fn_name  = m.group(2)
            src_file = m.group(3)
            ll_path  = str(Path(ir_dir) / src_file)
            results.append((ll_path, fn_name))
    if not results:
        sys.exit("Could not parse any functions from ir-score output:\n" + r.stdout)
    return results


def pick_top_function(ir_dir: str, no_gep_only: bool,
                      header_text: str) -> tuple[str, str]:
    """Pick the highest-ranked function that appears in the header (if provided).

    When a header is given, internal helpers (not declared in the public API)
    are skipped — they can't be called directly from a harness and the LLM
    has no signature to work from. Falls back to rank 1 if nothing matches.
    """
    ranked = ranked_functions(ir_dir, no_gep_only)
    if header_text:
        for ll_path, fn_name in ranked:
            if fn_in_header(fn_name, header_text):
                return ll_path, fn_name
        print("  (no ranked function found in header — falling back to rank 1)")
    return ranked[0]


# ---------------------------------------------------------------------------
# Qwen
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Compilation + validation
# ---------------------------------------------------------------------------

def compile_to_ir(src: Path) -> tuple[Path | None, str]:
    out = src.with_suffix(".ll")
    r = subprocess.run(
        ["clang-20", "-O0", "-fno-inline", "-S", "-emit-llvm", "-w",
         str(src), "-o", str(out)],
        capture_output=True, text=True,
    )
    return (out, "") if r.returncode == 0 else (None, r.stderr)


def self_harm_verdict(score: float) -> str:
    if score >= SELF_HARM_WARN:
        return f"WARNING ({score:.0%}) — likely real bug in harness; review before fuzzing"
    if score >= 0.60:
        return f"REVIEW ({score:.0%}) — elevated; check flagged sinks"
    return f"OK ({score:.0%}) — expected harness noise"


def parse_top_score(output: str) -> float | None:
    for line in output.splitlines():
        if "LLVMFuzzerTestOneInput" in line:
            m = re.search(r"([\d.]+)%", line)
            if m:
                return float(m.group(1)) / 100
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ll",         metavar="FILE")
    src.add_argument("--ir-dir",     metavar="DIR")
    ap.add_argument("--function",    metavar="FN",
                    help="Required with --ll")
    ap.add_argument("--no-gep-only", action="store_true")
    ap.add_argument("--header",      metavar="FILE")
    args = ap.parse_args()

    if args.ll and not args.function:
        ap.error("--function is required with --ll")

    header = Path(args.header).read_text(errors="replace") if args.header else ""

    # ── 1. resolve target ─────────────────────────────────────────────────────
    if args.ir_dir:
        print(f"── auto-picking top public function from {args.ir_dir} ──")
        ll_path, fn_name = pick_top_function(args.ir_dir, args.no_gep_only, header)
        print(f"   → {fn_name}  ({ll_path})")
    else:
        ll_path, fn_name = args.ll, args.function

    # ── 2. slice context + IR signature ──────────────────────────────────────
    print(f"\n── slice context: {fn_name} ──────────────────────────")
    ctx = get_context(ll_path, fn_name)
    print(ctx)

    ir_sig = get_ir_signature(ll_path, fn_name)
    if ir_sig:
        print(f"\nIR signature: {ir_sig}")

    # ── 3. build prompt ───────────────────────────────────────────────────────
    header_block = f"\n## API reference\n```c\n{header}\n```" if header else ""
    sig_block    = (f"\n## Function signature (from IR)\n```\n{ir_sig}\n```"
                    if ir_sig else "")
    initial_prompt = f"""Write a libFuzzer harness in C for security testing.

## Static analysis (IR slicer output)
{ctx}
{sig_block}
{header_block}
## Task
Write `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)` targeting `{fn_name}`.

Requirements:
- Use the exact function signature from the IR / API reference above
- Check the API reference for required initialization and teardown functions and call them
- Pass `Data` and `Size` into `{fn_name}` — do not add artificial caps on Size
- If `Data` is used as a string (passed to a function expecting `const char *`), null-terminate it first: copy into a heap buffer of `Size + 1` bytes and set the last byte to `\\0`
- Initialize any required state before the call; clean it up after
- Return 0

Output C code only, no explanation."""

    messages = [{"role": "user", "content": initial_prompt}]
    out_c    = Path(f"harness_{fn_name}.c")

    # ── 4. Qwen with compile-error retry ─────────────────────────────────────
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
    r = subprocess.run(["ir-score", "--ir-dir", str(harness_ll)],
                       capture_output=True, text=True)
    print(r.stdout or "(no sinks — harness is trivially clean)")

    score = parse_top_score(r.stdout)
    if score is not None:
        print(f"Self-harm verdict: {self_harm_verdict(score)}")

    print("\nDone. To fuzz:")
    print(f"  clang-20 -fsanitize=fuzzer,address {out_c} <target_lib> -o fuzzer_{fn_name}")
    print(f"  ./fuzzer_{fn_name}")


if __name__ == "__main__":
    main()
