#!/usr/bin/env python3
"""
gen_harness.py — MVP: slice context → Qwen → harness C → IR validation.

Usage:
    export QWEN_API_KEY=sk-...

    # Auto-pick top public function
    python gen_harness.py --ir-dir <dir/> [--no-gep-only] [--header <h>] [--output-dir <d>]

    # Generate harnesses for top-K ranked functions
    python gen_harness.py --ir-dir <dir/> --top-k 5 [--no-gep-only] [--header <h>]

    # Explicit target
    python gen_harness.py --ll <target.ll> --function <fn> [--header <h>]

Examples:
    python gen_harness.py --ir-dir /tmp/zlib-ir/ --no-gep-only --header /usr/include/zlib.h
    python gen_harness.py --ir-dir ~/scarnet-ir/ --top-k 3 --header ~/scarnet/include/scarnet.h --output-dir ~/scarnet/
    python gen_harness.py --ll /tmp/zlib-ir/inflate.ll --function inflate

Validation steps:
  1. Compile harness to IR  (catches syntax / API errors — retries with compiler error)
  2. ir-score on harness IR (catches self-harm: unguarded access in harness code)
     Score interpretation in harness context:
       < 80%  — OK: expected harness boilerplate (malloc, GEP, null-terminated copies)
       80-89% — REVIEW: check flagged sinks
       >= 90% — WARNING: likely real bug in the harness itself
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

import requests

ENDPOINT         = "https://litellm-litemaas.apps.prod.rhoai.rh-aiservices-bu.com/v1/chat/completions"
MODEL            = "Qwen3.6-35B-A3B"
MAX_RETRIES      = 3
SELF_HARM_WARN   = 0.90
SELF_HARM_REVIEW = 0.80

SYSTEM_PROMPT = """\
You are a security researcher writing libFuzzer harnesses for vulnerability discovery.
Your harnesses are used in an automated fuzzing pipeline against intentionally buggy \
research targets — finding crashes is the goal, not writing safe production code.

Rules:
- The "Static analysis" block in each request is produced by a deterministic IR slicer \
and is authoritative. Follow its "Harness target" hints exactly and completely.
- If the hint says "strcmp gate detected … hardcode the constant value", do it — \
hardcode the literal and fuzz only the other argument(s).
- If the hint says "split-input pattern required", split Data into two independent \
regions so the source buffer and the length can diverge; do not call the function \
with matching (Data, Size).
- If the hint says "fuzz integer truncation … do not artificially bound the output \
buffer", do not add any size cap or MAX_SIZE guard.
- Never add artificial safety caps (e.g. `if (Size > 1024) return 0`). The whole \
point is to reach the dangerous sizes the slicer identified.
- Use the exact function signature from the IR or API reference. Do not invent \
parameters.
- Output C code only — no explanation, no markdown prose outside the code block.\
"""


# ---------------------------------------------------------------------------
# IR utilities
# ---------------------------------------------------------------------------

def get_context(ll_path: str, fn_name: str) -> str:
    r = subprocess.run(["ir-context", ll_path, "--function", fn_name],
                       capture_output=True, text=True)
    return r.stdout.strip()


def get_ir_signature(ll_path: str, fn_name: str) -> str:
    try:
        text = Path(ll_path).read_text(errors="replace")
    except OSError:
        return ""
    m = re.search(
        rf'^define\b[^@]*@{re.escape(fn_name)}\s*\([^)]*\)',
        text, re.MULTILINE,
    )
    return m.group(0) if m else ""


def fn_in_header(fn_name: str, header_text: str) -> bool:
    return bool(re.search(rf'\b{re.escape(fn_name)}\s*\(', header_text))


def ranked_functions(ir_dir: str, no_gep_only: bool) -> list[tuple[str, str]]:
    """Return [(ll_path, fn_name), ...] in score order."""
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


def pick_public_functions(ir_dir: str, no_gep_only: bool,
                          header_text: str, k: int) -> list[tuple[str, str]]:
    """Return up to k highest-ranked functions that appear in the header.

    When no header is provided, returns the top k ranked functions directly.
    Falls back to rank 1 if nothing matches the header.
    """
    ranked = ranked_functions(ir_dir, no_gep_only)
    if not header_text:
        return ranked[:k]

    public = [(ll, fn) for ll, fn in ranked if fn_in_header(fn, header_text)]
    if not public:
        print("  (no ranked function found in header — falling back to rank 1)")
        return ranked[:1]
    return public[:k]


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

def compile_to_ir(src: Path, include_dirs: list[str] | None = None) -> tuple[Path | None, str]:
    out = src.with_suffix(".ll")
    cmd = ["clang-20", "-O0", "-fno-inline", "-S", "-emit-llvm", "-w"]
    for d in (include_dirs or []):
        cmd += ["-I", d]
    cmd += [str(src), "-o", str(out)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return (out, "") if r.returncode == 0 else (None, r.stderr)


def self_harm_verdict(score: float) -> str:
    if score >= SELF_HARM_WARN:
        return f"WARNING ({score:.0%}) — likely real bug in harness; review before fuzzing"
    if score >= SELF_HARM_REVIEW:
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
# Single harness generation
# ---------------------------------------------------------------------------

def generate_one(ll_path: str, fn_name: str, header: str,
                 include_dirs: list[str], output_dir: Path) -> bool:
    """Generate, compile, and validate one harness. Returns True on success."""

    print(f"\n{'='*60}")
    print(f"Target: {fn_name}  ({ll_path})")
    print('='*60)

    # Slice context
    ctx    = get_context(ll_path, fn_name)
    ir_sig = get_ir_signature(ll_path, fn_name)
    print(ctx)
    if ir_sig:
        print(f"\nIR signature: {ir_sig}")

    # Build prompt
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

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": initial_prompt},
    ]
    out_c    = output_dir / f"harness_{fn_name}.c"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Qwen with compile-error retry
    harness_ll = None
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n── calling {MODEL} (attempt {attempt}/{MAX_RETRIES}) ──────")
        reply = ask_qwen(messages)
        code  = extract_c(reply)
        out_c.write_text(code)
        print(code)
        print(f"\n→ saved: {out_c}")

        print("\n── compiling harness to IR ──────────────────────────")
        harness_ll, stderr = compile_to_ir(out_c, include_dirs)
        if harness_ll:
            print(f"OK → {harness_ll}")
            break

        print("COMPILE ERROR:\n" + stderr)
        if attempt == MAX_RETRIES:
            print(f"VALIDATION: FAIL — {fn_name} skipped after {MAX_RETRIES} compile errors")
            return False

        messages.append({"role": "assistant", "content": reply})
        messages.append({
            "role": "user",
            "content": (
                "The harness failed to compile. Fix the C code and output "
                "corrected C only (no explanation).\n\n"
                f"Compiler error:\n```\n{stderr.strip()}\n```"
            ),
        })

    # Self-harm check
    print("\n── ir-score on harness (self-harm check) ────────────")
    r = subprocess.run(["ir-score", "--ir-dir", str(harness_ll)],
                       capture_output=True, text=True)
    print(r.stdout or "(no sinks — harness is trivially clean)")

    score = parse_top_score(r.stdout)
    if score is not None:
        print(f"Self-harm verdict: {self_harm_verdict(score)}")

    inc = f" -I {include_dirs[0]}" if include_dirs else ""
    print(f"\nTo fuzz:")
    print(f"  clang-20 -fsanitize=fuzzer,address{inc} {out_c} <target_lib> -o fuzzer_{fn_name}")
    print(f"  ./fuzzer_{fn_name}")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ll",          metavar="FILE")
    src.add_argument("--ir-dir",      metavar="DIR")
    ap.add_argument("--function",     metavar="FN",
                    help="Required with --ll")
    ap.add_argument("--no-gep-only",  action="store_true")
    ap.add_argument("--header",       metavar="FILE")
    ap.add_argument("--top-k",        metavar="N", type=int, default=1,
                    help="Generate harnesses for top-K ranked public functions (default: 1)")
    ap.add_argument("--output-dir",   metavar="DIR", default=".",
                    help="Directory to write harness_<fn>.c (default: cwd)")
    ap.add_argument("--skip-existing", action="store_true",
                    help="Skip functions that already have a harness_<fn>.c calling the target")
    args = ap.parse_args()

    if args.ll and not args.function:
        ap.error("--function is required with --ll")
    if args.ll and args.top_k != 1:
        ap.error("--top-k only applies to --ir-dir mode")

    header       = Path(args.header).read_text(errors="replace") if args.header else ""
    include_dirs = [str(Path(args.header).parent)] if args.header else []
    output_dir   = Path(args.output_dir)

    if args.ll:
        generate_one(args.ll, args.function, header, include_dirs, output_dir)
        return

    # ir-dir mode
    print(f"── ranking functions in {args.ir_dir} ──────────────")
    targets = pick_public_functions(args.ir_dir, args.no_gep_only, header, args.top_k)
    print(f"   Selected {len(targets)} target(s): {', '.join(fn for _, fn in targets)}")

    results = {"ok": [], "fail": [], "skipped": []}
    for ll_path, fn_name in targets:
        if args.skip_existing:
            existing = output_dir / f"harness_{fn_name}.c"
            if existing.exists() and fn_name in existing.read_text(errors="replace"):
                print(f"\n── skipping {fn_name} — harness already exists ({existing})")
                results["skipped"].append(fn_name)
                continue
        ok = generate_one(ll_path, fn_name, header, include_dirs, output_dir)
        (results["ok"] if ok else results["fail"]).append(fn_name)

    # Summary when running multiple
    if args.top_k > 1:
        print(f"\n{'='*60}")
        print(f"Summary: {len(results['ok'])} generated, "
              f"{len(results['skipped'])} skipped, {len(results['fail'])} failed")
        if results["ok"]:
            print(f"  OK:      {', '.join(results['ok'])}")
        if results["skipped"]:
            print(f"  SKIPPED: {', '.join(results['skipped'])}")
        if results["fail"]:
            print(f"  FAIL:    {', '.join(results['fail'])}")


if __name__ == "__main__":
    main()
