#!/usr/bin/env python3
"""
gen_harness.py — MVP: slice context → Qwen → harness C → IR validation.

Usage:
    export QWEN_API_KEY=sk-...
    python gen_harness.py <target.ll> <function_name> [<header.h>]

Example:
    python gen_harness.py /tmp/zlib-ir/inflate.ll inflate /usr/include/zlib.h

Validation steps:
  1. Compile harness to IR  (catches syntax / API errors — retries with error)
  2. ir-score on harness IR (catches self-harm: unguarded access in test code)
"""

import os
import re
import subprocess
import sys
from pathlib import Path

import requests

ENDPOINT   = "https://litellm-litemaas.apps.prod.rhoai.rh-aiservices-bu.com/v1/chat/completions"
MODEL      = "Qwen3.6-35B-A3B"
MAX_RETRIES = 3


def get_context(ll_path: str, fn_name: str) -> str:
    r = subprocess.run(["ir-context", ll_path, "--function", fn_name],
                       capture_output=True, text=True)
    return r.stdout.strip()


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


def main():
    if len(sys.argv) < 3:
        sys.exit(f"usage: {sys.argv[0]} <target.ll> <fn_name> [<header.h>]")

    ll_path  = sys.argv[1]
    fn_name  = sys.argv[2]
    header   = Path(sys.argv[3]).read_text() if len(sys.argv) > 3 else ""

    # ── 1. slice context ──────────────────────────────────────────────────────
    print(f"── slice context: {fn_name} ─────────────────────────")
    ctx = get_context(ll_path, fn_name)
    print(ctx)

    # ── 2. build initial prompt ───────────────────────────────────────────────
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

    # ── 3. call Qwen with compile-error retry loop ────────────────────────────
    harness_ll = None
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n── calling {MODEL} (attempt {attempt}/{MAX_RETRIES}) ─────────")
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

        # Feed the compiler error back as a follow-up message so Qwen has
        # both the original context and the specific failure.
        messages.append({"role": "assistant", "content": reply})
        messages.append({
            "role": "user",
            "content": (
                f"The harness failed to compile. Fix the C code and output "
                f"corrected C only (no explanation).\n\n"
                f"Compiler error:\n```\n{stderr.strip()}\n```"
            ),
        })

    # ── 4. self-harm check ───────────────────────────────────────────────────
    print("\n── ir-score on harness (self-harm check) ────────────")
    r = subprocess.run(
        ["ir-score", "--ir-dir", str(harness_ll)],
        capture_output=True, text=True,
    )
    print(r.stdout or "(no sinks found in harness — looks clean)")


if __name__ == "__main__":
    main()
