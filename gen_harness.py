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
    python gen_harness.py --ll target.ll --function foo --save-prompt  # inspect what the LLM sees

Validation steps:
  1. Compile harness to IR  (catches syntax / API errors — retries with compiler error)
  2. ir-score on harness IR (catches self-harm: unguarded access in harness code)
     Score interpretation in harness context:
       < 80%  — OK: expected harness boilerplate (malloc, GEP, null-terminated copies)
       80-89% — REVIEW: check flagged sinks
       >= 90% — WARNING: likely real bug in the harness itself
"""

import argparse
import json
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
- If the hint says "strcmp gate" with a single literal, hardcode that literal \
and fuzz only the other argument(s).
- If the hint says "command router" with a list of literals, randomize the \
routed argument across all listed literals on each call — do not hardcode one; \
examine the function's API to determine if any literal requires prior \
initialization before the others.
- If the hint says "split-input pattern required", split Data into two independent \
regions so the source buffer and the length can diverge; do not call the function \
with matching (Data, Size).
- If the hint says "fuzz integer truncation … do not artificially bound the output \
buffer", do not add any size cap or MAX_SIZE guard.
- Never add artificial safety caps (e.g. `if (Size > 1024) return 0`). The whole \
point is to reach the dangerous sizes the slicer identified.
- Use the exact function signature from the IR or API reference. Do not invent \
parameters.
- If an "API reference" header is provided, always `#include` it — never redefine \
structs, typedefs, or enums that are declared in it. Redefining types that don't \
match the compiled target causes silent layout mismatches and missed bugs.
- Output C code only — no explanation, no markdown prose outside the code block.\
"""


# ---------------------------------------------------------------------------
# IR utilities
# ---------------------------------------------------------------------------

def get_context(ll_path: str, fn_name: str) -> str:
    r = subprocess.run(["ir-context", ll_path, "--function", fn_name],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        err = r.stderr.strip() or "(no output)"
        print(f"WARNING: ir-context returned no context (rc={r.returncode}):\n  {err}")
    return r.stdout.strip()


def get_context_json(ll_path: str, fn_name: str) -> dict:
    """Return the raw slice summary dict from ir-context --json, or {}."""
    r = subprocess.run(["ir-context", ll_path, "--function", fn_name, "--json"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}


def resolve_public_caller(ll_path: str, fn_name: str,
                          header_text: str, ir_dir: str) -> "tuple[str, str] | None":
    """Find the best public caller of fn_name.

    Uses caller_names from the slice JSON. Searches all .ll files in ir_dir
    for a function that (a) is in the header and (b) appears in caller_names.
    Returns (caller_ll_path, caller_fn_name) or None.
    """
    if not header_text:
        return None
    summary = get_context_json(ll_path, fn_name)
    caller_names = summary.get("caller_names", [])
    if not caller_names:
        return None

    public_callers = [c for c in caller_names if fn_in_header(c, header_text)]
    if not public_callers:
        return None

    # Find which .ll file defines each public caller
    search_dir = Path(ir_dir) if ir_dir else Path(ll_path).parent
    for ll in search_dir.glob("*.ll"):
        try:
            text = ll.read_text(errors="replace")
        except OSError:
            continue
        for caller in public_callers:
            if re.search(rf'^define\b[^@]*@{re.escape(caller)}\b', text, re.MULTILINE):
                return (str(ll), caller)
    return None


def extract_fn_source(src_text: str, fn_name: str) -> str:
    """Extract the body of fn_name from C source text using brace matching.

    Finds the function definition line then walks forward tracking brace depth
    until the matching closing brace. Returns the full function text including
    signature, or empty string if not found.
    """
    # Match a function definition: return-type fn_name(...) possibly across lines.
    # We look for fn_name followed by '(' not preceded by another word char
    # (to avoid matching calls or type names that contain fn_name).
    pattern = re.compile(
        rf'(?m)^[^\n#/][^\n]*\b{re.escape(fn_name)}\s*\([^;{{]*\{{'
    )
    m = pattern.search(src_text)
    if not m:
        # Fallback: find the opening brace on the next line after the signature
        sig_pat = re.compile(rf'(?m)\b{re.escape(fn_name)}\s*\(')
        sm = sig_pat.search(src_text)
        if not sm:
            return ""
        # Walk forward from the match to find the first '{'
        start = src_text.find('{', sm.start())
        if start == -1:
            return ""
        fn_start = src_text.rfind('\n', 0, sm.start()) + 1
    else:
        start    = src_text.index('{', m.start())
        fn_start = m.start()

    depth = 0
    i = start
    while i < len(src_text):
        ch = src_text[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return src_text[fn_start:i + 1]
        i += 1
    return ""  # unterminated — should not happen for valid C


def find_source_for_ll(ll_path: str, src_dir: str) -> str:
    """Guess the C source file path from the .ll filename and src_dir.

    Heuristic: src_handler.ll → handler.c, src_util.ll → util.c, etc.
    Strips a leading 'src_' prefix and replaces the extension.
    Also tries the stem directly (handler.ll → handler.c).
    """
    stem = Path(ll_path).stem          # e.g. "src_handler"
    candidates = [
        stem,                           # src_handler
        re.sub(r'^src_', '', stem),    # handler
        re.sub(r'^[^_]+_', '', stem),  # handler (strip any prefix)
    ]
    src_dir_path = Path(src_dir)
    for cand in candidates:
        for ext in (".c", ".cpp", ".cc"):
            p = src_dir_path / (cand + ext)
            if p.exists():
                return str(p)
            # also try src/ subdirectory
            p2 = src_dir_path / "src" / (cand + ext)
            if p2.exists():
                return str(p2)
    return ""


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
# Prompt saving
# ---------------------------------------------------------------------------

def save_prompt_file(path: Path, messages: list[dict]) -> None:
    """Write the full message sequence to a markdown file for inspection."""
    lines = [f"# Prompt: {path.stem}\n"]
    for msg in messages:
        role = msg["role"].upper()
        lines.append(f"## {role}\n\n{msg['content']}\n")
    path.write_text("\n---\n\n".join(lines))
    print(f"  Prompt saved: {path}")


# ---------------------------------------------------------------------------
# Source extraction helper (shared by 1:1 and interprocedural paths)
# ---------------------------------------------------------------------------

def _source_block(ll_path: str, fn_name: str, src_dir: str,
                  label: str = "Target function") -> str:
    """Return a markdown source block for fn_name, or empty string."""
    if not src_dir:
        return ""
    src_file = find_source_for_ll(ll_path, src_dir)
    if not src_file:
        print(f"  WARNING: no C source found for {Path(ll_path).name} in {src_dir}")
        return ""
    try:
        src_text = Path(src_file).read_text(errors="replace")
    except OSError as e:
        print(f"  WARNING: could not read {src_file}: {e}")
        return ""
    fn_src = extract_fn_source(src_text, fn_name)
    if not fn_src:
        print(f"  WARNING: could not extract {fn_name} from {src_file}")
        return ""
    print(f"  Source ({label}): {src_file} ({len(fn_src)} chars)")
    return f"\n## {label} (C source)\n```c\n{fn_src}\n```"


# ---------------------------------------------------------------------------
# Interprocedural harness generation (P-05)
# ---------------------------------------------------------------------------

def _generate_interprocedural(vuln_ll: str, vuln_fn: str,
                               caller_ll: str, caller_fn: str,
                               header: str, include_dirs: list[str],
                               output_dir: Path, src_dir: str,
                               save_prompt: bool = False) -> bool:
    """Build a two-section prompt: vulnerable callee context + caller entry point.

    The model sees where the bug is (vuln_fn) and where the harness must
    enter (caller_fn), and must reason about how to drive caller_fn into
    the path that reaches vuln_fn.
    """
    # Vulnerability context from the callee
    vuln_ctx    = get_context(vuln_ll, vuln_fn)
    vuln_sig    = get_ir_signature(vuln_ll, vuln_fn)
    vuln_src    = _source_block(vuln_ll, vuln_fn, src_dir,
                                label=f"Vulnerable function: {vuln_fn}")

    # Caller context (for routing gates etc.)
    caller_ctx  = get_context(caller_ll, caller_fn)
    caller_sig  = get_ir_signature(caller_ll, caller_fn)
    caller_src  = _source_block(caller_ll, caller_fn, src_dir,
                                label=f"Harness entry point: {caller_fn}")

    header_block = f"\n## API reference\n```c\n{header}\n```" if header else ""
    vuln_sig_block   = (f"\n## Vulnerable function signature (from IR)\n```\n{vuln_sig}\n```"
                        if vuln_sig else "")
    caller_sig_block = (f"\n## Entry point signature (from IR)\n```\n{caller_sig}\n```"
                        if caller_sig else "")

    print(f"\n── Vulnerability context ({vuln_fn}) ──")
    print(vuln_ctx)
    print(f"\n── Caller context ({caller_fn}) ──")
    print(caller_ctx)

    initial_prompt = f"""Write a libFuzzer harness in C for security testing.

The vulnerability is in `{vuln_fn}` but it is an internal function not \
directly accessible. The harness must enter via `{caller_fn}`, which is \
the public API function that calls `{vuln_fn}`.

## Static analysis — vulnerable function: {vuln_fn}
{vuln_ctx}
{vuln_sig_block}
{vuln_src}
## Static analysis — harness entry point: {caller_fn}
{caller_ctx}
{caller_sig_block}
{caller_src}
{header_block}
## Task
Write `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)` \
targeting `{caller_fn}`.

Requirements:
- The harness entry point is `{caller_fn}` — do NOT call `{vuln_fn}` directly
- Read both function sources carefully: understand the path through `{caller_fn}` \
that reaches `{vuln_fn}` and set up any required preconditions (state, prior calls, \
argument values) to exercise that path
- Check the API reference for required initialization and teardown functions and call them
- Pass fuzz-controlled data into `{caller_fn}` — do not add artificial caps on Size
- If data is used as a string, null-terminate it first
- Initialize any required state before the call; clean it up after
- Return 0

Output C code only, no explanation."""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": initial_prompt},
    ]
    out_c = output_dir / f"harness_{vuln_fn}_via_{caller_fn}.c"
    output_dir.mkdir(parents=True, exist_ok=True)

    if save_prompt:
        save_prompt_file(output_dir / f"harness_{vuln_fn}_via_{caller_fn}_prompt.md", messages)

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
            print(f"VALIDATION: FAIL — {vuln_fn} via {caller_fn} skipped "
                  f"after {MAX_RETRIES} compile errors")
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

    print("\n── ir-score on harness (self-harm check) ────────────")
    r = subprocess.run(["ir-score", "--ir-dir", str(harness_ll)],
                       capture_output=True, text=True)
    print(r.stdout or "(no sinks — harness is trivially clean)")

    score = parse_top_score(r.stdout)
    if score is not None:
        print(f"Self-harm verdict: {self_harm_verdict(score)}")

    inc = f" -I {include_dirs[0]}" if include_dirs else ""
    print(f"\nTo fuzz:")
    print(f"  clang-20 -fsanitize=fuzzer,address{inc} {out_c} <target_lib> "
          f"-o fuzzer_{vuln_fn}_via_{caller_fn}")
    print(f"  ./fuzzer_{vuln_fn}_via_{caller_fn}")
    return True


# ---------------------------------------------------------------------------
# Single harness generation
# ---------------------------------------------------------------------------

def generate_one(ll_path: str, fn_name: str, header: str,
                 include_dirs: list[str], output_dir: Path,
                 src_dir: str = "", ir_dir: str = "",
                 save_prompt: bool = False) -> bool:
    """Generate, compile, and validate one harness. Returns True on success."""

    print(f"\n{'='*60}")
    print(f"Target: {fn_name}  ({ll_path})")
    print('='*60)

    # Detect interprocedural case: fn_name not in header but has a public caller.
    # When detected, delegate to the interprocedural prompt builder.
    if header and not fn_in_header(fn_name, header):
        search_dir = ir_dir or str(Path(ll_path).parent)
        caller = resolve_public_caller(ll_path, fn_name, header, search_dir)
        if caller:
            caller_ll, caller_fn = caller
            print(f"  P-05: {fn_name} not in header — "
                  f"fuzz via caller `{caller_fn}` ({caller_ll})")
            return _generate_interprocedural(
                vuln_ll=ll_path, vuln_fn=fn_name,
                caller_ll=caller_ll, caller_fn=caller_fn,
                header=header, include_dirs=include_dirs,
                output_dir=output_dir, src_dir=src_dir,
                save_prompt=save_prompt,
            )

    # Standard 1:1 path
    ctx    = get_context(ll_path, fn_name)
    ir_sig = get_ir_signature(ll_path, fn_name)
    print(ctx)
    if ir_sig:
        print(f"\nIR signature: {ir_sig}")

    src_block    = _source_block(ll_path, fn_name, src_dir)
    header_block = f"\n## API reference\n```c\n{header}\n```" if header else ""
    sig_block    = (f"\n## Function signature (from IR)\n```\n{ir_sig}\n```"
                    if ir_sig else "")

    initial_prompt = f"""Write a libFuzzer harness in C for security testing.

## Static analysis (IR slicer output)
{ctx}
{sig_block}
{src_block}
{header_block}
## Task
Write `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)` targeting `{fn_name}`.

Requirements:
- Use the exact function signature from the IR / API reference above
- Read the target function source carefully — understand what state must be \
initialized before calling it and what the function does with its arguments
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

    if save_prompt:
        save_prompt_file(output_dir / f"harness_{fn_name}_prompt.md", messages)

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
    ap.add_argument("--src-dir",      metavar="DIR", default="",
                    help="Directory containing C source files; the target function body "
                         "is extracted and included in the prompt so the model can reason "
                         "about required state and call sequences")
    ap.add_argument("--save-prompt",  action="store_true",
                    help="Write harness_<fn>_prompt.md alongside each harness showing "
                         "the full message sequence sent to the model (system + user turns)")
    args = ap.parse_args()

    if args.ll and not args.function:
        ap.error("--function is required with --ll")
    if args.ll and args.top_k != 1:
        ap.error("--top-k only applies to --ir-dir mode")

    header       = Path(args.header).read_text(errors="replace") if args.header else ""
    include_dirs = [str(Path(args.header).parent)] if args.header else []
    output_dir   = Path(args.output_dir)
    src_dir      = args.src_dir

    if args.ll:
        generate_one(args.ll, args.function, header, include_dirs, output_dir,
                     src_dir=src_dir,
                     ir_dir=str(Path(args.ll).parent),
                     save_prompt=args.save_prompt)
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
        ok = generate_one(ll_path, fn_name, header, include_dirs, output_dir,
                          src_dir=src_dir, ir_dir=args.ir_dir,
                          save_prompt=args.save_prompt)
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
