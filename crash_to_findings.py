#!/usr/bin/env python3
"""
crash_to_findings.py — Convert a libFuzzer/ASAN crash to SCAR findings JSON.

Reads a crash artifact and optional ASAN log, extracts file/line from the ASAN
stack trace, enriches the finding message with IR slice context, and writes
a findings-llvm-ir.json file that SCAR's repair loop can consume directly.

Usage:
    python crash_to_findings.py \\
        --crash ~/scarnet/handle_stats_crash_<hash> \\
        --asan-log ~/scarnet/asan.log \\
        --ll ~/scarnet-ir/src_handler.ll \\
        --function handle_stats \\
        --repo ~/scarnet/ \\
        [--output ~/scarnet/.scar/findings-llvm-ir.json]

    # Re-run the fuzzer with the crash to capture ASAN output:
    ./fuzzer_handle_stats handle_stats_crash_<hash> 2>asan.log

Output written to <repo>/.scar/findings-llvm-ir.json by default.
Appends to existing findings in that file (deduplicates by file+line).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Symbolizer discovery
# ---------------------------------------------------------------------------

def _find_symbolizer() -> str | None:
    """Return the path to llvm-symbolizer, trying versioned names first."""
    for name in ("llvm-symbolizer-20", "llvm-symbolizer-19", "llvm-symbolizer-18",
                 "llvm-symbolizer"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _asan_env() -> dict:
    """Return env vars that make ASAN use the best available symbolizer."""
    env = dict(os.environ)
    sym = _find_symbolizer()
    if sym and "ASAN_SYMBOLIZER_PATH" not in env:
        env["ASAN_SYMBOLIZER_PATH"] = sym
    return env


# ---------------------------------------------------------------------------
# ASAN log parsing
# ---------------------------------------------------------------------------

# Matches lines like:
#   #1 0x... in handle_stats /home/user/scarnet/src/handler.c:42:5
#   #1 0x... in handle_stats handler.c:42
_FRAME_RE = re.compile(
    r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+(/.+?):(\d+)"
)

# Bug type line: "AddressSanitizer: heap-buffer-overflow ..."
_BUG_TYPE_RE = re.compile(
    r"ERROR: (?:AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer):\s*(.+?)(?:\s+on\s+address|\s+at\s+pc|\s*$)",
    re.IGNORECASE,
)

# SIGFPE / signal crashes: "SUMMARY: ... SIGSEGV" or runtime error lines
_SUMMARY_RE = re.compile(r"SUMMARY:\s+(.+)")


def _asan_rule_id(bug_type: str) -> str:
    t = bug_type.lower()
    if "divide-by-zero" in t or "division by zero" in t or "fpe" in t or "sigfpe" in t:
        return "DIV_BY_ZERO"
    if "double-free" in t:
        return "DOUBLE_FREE"
    if "heap-buffer-overflow" in t:
        return "HEAP_BUFFER_OVERFLOW"
    if "stack-buffer-overflow" in t:
        return "STACK_BUFFER_OVERFLOW"
    if "use-after-free" in t:
        return "USE_AFTER_FREE"
    if "null" in t:
        return "NULL_DEREF"
    if "format-string" in t or "printf" in t:
        return "FORMAT_STRING"
    if "undefined" in t or "ubsan" in t:
        return "UNDEFINED_BEHAVIOR"
    return "MEMORY_SAFETY"


def _symbolize_address(binary: str, addr: str) -> "tuple[str,str,int] | None":
    """Try to resolve a raw address to (func, file, line) using llvm-symbolizer.

    Returns None if no symbolizer is available or address cannot be resolved.
    """
    sym = _find_symbolizer()
    if not sym:
        return None
    try:
        r = subprocess.run(
            [sym, "--exe", binary, addr],
            capture_output=True, text=True, timeout=10,
        )
        lines = r.stdout.strip().splitlines()
        if len(lines) >= 2:
            func = lines[0].strip()
            loc  = lines[1].strip()   # file:line:col
            parts = loc.rsplit(":", 2)
            if len(parts) >= 2 and parts[-2].isdigit():
                return func, parts[0], int(parts[-2])
            elif len(parts) >= 1:
                m = re.search(r":(\d+)", loc)
                if m:
                    return func, parts[0], int(m.group(1))
    except Exception:
        pass
    return None


# Matches raw-address frames when symbolizer wasn't available:
#   #0 0x0000005249b7  (/path/to/binary+0x5249b7)
_RAW_FRAME_RE = re.compile(
    r"#(\d+)\s+0x[0-9a-f]+\s+\((.+?)\+0x([0-9a-f]+)\)"
)


def parse_asan_log(log_text: str, fn_name: str | None = None) -> dict | None:
    """Extract (rule_id, file_path, line, message) from ASAN output.

    Prefers a stack frame that matches fn_name if provided.
    Falls back to the first user-code frame (skips libFuzzer internals).
    When debug symbols are absent, attempts to symbolize raw addresses via
    llvm-symbolizer. Returns None if the log cannot be parsed.
    """
    bug_type = ""
    m = _BUG_TYPE_RE.search(log_text)
    if m:
        bug_type = m.group(1).strip()
    else:
        m = _SUMMARY_RE.search(log_text)
        if m:
            bug_type = m.group(1).strip()

    # Try symbolic frames first (binary compiled with -g and symbolizer ran)
    frames = _FRAME_RE.findall(log_text)  # list of (func, file, line)
    best_func, best_file, best_line = None, None, None
    for func, fpath, lineno in frames:
        if fn_name and func == fn_name:
            best_func, best_file, best_line = func, fpath, int(lineno)
            break
        if best_func is None and "LLVMFuzzer" not in func and "sanitizer" not in func.lower():
            best_func, best_file, best_line = func, fpath, int(lineno)

    # If no symbolic frames, try to symbolize raw addresses
    if best_file is None:
        raw_frames = _RAW_FRAME_RE.findall(log_text)  # (frame_no, binary, offset)
        for _fno, binary, offset in raw_frames:
            if "libc" in binary or "libfuzzer" in binary.lower():
                continue
            result = _symbolize_address(binary, f"0x{offset}")
            if result:
                func, fpath, lineno = result
                if fn_name and func == fn_name:
                    best_func, best_file, best_line = func, fpath, lineno
                    break
                if best_func is None and "LLVMFuzzer" not in func:
                    best_func, best_file, best_line = func, fpath, lineno

    if best_file is None:
        return None

    rule_id = _asan_rule_id(bug_type)
    message = (
        f"libFuzzer/ASAN crash: {bug_type or 'unknown'} "
        f"in {best_func or '?'} at line {best_line}."
    )
    return {
        "rule_id": rule_id,
        "file_path": best_file,
        "line": best_line,
        "bug_type": bug_type,
        "message": message,
    }


# ---------------------------------------------------------------------------
# IR slice enrichment
# ---------------------------------------------------------------------------

def _ir_context(ll_path: str, fn_name: str) -> str:
    """Return the IR slice context string for fn_name, or empty string."""
    r = subprocess.run(
        ["ir-context", ll_path, "--function", fn_name],
        capture_output=True, text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else ""


def _ir_summary(ll_path: str, fn_name: str) -> dict:
    """Return the slice summary dict from ir-context --json, or {}."""
    r = subprocess.run(
        ["ir-context", ll_path, "--function", fn_name, "--json"],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}


def enrich_message(base_message: str, ll_path: str | None, fn_name: str | None) -> str:
    """Append IR slice facts to the ASAN message for SCAR's context_gen."""
    if not ll_path or not fn_name:
        return base_message

    ctx = _ir_context(ll_path, fn_name)
    if not ctx:
        return base_message

    summary = _ir_summary(ll_path, fn_name)
    hint = summary.get("harness_hint", "")

    parts = [base_message, "\n\n--- IR Slice Analysis ---\n" + ctx]
    if hint:
        parts.append(f"\nSlicer harness hint: {hint}")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Findings file I/O
# ---------------------------------------------------------------------------

def _load_existing(path: Path) -> list[dict]:
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


def _dedup(findings: list[dict]) -> list[dict]:
    """Keep one finding per (file_path, line) — last one wins."""
    seen: dict[tuple, dict] = {}
    for f in findings:
        key = (str(Path(f["file_path"]).resolve()), f["line"])
        seen[key] = f
    return list(seen.values())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Convert a libFuzzer/ASAN crash to SCAR findings JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--crash",    metavar="FILE",
                    help="Crash artifact file from libFuzzer")
    ap.add_argument("--asan-log", metavar="FILE",
                    help="File containing ASAN stderr output. "
                         "If omitted, re-runs the fuzzer binary to capture it.")
    ap.add_argument("--fuzzer",   metavar="BINARY",
                    help="Fuzzer binary path (used to capture ASAN log when --asan-log is omitted)")
    ap.add_argument("--ll",       metavar="FILE",
                    help="LLVM IR (.ll) file for the target function")
    ap.add_argument("--function", metavar="FN",
                    help="Target function name (used to pick the right stack frame "
                         "and enrich the message with IR context)")
    ap.add_argument("--repo",     metavar="DIR", required=True,
                    help="Root of the target repository (SCAR writes patches here)")
    ap.add_argument("--output",   metavar="FILE",
                    help="Output path for findings JSON "
                         "(default: <repo>/.scar/findings-llvm-ir.json)")
    ap.add_argument("--severity", default="error",
                    choices=["error", "warning", "note"],
                    help="SCAR severity level (default: error)")
    ap.add_argument("--file",     metavar="FILE",
                    help="Override: source file path of the bug (skips ASAN log parsing)")
    ap.add_argument("--line",     metavar="N", type=int,
                    help="Override: line number of the bug (skips ASAN log parsing)")
    ap.add_argument("--replace",  action="store_true",
                    help="Remove all existing findings for the same --file before appending. "
                         "Prevents stale entries from accumulating when re-running on the same target.")
    args = ap.parse_args()

    # --- Get ASAN output ---
    # Not required when --file + --line are provided as explicit overrides.
    log_text = ""
    if args.asan_log:
        log_text = Path(args.asan_log).read_text(errors="replace")
    elif args.fuzzer and args.crash:
        print(f"Re-running {args.fuzzer} on crash to capture ASAN output …")
        r = subprocess.run(
            [args.fuzzer, args.crash],
            capture_output=True, text=True, timeout=30,
            env=_asan_env(),
        )
        log_text = r.stderr  # ASAN writes to stderr
        if not log_text.strip():
            sys.exit("ERROR: fuzzer produced no ASAN output. "
                     "Was it built with -fsanitize=address?")
    elif args.crash:
        log_text = Path(args.crash).read_text(errors="replace")
        if "AddressSanitizer" not in log_text and "SUMMARY" not in log_text:
            sys.exit("ERROR: --crash file does not look like an ASAN log. "
                     "Provide --asan-log or --fuzzer to capture ASAN output.")
    elif not (args.file and args.line):
        sys.exit("ERROR: provide --asan-log <file>, or --fuzzer + --crash, "
                 "or --file + --line to specify the bug location directly.")

    # --- Parse ASAN log or use explicit override ---
    if args.file and args.line:
        # Explicit override — skip log parsing entirely
        bug_type = ""
        if log_text:
            m = _BUG_TYPE_RE.search(log_text)
            if m:
                bug_type = m.group(1).strip()
            elif _SUMMARY_RE.search(log_text):
                # SIGFPE / signal crashes lack an ERROR: line but have SUMMARY
                ms = _SUMMARY_RE.search(log_text)
                bug_type = ms.group(1).strip()
        rule_id = _asan_rule_id(bug_type) if bug_type else "MEMORY_SAFETY"
        # Make the message specific enough for SCAR's context_gen to pick the right sink
        if rule_id == "DIV_BY_ZERO":
            crash_desc = "divide-by-zero (SIGFPE)"
        elif bug_type:
            crash_desc = bug_type
        else:
            crash_desc = "unknown crash"
        parsed = {
            "rule_id":   rule_id,
            "file_path": args.file,
            "line":      args.line,
            "bug_type":  bug_type,
            "message":   (
                f"libFuzzer/ASAN crash: {crash_desc} "
                f"in {args.function or '?'} at line {args.line}."
            ),
        }
        print(f"  Using explicit location override ({rule_id})")
    else:
        parsed = parse_asan_log(log_text, fn_name=args.function)
        if parsed is None:
            sys.exit(
                "ERROR: could not extract file/line from ASAN output.\n"
                "The stack trace must include function names and file paths.\n"
                "Options:\n"
                "  1. Rebuild with debug info and ensure llvm-symbolizer is in PATH:\n"
                "       clang-20 -fsanitize=fuzzer,address -g -I include \\\n"
                "           harness_<fn>.c src/*.c -o fuzzer_<fn>\n"
                "       export PATH=/usr/lib/llvm-20/bin:$PATH\n"
                "  2. Skip ASAN parsing and provide location directly:\n"
                "       --file src/handler.c --line 87\n"
            )

    print(f"  Bug type  : {parsed['bug_type'] or '(unknown)'}")
    print(f"  Rule ID   : {parsed['rule_id']}")
    print(f"  Location  : {parsed['file_path']}:{parsed['line']}")

    # --- Enrich with IR context ---
    message = enrich_message(parsed["message"], args.ll, args.function)
    if args.ll and args.function:
        print(f"  IR context: enriched from {Path(args.ll).name}:{args.function}")

    # --- Build finding ---
    finding = {
        "rule_id":   parsed["rule_id"],
        "severity":  args.severity,
        "file_path": parsed["file_path"],
        "line":      parsed["line"],
        "column":    0,
        "message":   message,
    }

    # --- Write output ---
    repo_dir = Path(args.repo)
    out_path = Path(args.output) if args.output else repo_dir / ".scar" / "findings-llvm-ir.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    existing = _load_existing(out_path)
    if args.replace and args.file:
        target_file = str(Path(args.file).resolve())
        existing = [f for f in existing if str(Path(f["file_path"]).resolve()) != target_file]
    merged   = _dedup(existing + [finding])
    out_path.write_text(json.dumps(merged, indent=2))

    print(f"  Written   : {out_path} ({len(merged)} finding(s) total)")
    print(f"\nRun the repair loop with:")
    print(f"  cd {repo_dir} && scar /dev/null {repo_dir} --triage-rounds 3")


if __name__ == "__main__":
    main()
