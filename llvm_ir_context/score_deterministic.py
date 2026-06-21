#!/usr/bin/env python3
"""
score_deterministic.py — Philosophy 2 deterministic ranker + MAX ensemble.

Scores each function using only the structural facts computed by
preprocess_slice_pdg.py + slice_context.py — no trained model, no weights.

Philosophy 2 rule:
  "Does a parameter reach a dangerous sink without a guard?"

Score formula:
  base: n_sinks > 0 AND no guard            → 1.00  (unguarded sink)
        n_sinks > 0 AND null_check only      → 0.75  (weak guard)
        n_sinks > 0 AND bounds_check present → 0.40  (guarded)
        no slice / no sinks                  → 0.05

Multipliers:
  is_external_input   × 1.10
  has_trunc           × 1.05
Score capped at 1.0.

MAX ensemble (--gnn-checkpoint):
  Loads a trained GNN checkpoint and scores each function with it too.
  Final score = max(rule_score, gnn_score).
  Prints rule-only, GNN-only, and MAX ranked tables side by side in summary.

Usage:
    python score_deterministic.py --scarnet --answer-key scarnet-answer-key.txt
    python score_deterministic.py --ir-dir /tmp/ir/
    python score_deterministic.py --ir-dir /tmp/ir/ --no-gep-only
    python score_deterministic.py --scarnet --answer-key ... \\
        --gnn-checkpoint model_slice_pdg_v8.pt
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg
from llvm_ir_context.slice_context        import summarize_slice

_SCARNET_REPO = "https://github.com/johwes/scarnet.git"


# ---------------------------------------------------------------------------
# Scoring rule
# ---------------------------------------------------------------------------

# Sink types that are IR instructions rather than function calls.
# GEP / alloca unguarded in an internal helper often means the guard was
# done by the caller (intra-procedural blind spot) — score them lower.
_GEP_SINKS = frozenset({"getelementptr", "alloca"})
_DIV_SINKS = frozenset({"sdiv", "udiv", "srem", "urem"})

# Raw buffer-copy sinks: no built-in size limit, or size is not enforced by the function name.
# Presence → ×1.20 boost (more dangerous than allocation or format sinks).
_BUFFER_WRITE_SINKS = frozenset({
    "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "memmove", "bcopy",
    "gets", "fgets",
    "sprintf", "vsprintf",   # unbounded format writes
})

# Format/logging sinks: output-only, or have an explicit size parameter (snprintf).
# When ALL call sinks are in this set AND a guard is present → ×0.70 penalty.
# Rationale: snprintf(buf, size, ...) with a null_check guard is far less likely to
# overflow than memcpy(buf, src, n) with the same guard.
_FORMAT_ONLY_SINKS = frozenset({
    "printf", "fprintf", "snprintf", "vsnprintf",
    "syslog", "err", "warn",
})

# Pure allocation sinks: the bug is "null return not checked" (OOM / null-deref),
# not buffer overflow. When ALL call sinks are allocators, apply ×0.70 penalty —
# these matter but rank below overflow/UAF vulnerabilities.
_ALLOC_ONLY_SINKS = frozenset({
    "malloc", "calloc", "realloc", "xmalloc", "xrealloc",
})


def philosophy2_score(summary: dict) -> float:  # noqa: C901
    """Pure structural Philosophy 2 score from a slice_context summary.

    Tier system (descending priority):
      1.00  trunc + call sink + no guard  — integer narrowing into unguarded call
      0.90  call sink + no guard + function_argument input  — direct arg to unguarded call
      0.75  call sink + null_check only  — null guard doesn't protect buffer writes
      0.70  call sink + no guard, struct/return source  — upstream validation possible
      0.55  GEP only + no guard  — likely struct field pattern, not a buffer call
      0.40–0.70  call sink + bounds_check  — guard density logic
      0.18–0.40  GEP only + guarded  — well-covered array access
      0.05  no sink
    """
    n_sinks    = summary["n_sinks"]
    has_guard  = summary["has_guard"]
    guard_type = summary.get("guard_type", "none")
    is_ext     = summary.get("is_external_input", False)
    has_trunc  = summary.get("has_trunc", False)
    sinks      = summary.get("sinks", [])
    channels   = summary.get("input_channels", [])

    has_call_sink    = any(s.get("fn") not in _GEP_SINKS and s.get("fn") not in _DIV_SINKS
                          for s in sinks)
    has_div_sink     = any(s.get("fn") in _DIV_SINKS for s in sinks)
    has_arg_input    = "function_argument" in channels
    caller_validated = summary.get("caller_validated", False)

    # For div/rem sinks a null_check (icmp ne ... 0) IS the correct guard.
    # Separate early: unguarded div is dangerous, guarded div is fine.
    if has_div_sink and not has_call_sink:
        # Only div sinks — guard adequacy differs from buffer sinks.
        if n_sinks == 0:
            return 0.05
        if not has_guard:
            # Unguarded divisor — divide-by-zero likely.
            base = 0.85 if has_arg_input else 0.70
        else:
            # Any icmp (including ne) is sufficient for div guard.
            base = 0.15
        mult = 1.10 if is_ext else 1.0
        return min(base * mult, 1.0)

    if n_sinks == 0:
        base = 0.05

    elif has_trunc and has_call_sink:
        # Integer narrowing before a call-based size sink — suspicious regardless of guards.
        # Guards elsewhere in the slice may protect pointer validity, not the truncated size.
        base = 1.00 if not has_guard else 0.88

    elif not has_guard:
        if has_call_sink and has_arg_input:
            base = 0.90   # direct function argument to unguarded call sink
        elif has_call_sink:
            base = 0.70   # unguarded call sink, struct/return source — upstream validation possible
        else:
            base = 0.55   # GEP-only unguarded — likely struct field access pattern

    elif guard_type == "null_check":
        if has_call_sink:
            base = 0.75   # null check doesn't protect buffer writes
        else:
            base = 0.30   # null-check + GEP — standard pointer guard, not a buffer sink

    else:
        # bounds_check or mixed
        gd = summary.get("guard_density", 1.0)
        if gd == float("inf"):
            base = 1.00
        elif has_call_sink:
            # Use call-sink-only density: GEP sinks inflate total count and make call sinks
            # look sparse even when the guards actually cover the memcpy/memset paths.
            # Example: deflateCopy has 67 GEP + 8 call sinks / 9 guards → total gd=8.3,
            # but call gd=0.89 (well-covered). We want 0.40, not 0.70.
            gc = summary.get("guard_count", 1) or 1
            n_call_sinks = sum(1 for s in sinks
                               if s.get("fn") not in _GEP_SINKS
                               and s.get("fn") not in _DIV_SINKS)
            call_gd = n_call_sinks / gc
            if call_gd >= 5:   base = 0.70
            elif call_gd >= 2: base = 0.55
            else:              base = 0.40
        else:
            # GEP with bounds check — higher gd means many accesses per guard (off-by-one risk)
            if gd >= 5:   base = 0.62   # sparse: 1 guard for 5+ GEP sinks — guard may miss some
            elif gd >= 2: base = 0.28
            else:         base = 0.18

    # Identify call sink types for multiplier logic
    call_sink_fns = {s.get("fn") for s in sinks
                     if s.get("fn") not in _GEP_SINKS and s.get("fn") not in _DIV_SINKS}
    has_buffer_write  = bool(call_sink_fns & _BUFFER_WRITE_SINKS)
    all_format_sinks  = bool(call_sink_fns) and call_sink_fns <= _FORMAT_ONLY_SINKS
    all_alloc_sinks   = bool(call_sink_fns) and call_sink_fns <= _ALLOC_ONLY_SINKS

    has_free_sink = any(s.get("fn") == "free" for s in sinks
                        if s.get("fn") not in _GEP_SINKS and s.get("fn") not in _DIV_SINKS)

    trunc_drove_base      = has_trunc and has_call_sink
    null_check_drove_base = (not has_trunc) and has_call_sink and guard_type == "null_check"

    mult = 1.0
    if is_ext:
        mult *= 1.10
    if has_buffer_write and not trunc_drove_base and not null_check_drove_base:
        # Skip when trunc or null_check drove the tier — those bases already encode the
        # risk level. Stacking ×1.50 pushes well-known patterns (guarded memcpy, null-only
        # inflateGetDictionary) to 1.00 and destroys differentiation at the top.
        mult *= 1.50   # raw copy with no built-in size limit — categorically most dangerous
    elif all_format_sinks and has_guard:
        mult *= 0.70   # snprintf/printf with guard — size param is the guard
    elif all_alloc_sinks:
        mult *= 0.70   # null-return / OOM bug, not overflow — lower severity
    if has_free_sink and not has_buffer_write:
        mult *= 1.05   # free() call without a raw copy — UAF/double-free risk signal

    # caller_validated is surfaced as +caller? in the details column for human review.
    # caller_validated is surfaced as +caller? in the details column for human review.
    # We do NOT apply an automatic score reduction: "caller has icmp" is too broad a
    # signal — routing guards, null pointer checks, and loop bounds all satisfy it
    # independently of whether they protect the data flow into this function's sinks.

    score = min(base * mult, 1.0)

    # Double-free / use-after-free override: these are detected intra-procedurally
    # independent of the slice — if present, escalate to at least 0.88.
    if summary.get("double_free"):
        score = max(score, 0.92)
    elif summary.get("use_after_free"):
        score = max(score, 0.88)

    return score


# ---------------------------------------------------------------------------
# IR utilities
# ---------------------------------------------------------------------------

def _collect_functions(ir_path: Path) -> list[tuple[str, str, Path]]:
    """Return (fn_name, full_module_ir, source_file) triples from all .ll files.

    Passes the full module IR (not a per-function split) to the slicer so that
    all declare stubs and globals remain visible — exactly how slice_context.py
    operates. Falls back to a regex split if llvmlite can't parse the file.
    """
    import llvmlite.binding as llvm
    files = [ir_path] if ir_path.is_file() else sorted(ir_path.glob("**/*.ll"))
    out   = []
    for f in files:
        ir_text = f.read_text(errors="replace")
        try:
            mod = llvm.parse_assembly(ir_text)
            for fn in mod.functions:
                if not fn.is_declaration:
                    out.append((fn.name, ir_text, f))
        except Exception:
            # Fallback: regex split (loses cross-function declares, but better than nothing)
            header_lines = []
            for line in ir_text.splitlines():
                if line.startswith("define"):
                    break
                header_lines.append(line)
            header = "\n".join(header_lines)
            for seg in re.split(r'(?=^define\b)', ir_text, flags=re.MULTILINE):
                seg = seg.strip()
                if not seg.startswith("define"):
                    continue
                m = re.match(r'define\s+.*?@([\w.]+)\s*\(', seg)
                if m:
                    out.append((m.group(1), header + "\n\n" + seg + "\n", f))
    return out


def _load_answer_key(path: Path) -> set[str]:
    return {l.strip() for l in path.read_text().splitlines()
            if l.strip() and not l.startswith("#")}


_SCARNET_SRCS = [
    "src/parse.c",
    "src/handler.c",
    "src/util.c",
    "src/session.c",
    "main.c",
]


def _setup_scarnet_ir(keep_ir: Path | None) -> tuple[Path, Path | None]:
    tmpdir    = Path(tempfile.mkdtemp(prefix="scarnet-det-"))
    clone_dir = tmpdir / "scarnet"
    print(f"Cloning {_SCARNET_REPO} ...")
    subprocess.run(["git", "clone", "--quiet", "--depth=1", _SCARNET_REPO, str(clone_dir)],
                   check=True)
    ir_out = keep_ir if keep_ir else tmpdir / "ir"
    ir_out.mkdir(parents=True, exist_ok=True)
    print(f"Compiling {len(_SCARNET_SRCS)} C file(s) to LLVM IR ...")
    compiled = 0
    for rel in _SCARNET_SRCS:
        cf     = clone_dir / rel
        base   = rel.replace("/", "_").removesuffix(".c")
        out_ll = ir_out / f"{base}.ll"
        result = subprocess.run(
            ["clang-20", "-O0", "-fno-inline", "-S", "-emit-llvm",
             "-I", str(clone_dir / "include"),
             "-w", str(cf), "-o", str(out_ll)],
            capture_output=True)
        if result.returncode == 0:
            compiled += 1
        else:
            print(f"  WARN: {rel} failed to compile")
            if result.stderr:
                print(f"    {result.stderr.decode(errors='replace').strip()[:200]}")
    print(f"  {compiled}/{len(_SCARNET_SRCS)} compiled → {ir_out}")
    return ir_out, (None if keep_ir else tmpdir)


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------

def _p_at_k(ranked: list[tuple[str, float]], answer_key: set[str], k: int):
    top  = {fn for fn, _ in ranked[:k]}
    hits = top & answer_key
    prec = len(hits) / k if k else 0.0
    rec  = len(hits) / len(answer_key) if answer_key else 0.0
    return hits, prec, rec


def _print_table(label: str, ranked: list[tuple[str, float]],
                 answer_key: set[str], top_k: int,
                 details: dict[str, str] | None = None):
    print(f"\n=== {label} ===")
    print(f"  {'Rank':>4}  {'Function':<44} {'Score':>6}  {'Vuln?':<5}"
          + ("  Details" if details else ""))
    print(f"  {'----':>4}  {'-'*44} {'------':>6}  {'-----':<5}")
    boundary = False
    for i, (fn, score) in enumerate(ranked, 1):
        if i == top_k + 1 and not boundary:
            print(f"  {'----':>4}  {'-'*44} {'------':>6}  (below top-{top_k})")
            boundary = True
        vuln = ("YES" if fn in answer_key else "no") if answer_key else ""
        det  = f"  {details[fn]}" if details and fn in details else ""
        print(f"  {i:>4}  {fn:<44} {score:>5.1%}  {vuln:<5}{det}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--scarnet",  action="store_true",
                     help="Clone johwes/scarnet and compile to IR")
    src.add_argument("--ir-dir",   type=str,
                     help="Directory of pre-compiled .ll files")
    ap.add_argument("--keep-ir",    type=str, default=None)
    ap.add_argument("--answer-key", type=str, default=None,
                    help="Known-vulnerable function names, one per line (optional)")
    ap.add_argument("--top-k",      type=int, default=None)
    ap.add_argument("--no-gep-only", action="store_true",
                    help="Suppress functions whose only sinks are getelementptr (GEP). "
                         "Reduces false positives in codebases with heavily-indexed "
                         "data structures (e.g. compression libraries).")
    ap.add_argument("--verbose",    action="store_true")
    args = ap.parse_args()

    # --- setup IR ---
    tmpdir = None
    if args.scarnet:
        for tool in ("git", "clang-20"):
            if not shutil.which(tool):
                print(f"ERROR: {tool} not found"); sys.exit(1)
        keep = Path(args.keep_ir) if args.keep_ir else None
        ir_path, tmpdir = _setup_scarnet_ir(keep)
    else:
        ir_path = Path(args.ir_dir)

    functions  = _collect_functions(ir_path)
    answer_key = _load_answer_key(Path(args.answer_key)) if args.answer_key else set()
    top_k      = args.top_k or (len(answer_key) if answer_key else len(functions))
    print(f"Functions found: {len(functions)}")
    if answer_key:
        print(f"Answer key: {len(answer_key)} known-vulnerable  (top-K = {top_k})")
    else:
        print(f"No answer key — showing all {len(functions)} functions ranked")

    # --- parse all modules once for cross-file caller scanning ---
    import llvmlite.binding as _llvm
    all_modules = []
    seen_ir: set[int] = set()
    for _, fn_ir, _ in functions:
        ir_id = id(fn_ir)
        if ir_id not in seen_ir:
            seen_ir.add(ir_id)
            try:
                all_modules.append(_llvm.parse_assembly(fn_ir))
            except Exception:
                pass

    # --- score each function ---
    rule_scores: dict[str, float] = {}
    details:     dict[str, str]   = {}
    summaries:   dict[str, dict]  = {}
    fn_files:    dict[str, Path]  = {}
    no_slice_rule = []

    for fn_name, fn_ir, fn_file in functions:
        fn_files[fn_name] = fn_file
        g = ir_to_graph_slice_pdg(fn_ir, fn_name=fn_name, extra_modules=all_modules)
        if g is None or g.get("x") is None:
            rule_scores[fn_name] = 0.05
            details[fn_name]     = f"no slice ({fn_file.name})"
            no_slice_rule.append(fn_name)
        else:
            summary              = summarize_slice(g, fn_name=fn_name)
            summaries[fn_name]   = summary
            rule_scores[fn_name] = philosophy2_score(summary)
            ns    = summary["n_sinks"]
            hg    = summary["has_guard"]
            gt    = summary.get("guard_type", "none")
            ext   = "ext" if summary.get("is_external_input") else ""
            trunc = "+trunc" if summary.get("has_trunc") else ""
            df    = "+df"      if summary.get("double_free")    else ""
            uaf   = "+uaf"     if summary.get("use_after_free") else ""
            cv    = "+caller?" if summary.get("caller_validated") else ""
            sinks = ",".join(sorted({s.get("fn","?") for s in summary["sinks"]}))
            details[fn_name] = (
                f"sinks={ns} guard={'yes('+gt+')' if hg else 'NO'} "
                f"{ext}{trunc}{df}{uaf}{cv} [{sinks}] ({fn_file.name})"
            )
            if args.verbose:
                print(f"  {fn_name}: {summary['natural_language']}")

    # --- --no-gep-only filter ---
    # Drop functions whose only sinks are GEP (array index) instructions.
    # These are false positives in codebases with heavily-indexed data structures
    # where every table access becomes a GEP "sink" — the signal is too coarse.
    if args.no_gep_only:
        gep_only_fns = set()
        for fn_name, summary in summaries.items():
            sink_types = {s.get("fn") for s in summary["sinks"]}
            # Only suppress when GEP is the only sink type AND there are no bounds checks.
            # GEP-only + bounds_check means real array indexing with guard logic (parsing,
            # protocol code) — suppressing that would hide genuine vulnerabilities.
            # GEP-only + no guard / null_check = table lookup pattern → safe to suppress.
            has_bounds = summary.get("bounds_check_count", 0) > 0
            if sink_types and sink_types <= {"getelementptr"} and not has_bounds:
                gep_only_fns.add(fn_name)
        if gep_only_fns:
            print(f"--no-gep-only: suppressing {len(gep_only_fns)} GEP-only function(s): "
                  + ", ".join(sorted(gep_only_fns)))
            for fn_name in gep_only_fns:
                rule_scores[fn_name] = 0.05
                details[fn_name]    += "  [gep-only suppressed]"

    # --- build ranked list and print ---
    rule_ranked = sorted(rule_scores.items(),
                         key=lambda x: (x[1], summaries.get(x[0], {}).get("n_sinks", 0)),
                         reverse=True)
    _print_table("Philosophy 2 rule", rule_ranked, answer_key, top_k, details)

    # --- summary ---
    print(f"\n{'='*65}")
    if answer_key:
        print(f"  {'Method':<30} {'Hits':>6}  {'P@K':>6}  {'R@K':>6}")
        print(f"  {'-'*30} {'------':>6}  {'------':>6}  {'------':>6}")
        h, p, r = _p_at_k(rule_ranked, answer_key, top_k)
        print(f"  {'Philosophy 2 rule':<30} {len(h):>3}/{len(answer_key):<2}  {p:>6.1%}  {r:>6.1%}")
        print(f"{'='*65}")
        print(f"\n  No-slice: {', '.join(no_slice_rule) or 'none'}")
        rule_misses = sorted(answer_key - {fn for fn, _ in rule_ranked[:top_k]})
        print(f"  Misses:   {rule_misses}")
    else:
        print(f"  No-slice: {', '.join(no_slice_rule) or 'none'}")
        print(f"{'='*65}")

    if tmpdir and tmpdir.exists():
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
