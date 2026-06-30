#!/usr/bin/env python3
"""
score_deterministic.py — Philosophy 2 deterministic ranker + MAX ensemble.

Scores each function using only the structural facts computed by
preprocess_slice_pdg.py + slice_context.py — no trained model, no weights.

Philosophy 2 rule:
  "Does a parameter reach a dangerous sink without a bounds-checking guard?"

Base tier (descending priority):
  1.00  trunc + call sink + no guard       — integer narrowing into unguarded call
  0.88  trunc + call sink + guards         — truncation still suspicious despite guards
  0.90  call sink + no guard + fn_arg      — direct argument to unguarded call
  0.70  call sink + no guard, other source — upstream validation possible
  0.75  call sink + null_check only        — null guard doesn't protect buffer writes
  0.55  GEP-only or free-only unguarded    — not a buffer overflow signal
  0.40–0.70  call sink + bounds_check      — guard density logic (sinks/guard ratio)
  0.18–0.62  GEP-only + guarded           — well-covered array access
  0.05  no sink

  free() is excluded from "substantive call sink" for base-tier selection.
  free(NULL) is valid C — bare deallocation wrappers are not a buffer overflow
  signal. UAF/double-free risk is detected by typestate and handled via floors.

Multipliers (applied after base, only when base didn't already encode the risk):
  buffer-write sinks × 1.50 — skipped when trunc or null_check drove the base
  is_external_input  × 1.10
  free() call site   × 1.05 — UAF signal; skipped when free is the only call sink
  format-only + guard × 0.70
  allocation-only     × 0.70
  double-free floor   → 0.92
  UAF floor           → 0.88

Guard density for the bounds_check/mixed tier uses non-free call-sink count so
GEP noise doesn't make guarded memcpy functions appear sparse.

Usage:
    ir-score --scarnet --answer-key scarnet-answer-key.txt
    ir-score --ir-dir /tmp/ir/
    ir-score --ir-dir /tmp/ir/ --no-gep-only
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
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

# Command injection sinks: user-controlled string reaches shell/exec.
# Scored like unguarded call sinks — no buffer-write multiplier since there
# is no size argument, but the vulnerability class is high severity.
_COMMAND_INJECTION_SINKS = frozenset({
    "system", "popen",
    "execv", "execvp", "execve", "execle", "execl", "execlp",
    "posix_spawn",
})

# Path traversal sinks: user-controlled string reaches filesystem call.
_PATH_TRAVERSAL_SINKS = frozenset({
    "open", "openat", "creat",
    "fopen", "fopen64", "freopen",
    "unlink", "unlinkat", "remove",
    "rename", "renameat",
    "rmdir", "mkdir", "mkdirat",
    "chmod", "chown", "lchown",
    "symlink", "symlinkat", "link", "linkat",
    "stat", "lstat", "access", "faccessat",
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
    # Substantive call sink: excludes free() for base-tier purposes.
    # free(ptr) with a function arg and no null check isn't a ranking signal —
    # free(NULL) is valid C, and the real free() risks (UAF, double-free) are
    # caught by typestate analysis. Counting free as a "call sink" pushes bare
    # deallocation wrappers (zcfree, xfree) to the top of the ranking incorrectly.
    has_substantive_call_sink = any(
        s.get("fn") not in _GEP_SINKS
        and s.get("fn") not in _DIV_SINKS
        and s.get("fn") != "free"
        for s in sinks
    )
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
        if has_substantive_call_sink and has_arg_input:
            base = 0.90   # direct function argument to unguarded call sink
        elif has_substantive_call_sink:
            base = 0.70   # unguarded call sink, struct/return source — upstream validation possible
        else:
            base = 0.55   # GEP-only or free-only unguarded — not a buffer overflow signal

    elif guard_type == "null_check":
        if has_substantive_call_sink:
            base = 0.75   # null check doesn't protect buffer writes
        else:
            base = 0.30   # null-check + GEP/free — standard pointer guard, not a buffer sink

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
            # Exclude free() from the count: a null-check before free(ptr) only prevents
            # null-deref, not UAF/double-free. If the only call sinks are free, fall back
            # to total density so the overall sink-to-guard ratio still informs the base.
            gc = summary.get("guard_count", 1) or 1
            n_call_sinks_nonfree = sum(1 for s in sinks
                                       if s.get("fn") not in _GEP_SINKS
                                       and s.get("fn") not in _DIV_SINKS
                                       and s.get("fn") != "free")
            effective_gd = (n_call_sinks_nonfree / gc) if n_call_sinks_nonfree > 0 else gd
            if effective_gd >= 5:   base = 0.70
            elif effective_gd >= 2: base = 0.55
            else:                   base = 0.40
        else:
            # GEP with bounds check — higher gd means many accesses per guard (off-by-one risk)
            if gd >= 5:   base = 0.62   # sparse: 1 guard for 5+ GEP sinks — guard may miss some
            elif gd >= 2: base = 0.28
            else:         base = 0.18

    # Identify call sink types for multiplier logic
    call_sink_fns = {s.get("fn") for s in sinks
                     if s.get("fn") not in _GEP_SINKS and s.get("fn") not in _DIV_SINKS}
    has_buffer_write      = bool(call_sink_fns & _BUFFER_WRITE_SINKS)
    has_cmd_injection     = bool(call_sink_fns & _COMMAND_INJECTION_SINKS)
    has_path_traversal    = bool(call_sink_fns & _PATH_TRAVERSAL_SINKS)
    all_format_sinks      = bool(call_sink_fns) and call_sink_fns <= _FORMAT_ONLY_SINKS
    all_alloc_sinks       = bool(call_sink_fns) and call_sink_fns <= _ALLOC_ONLY_SINKS

    has_free_sink = any(s.get("fn") == "free" for s in sinks
                        if s.get("fn") not in _GEP_SINKS and s.get("fn") not in _DIV_SINKS)

    trunc_drove_base      = has_trunc and has_call_sink
    null_check_drove_base = (not has_trunc) and has_call_sink and guard_type == "null_check"
    safe_mul_via_zext     = summary.get("has_safe_mul_via_zext", False)

    mult = 1.0
    if is_ext:
        mult *= 1.10
    if has_buffer_write and not trunc_drove_base and not null_check_drove_base:
        # Skip when trunc or null_check drove the tier — those bases already encode the
        # risk level. Stacking ×1.50 pushes well-known patterns (guarded memcpy, null-only
        # inflateGetDictionary) to 1.00 and destroys differentiation at the top.
        mult *= 1.50   # raw copy with no built-in size limit — categorically most dangerous
    elif has_cmd_injection and not trunc_drove_base:
        mult *= 1.30   # shell/exec with user-controlled arg — high severity
    elif has_path_traversal and not trunc_drove_base:
        mult *= 1.20   # filesystem call with user-controlled path
    elif all_format_sinks and has_guard:
        mult *= 0.70   # snprintf/printf with guard — size param is the guard
    elif all_alloc_sinks:
        mult *= 0.70   # null-return / OOM bug, not overflow — lower severity

    if safe_mul_via_zext:
        mult *= 0.60   # zext i32→i64 before multiply: overflow unreachable on 64-bit target
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
            ["clang-20", "-O0", "-Xclang", "-disable-O0-optnone",
             "-fno-inline", "-S", "-emit-llvm",
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
                 details: dict[str, str] | None = None,
                 wrapper_of: dict[str, str] | None = None):
    # Group wrappers: impl_fn → [wrapper_fn, ...]
    wrappers_for: dict[str, list[str]] = {}
    if wrapper_of:
        for w, impl in wrapper_of.items():
            wrappers_for.setdefault(impl, []).append(w)

    print(f"\n=== {label} ===")
    print(f"  {'Rank':>4}  {'Function':<44} {'Score':>6}  {'Vuln?':<5}"
          + ("  Details" if details else ""))
    print(f"  {'----':>4}  {'-'*44} {'------':>6}  {'-----':<5}")
    boundary = False
    rank = 0
    for fn, score in ranked:
        if wrapper_of and fn in wrapper_of:
            continue   # printed beneath its implementation
        rank += 1
        if rank == top_k + 1 and not boundary:
            print(f"  {'----':>4}  {'-'*44} {'------':>6}  (below top-{top_k})")
            boundary = True
        vuln = ("YES" if fn in answer_key else "no") if answer_key else ""
        det  = f"  {details[fn]}" if details and fn in details else ""
        print(f"  {rank:>4}  {fn:<44} {score:>5.1%}  {vuln:<5}{det}")
        for w in sorted(wrappers_for.get(fn, [])):
            w_vuln = ("YES" if w in answer_key else "no") if answer_key else ""
            print(f"  {'':>4}    └─ {w:<42} {score:>5.1%}  {w_vuln}")


# ---------------------------------------------------------------------------
# Per-function worker (runs in a subprocess — no llvmlite objects passed)
# ---------------------------------------------------------------------------

def _score_one(args):
    """Score a single function. Designed to run in a worker process.

    Accepts a tuple so it works with ProcessPoolExecutor.map.
    Returns (fn_name, summary_or_None, score, details_str, file_name).
    """
    fn_name, ir_text, file_name = args
    try:
        from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg
        from llvm_ir_context.slice_context import summarize_slice

        g = ir_to_graph_slice_pdg(ir_text, fn_name=fn_name)
        if g is None or g.get("x") is None:
            return (fn_name, None, 0.05, f"no slice ({file_name})", file_name)

        summary = summarize_slice(g, fn_name=fn_name)
        score   = philosophy2_score(summary)

        ns    = summary["n_sinks"]
        hg    = summary["has_guard"]
        gt    = summary.get("guard_type", "none")
        ext   = "ext"     if summary.get("is_external_input")   else ""
        trunc = "+trunc"  if summary.get("has_trunc")           else ""
        szext = "+zext64" if summary.get("has_safe_mul_via_zext") else ""
        df    = "+df"     if summary.get("double_free")         else ""
        uaf   = "+uaf"    if summary.get("use_after_free")      else ""
        cv    = "+caller?" if summary.get("caller_validated")   else ""
        sinks = ",".join(sorted({s.get("fn", "?") for s in summary["sinks"]}))
        detail = (
            f"sinks={ns} guard={'yes('+gt+')' if hg else 'NO'} "
            f"{ext}{trunc}{szext}{df}{uaf}{cv} [{sinks}] ({file_name})"
        )
        return (fn_name, summary, score, detail, file_name)
    except Exception as exc:
        return (fn_name, None, 0.05, f"error: {exc} ({file_name})", file_name)


# ---------------------------------------------------------------------------
# Core scoring engine (programmatic, no I/O)
# ---------------------------------------------------------------------------

def score_ir_dir(
    ir_path: Path,
    *,
    no_gep_only: bool = False,
    answer_key: set[str] | None = None,
    verbose: bool = False,
) -> dict:
    """Score all functions in ir_path and return structured results.

    Returns dict with keys:
      ranked       — list of (fn_name, score) sorted descending
      summaries    — {fn_name: slice_summary_dict}
      details      — {fn_name: detail_str}
      fn_files     — {fn_name: Path}
      caller_map   — {callee: [caller, ...]} cross-file call graph
      no_slice     — list of fn_names with no extractable slice
    """
    functions  = _collect_functions(ir_path)

    rule_scores:  dict[str, float] = {}
    details:      dict[str, str]   = {}
    summaries:    dict[str, dict]  = {}
    fn_files:     dict[str, Path]  = {}
    no_slice_fns: list[str]        = []

    total   = len(functions)
    workers = max(1, min(os.cpu_count() or 1, total))
    work    = [(fn_name, fn_ir, fn_file.name) for fn_name, fn_ir, fn_file in functions]
    fn_file_map = {fn_name: fn_file for fn_name, _, fn_file in functions}

    done = 0
    print(f"\r  Scoring {done}/{total} functions...", end="", flush=True)

    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_score_one, item): item[0] for item in work}
        for fut in as_completed(futures):
            fn_name, summary, score, detail, file_name = fut.result()
            fn_files[fn_name]    = fn_file_map[fn_name]
            rule_scores[fn_name] = score
            details[fn_name]     = detail
            if summary is not None:
                summaries[fn_name] = summary
                if verbose:
                    print(f"\n  {fn_name}: {summary['natural_language']}", flush=True)
            else:
                no_slice_fns.append(fn_name)
            done += 1
            if done % 50 == 0 or done == total:
                print(f"\r  Scoring {done}/{total} functions...", end="", flush=True)

    print()  # end progress line
    # Build caller_map: callee → [callers] from summaries (intra-module edges).
    caller_map: dict[str, list[str]] = {}
    for fn_name, summary in summaries.items():
        for caller in summary.get("caller_names", []):
            caller_map.setdefault(fn_name, [])
            if caller not in caller_map[fn_name]:
                caller_map[fn_name].append(caller)

    # Cross-file call edges via regex scan of all IR texts.
    # Workers only parsed their own module so caller_names misses cross-file
    # callers. A single regex pass over all IR is fast and sufficient for the
    # wrapper dedup and reachability queries.
    _call_re = re.compile(r'\bcall\b[^@\n]*@([\w.]+)\s*\(')
    _define_re = re.compile(r'^define\b[^\n]*@([\w.]+)\s*\(', re.MULTILINE)
    seen_ir_ids: set[int] = set()
    all_known_fns = set(rule_scores)
    for _, ir_text, _ in functions:
        ir_id = id(ir_text)
        if ir_id in seen_ir_ids:
            continue
        seen_ir_ids.add(ir_id)
        defined_in_module = set(_define_re.findall(ir_text))
        for caller_fn in defined_in_module:
            if caller_fn not in all_known_fns:
                continue
            # Find all callees referenced inside this function's body.
            # Slice out just this function's body to avoid false edges from
            # other functions in the same module.
            fn_match = re.search(
                rf'^define\b[^\n]*@{re.escape(caller_fn)}\s*\(',
                ir_text, re.MULTILINE,
            )
            if not fn_match:
                continue
            start = fn_match.start()
            # Find the closing brace of this function (first lone '}' at col 0)
            end = len(ir_text)
            for m in re.finditer(r'^\}', ir_text[start:], re.MULTILINE):
                end = start + m.end()
                break
            fn_body = ir_text[start:end]
            for callee_fn in _call_re.findall(fn_body):
                if callee_fn == caller_fn:
                    continue
                if callee_fn not in all_known_fns:
                    continue
                if caller_fn not in caller_map.get(callee_fn, []):
                    caller_map.setdefault(callee_fn, []).append(caller_fn)

    # Interprocedural score propagation -- categorical signal-based floors.
    # Priority: double_free (0.92) > use_after_free (0.88) >
    #           unguarded call sink + function_argument (0.70) >
    #           fractional fallback (callee_score x 0.75, threshold 0.50).
    def _propagation_floor(summary: dict, callee_score: float):
        if summary.get("double_free"):
            return 0.92, "df->0.92"
        if summary.get("use_after_free"):
            return 0.88, "uaf->0.88"
        sinks    = summary.get("sinks", [])
        channels = summary.get("input_channels", [])
        has_call_sink = any(s.get("type") == "dangerous_call" for s in sinks)
        if (has_call_sink and "function_argument" in channels
                and summary.get("guard_type", "none") == "none"):
            return 0.70, "call->0.70"
        if callee_score >= 0.50:
            return callee_score * 0.75, f"{callee_score * 0.75:.0%}"
        return None

    propagated_into: dict[str, list] = {}
    for fn_name, summary in summaries.items():
        callee_score = rule_scores.get(fn_name, 0.0)
        prop = _propagation_floor(summary, callee_score)
        if prop is None:
            continue
        floor, label = prop
        for caller in set(summary.get("caller_names", [])):
            if caller not in rule_scores:
                continue
            propagated_into.setdefault(caller, []).append((floor, label, fn_name))
    for caller, sources in propagated_into.items():
        best_floor, best_label, _ = max(sources, key=lambda x: x[0])
        if best_floor > rule_scores[caller]:
            rule_scores[caller] = best_floor
        src_str = "+".join(f"{fn}({lbl})" for _, lbl, fn in
                           sorted(sources, key=lambda x: -x[0]))
        details[caller] = details.get(caller, "") + f"  [+prop:{src_str}]"

    # GEP-only filter.
    if no_gep_only:
        gep_only_fns = set()
        for fn_name, summary in summaries.items():
            sink_types = {s.get("fn") for s in summary["sinks"]}
            has_bounds = summary.get("bounds_check_count", 0) > 0
            if sink_types and sink_types <= {"getelementptr"} and not has_bounds:
                gep_only_fns.add(fn_name)
        for fn_name in gep_only_fns:
            rule_scores[fn_name] = 0.05
            details[fn_name]    += "  [gep-only suppressed]"

    ranked = sorted(rule_scores.items(),
                    key=lambda x: (x[1], summaries.get(x[0], {}).get("n_sinks", 0)),
                    reverse=True)

    # Wrapper deduplication: identify thin wrappers whose only contribution is
    # delegating to a higher-ranked function already in the output.
    #
    # A function W is a wrapper of implementation I when:
    #   1. W is reachable from I via the call graph (caller_map edges)
    #   2. I ranks higher than W
    #   3. W's own sink set is a non-empty subset of I's sink set
    #
    # The BFS from each impl traverses through no-sink intermediaries (adapter
    # layers, type-specific shims) to reach the true public API wrappers.
    # Max hop limit prevents runaway traversal of deep call graphs.
    _MAX_WRAPPER_HOPS = 6
    rank_position = {fn: i for i, (fn, _) in enumerate(ranked)}

    def _sink_fns(fn: str) -> frozenset:
        return frozenset(
            s.get("fn", "") for s in summaries.get(fn, {}).get("sinks", [])
            if s.get("fn") not in ("getelementptr", "alloca")
        )

    wrapper_of: dict[str, str] = {}   # wrapper_fn → impl_fn (root)

    for impl_fn, callers in caller_map.items():
        if impl_fn not in rank_position:
            continue
        impl_sinks = _sink_fns(impl_fn)
        if not impl_sinks:
            continue
        impl_rank = rank_position[impl_fn]

        # BFS upward through callers, hopping through no-sink intermediaries.
        from collections import deque
        queue: deque[tuple[str, int]] = deque()
        visited: set[str] = {impl_fn}
        for c in callers:
            queue.append((c, 1))
            visited.add(c)

        while queue:
            node, depth = queue.popleft()
            if node not in rank_position or rank_position[node] <= impl_rank:
                continue
            node_sinks = _sink_fns(node)
            if node_sinks:
                if node_sinks <= impl_sinks:
                    # Subset of impl's sinks: this is a wrapper layer.
                    # Mark it and continue propagating upward through it —
                    # its callers may be further API wrappers in the same chain.
                    if node not in wrapper_of:
                        wrapper_of[node] = impl_fn
                        details[node] += f"  [wrapper of {impl_fn}]"
                    if depth < _MAX_WRAPPER_HOPS:
                        for c in caller_map.get(node, []):
                            if c not in visited:
                                visited.add(c)
                                queue.append((c, depth + 1))
                # Sinks not ⊆ impl's: unrelated function, stop here
                continue
            # No own sinks: pass-through adapter — traverse further if within hop limit
            if depth < _MAX_WRAPPER_HOPS:
                for c in caller_map.get(node, []):
                    if c not in visited:
                        visited.add(c)
                        queue.append((c, depth + 1))

    return {
        "ranked":     ranked,
        "summaries":  summaries,
        "details":    details,
        "fn_files":   fn_files,
        "caller_map": caller_map,
        "no_slice":   no_slice_fns,
        "answer_key": answer_key or set(),
        "wrapper_of": wrapper_of,
    }


# ---------------------------------------------------------------------------
# Call-graph reachability (P1.2)
# ---------------------------------------------------------------------------

def get_call_paths(
    target_fn: str,
    caller_map: dict,
    header_fns: set | None = None,
    max_depth: int = 10,
) -> list:
    """BFS backward from target_fn through caller_map.

    Returns all paths [entry_point, ..., target_fn] where entry_point has
    no callers in caller_map or is present in header_fns.
    """
    if target_fn not in caller_map:
        return []

    # Each queue entry: (current_node, path_so_far)
    from collections import deque
    queue = deque([(target_fn, [target_fn])])
    paths = []
    visited_paths: set = set()

    while queue:
        node, path = queue.popleft()
        if len(path) > max_depth:
            continue
        callers = caller_map.get(node, [])
        is_entry = (not callers) or (header_fns and node in header_fns)
        if is_entry and len(path) > 1:
            key = tuple(path)
            if key not in visited_paths:
                visited_paths.add(key)
                paths.append(list(reversed(path)))
            continue
        for caller in callers:
            if caller not in path:  # avoid cycles
                queue.append((caller, path + [caller]))

    return sorted(paths, key=len)


# ---------------------------------------------------------------------------
# Main (thin CLI wrapper around score_ir_dir)
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
    ap.add_argument("--reachability-query", type=str, default=None,
                    metavar="FN_NAME",
                    help="Print all call paths from public API to the named function")
    args = ap.parse_args()

    tmpdir = None
    if args.scarnet:
        for tool in ("git", "clang-20"):
            if not shutil.which(tool):
                print(f"ERROR: {tool} not found"); sys.exit(1)
        keep = Path(args.keep_ir) if args.keep_ir else None
        ir_path, tmpdir = _setup_scarnet_ir(keep)
    else:
        ir_path = Path(args.ir_dir)

    answer_key = _load_answer_key(Path(args.answer_key)) if args.answer_key else set()

    result  = score_ir_dir(ir_path, no_gep_only=args.no_gep_only,
                           answer_key=answer_key, verbose=args.verbose)
    ranked  = result["ranked"]
    details = result["details"]
    summaries = result["summaries"]
    no_slice_rule = result["no_slice"]
    top_k   = args.top_k or (len(answer_key) if answer_key else len(ranked))

    print(f"Functions found: {len(ranked)}")
    if answer_key:
        print(f"Answer key: {len(answer_key)} known-vulnerable  (top-K = {top_k})")
    else:
        print(f"No answer key — showing all {len(ranked)} functions ranked")

    if result.get("gep_only_suppressed"):
        print(f"--no-gep-only: suppressing {len(result['gep_only_suppressed'])} GEP-only function(s): "
              + ", ".join(sorted(result["gep_only_suppressed"])))

    wrapper_of = result.get("wrapper_of", {})
    n_wrappers = len(wrapper_of)
    if n_wrappers:
        print(f"Wrappers deduplicated: {n_wrappers} thin wrapper(s) grouped beneath their implementation")

    _print_table("Philosophy 2 rule", ranked, answer_key, top_k, details, wrapper_of)

    print(f"\n{'='*65}")
    if answer_key:
        print(f"  {'Method':<30} {'Hits':>6}  {'P@K':>6}  {'R@K':>6}")
        print(f"  {'-'*30} {'------':>6}  {'------':>6}  {'------':>6}")
        h, p, r = _p_at_k(ranked, answer_key, top_k)
        print(f"  {'Philosophy 2 rule':<30} {len(h):>3}/{len(answer_key):<2}  {p:>6.1%}  {r:>6.1%}")
        print(f"{'='*65}")
        print(f"\n  No-slice: {', '.join(no_slice_rule) or 'none'}")
        rule_misses = sorted(answer_key - {fn for fn, _ in ranked[:top_k]})
        print(f"  Misses:   {rule_misses}")
    else:
        print(f"  No-slice: {', '.join(no_slice_rule) or 'none'}")
        print(f"{'='*65}")

    if args.reachability_query:
        target = args.reachability_query
        caller_map = result["caller_map"]
        paths = get_call_paths(target, caller_map)
        print(f"\n== Reachability: paths to `{target}` ==")
        if not paths:
            print(f"  No call paths found (is `{target}` in the IR?)")
        for path in paths:
            depth = len(path) - 1
            in_ak = " *" if answer_key and path[0] in answer_key else ""
            print(f"  {" -> ".join(path)}  [depth {depth}]{in_ak}")

    if tmpdir and tmpdir.exists():
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
