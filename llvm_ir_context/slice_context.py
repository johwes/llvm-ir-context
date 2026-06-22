#!/usr/bin/env python3
"""
slice_context.py — Convert a PDG slice graph into structured vulnerability context.

Takes a slice dict produced by preprocess_slice_pdg.py (or v3) and returns
a structured summary of the vulnerability pattern: what the dangerous sink is,
where the input comes from, whether a guard is present, and natural-language
context ready for injection into an LLM harness-generation prompt.

The goal is to pre-compute the hard analysis step (what is dangerous and why)
so that a small sparse model (e.g. Qwen 35B-A3B) only has to do the easy step
(generate code from a specification) rather than reason about data flow itself.

Usage (standalone):
    python slice_context.py path/to/function.ll
    python slice_context.py path/to/function.ll --json

Usage (as library):
    from slice_context import summarize_slice, format_for_llm
    summary = summarize_slice(graph_dict, fn_name="process_packet")
    prompt_block = format_for_llm(summary, score=0.82)
"""

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Opcode constants (must match OPCODE_VOCAB in preprocess_slice_pdg.py)
# ---------------------------------------------------------------------------

IDX_CONTEXT   = 0
IDX_ARGUMENT  = 1
IDX_MOCK      = 75    # external function / global variable reference
IDX_CONST_INT = 76
IDX_CONST_FP  = 77
IDX_UNDEF     = 78
IDX_UNKNOWN   = 79

ICMP_OPCODES = frozenset({
    46,              # icmp (unspecified predicate)
    80, 81,          # eq, ne
    82, 83, 84, 85,  # slt, sle, sgt, sge
    86, 87, 88, 89,  # ult, ule, ugt, uge
})

# Subsets of ICMP_OPCODES by structural meaning
_BOUNDS_CHECK_OPCODES = frozenset({82, 83, 84, 85, 86, 87, 88, 89})  # slt/sle/sgt/sge/ult/ule/ugt/uge
_NULL_CHECK_OPCODES   = frozenset({80, 81})                           # eq, ne

_ICMP_LABEL: dict[int, str] = {
    80: "eq", 81: "ne",
    82: "slt", 83: "sle", 84: "sgt", 85: "sge",
    86: "ult", 87: "ule", 88: "ugt", 89: "uge",
    46: "icmp",
}

# Human-readable display names for IR opcodes that appear as sinks.
# Keyed by the internal name used in _SINK_INFO / sink_fn_names.
_DISPLAY_NAMES: dict[str, str] = {
    "getelementptr": "array/ptr-subscript",
    "alloca":        "vla-stack-alloc",
}

# Dangerous sink descriptions: fn_name → (what it does, what to fuzz)
_SINK_INFO: dict[str, tuple[str, str]] = {
    "strcpy":   ("copies string to dest without bounds check",
                 "source string length vs dest buffer size"),
    "strncpy":  ("copies at most n bytes — check dest capacity vs n",
                 "n relative to dest size; source not null-terminated when n < len(src)"),
    "strcat":   ("appends string without bounds check",
                 "remaining dest capacity vs source length"),
    "strncat":  ("appends at most n bytes",
                 "n relative to remaining dest capacity"),
    "memcpy":   ("copies n bytes from src to dest — no overlap or bounds check",
                 "n relative to dest buffer size; n=0, n=SIZE_MAX, n=dest_size+1"),
    "memmove":  ("moves n bytes — allows overlap, no bounds check",
                 "n relative to dest size"),
    "memset":   ("fills n bytes — no bounds check",
                 "n relative to buffer size"),
    "bcopy":    ("copies n bytes src→dest (deprecated) — no bounds check",
                 "n relative to dest size"),
    "sprintf":  ("formats into dest without length limit",
                 "formatted output length vs dest size; user-controlled format string"),
    "snprintf": ("formats at most n bytes — verify n matches dest",
                 "n relative to dest size; off-by-one at n"),
    "vsprintf": ("formats variadic args without length limit",
                 "formatted output length vs dest size"),
    "vsnprintf":("formats variadic args, at most n bytes",
                 "n relative to dest size"),
    "gets":     ("reads line with no length limit — inherently unsafe",
                 "any non-empty input; function is unconditionally vulnerable"),
    "fgets":    ("reads at most n-1 chars — check n matches buffer",
                 "n relative to buffer size; input exactly n-1 chars with no newline"),
    "scanf":    ("reads formatted input — %%s without width is unbounded",
                 "input longer than any %%s field width; format string control"),
    "sscanf":   ("reads from string — %%s without width is unbounded",
                 "input longer than any %%s field width"),
    "fscanf":   ("reads from file — %%s without width is unbounded",
                 "input longer than any %%s field width"),
    "read":     ("reads up to count bytes — no null termination",
                 "count relative to buffer size; count=0; count=SIZE_MAX"),
    "recv":     ("receives up to len bytes — no null termination",
                 "len relative to buffer size; len=0; len=INT_MAX"),
    "recvfrom": ("receives up to len bytes from socket",
                 "len relative to buffer size; truncated messages"),
    "pread":    ("reads up to count bytes at offset",
                 "count relative to buffer size; offset overflow"),
    "malloc":   ("allocates heap — return may be null; size may overflow",
                 "size=0; size=SIZE_MAX; integer overflow in size computation"),
    "calloc":   ("allocates zeroed heap — n*size may overflow; return may be null",
                 "n*size integer overflow; n=0 or size=0; very large n"),
    "realloc":  ("reallocates — null return leaves original pointer valid but lost",
                 "new_size=0 (frees); new_size=SIZE_MAX; null return before use"),
    "free":     ("frees heap memory — double-free or use-after-free if called again",
                 "call target twice with same pointer; access after free"),
    "xmalloc":  ("malloc wrapper — check whether it aborts or returns null on failure",
                 "very large size; size=0"),
    "xrealloc": ("realloc wrapper",
                 "new_size=0; very large size"),
    "printf":   ("format string to stdout — dangerous if format is user-controlled",
                 "user-controlled format string with %%n, %%s, %%x"),
    "fprintf":  ("format string to file",
                 "user-controlled format string"),
    "syslog":   ("format string to syslog",
                 "user-controlled format string with %%n"),
    "err":      ("format string + perror to stderr",
                 "user-controlled format string"),
    "warn":     ("format string warning to stderr",
                 "user-controlled format string"),
    "getelementptr": ("pointer arithmetic with non-constant index — out-of-bounds if unchecked",
                      "index at, near, and beyond array bounds; negative index; index=SIZE_MAX"),
    "alloca":        ("stack allocation with non-constant size (VLA) — stack overflow if unchecked",
                      "size=0; size=SIZE_MAX; negative size (signed wrap); size from user input"),
    "sdiv":   ("signed division with non-constant divisor — divide-by-zero if divisor not checked",
               "divisor=0; divisor=-1 with dividend=INT_MIN (signed overflow)"),
    "udiv":   ("unsigned division with non-constant divisor — divide-by-zero if divisor not checked",
               "divisor=0"),
    "srem":   ("signed remainder with non-constant divisor — divide-by-zero if divisor not checked",
               "divisor=0; divisor=-1 with dividend=INT_MIN"),
    "urem":   ("unsigned remainder with non-constant divisor — divide-by-zero if divisor not checked",
               "divisor=0"),
}


# ---------------------------------------------------------------------------
# Core summarizer
# ---------------------------------------------------------------------------

def summarize_slice(g: dict, fn_name: str = "unknown") -> dict:
    """
    Convert a PDG slice dict into structured vulnerability context.

    Slice dict keys (preprocess_slice_pdg.py format):
      x             (N, 1) int64  — opcode ID per node
      edge_index    (2, E) int64  — [src; dst]
      edge_type     (E,)   int64  — 0=CFG, 1=DFG, 2=context
      sink_mask     (N,)   bool   — True at sink nodes (v3 only; inferred if absent)
      sink_fn_names {int: str}    — node_idx → dangerous function name at that sink

    Returns dict:
      fn_name, slice_size, n_sinks, sinks (list),
      input_channels (list), guard_count, has_guard,
      natural_language (str), harness_hint (str)
    """
    x          = g["x"]
    N          = x.shape[0]
    edge_index = g["edge_index"]
    edge_type  = g["edge_type"]
    E          = edge_index.shape[1] if (edge_index.ndim == 2 and edge_index.size > 0) else 0

    opcodes = [int(x[i, 0]) for i in range(N)]

    sink_fn_names:   dict[int, str] = g.get("sink_fn_names", {})
    source_fn_names: dict[int, str] = g.get("source_fn_names", {})
    div_sink_names:  dict[int, str] = g.get("div_sink_names", {})
    double_free:      bool  = g.get("double_free", False)
    use_after_free:   bool  = g.get("use_after_free", False)
    freed_ptrs:       list  = g.get("freed_ptrs", [])
    caller_validated: bool  = g.get("caller_validated", False)
    caller_count:     int   = g.get("caller_count", 0)
    caller_names:     list  = g.get("caller_names", [])
    strcmp_guards:    list  = g.get("strcmp_guards", [])
    arg_count:        int   = g.get("arg_count", 0)
    sink_mask = g.get("sink_mask", None)

    # ---- build DFG adjacency (used for distance + guard path analysis) -----
    # fwd_dfg[src] = [dst, ...]  — DFG edges only (edge_type == 1)
    from collections import deque
    fwd_dfg: dict[int, list[int]] = {}
    rev_dfg: dict[int, list[int]] = {}
    for e in range(E):
        if int(edge_type[e]) == 1:
            s, d = int(edge_index[0, e]), int(edge_index[1, e])
            fwd_dfg.setdefault(s, []).append(d)
            rev_dfg.setdefault(d, []).append(s)

    # ---- identify sinks ------------------------------------------------
    sinks = []

    if sink_mask is not None:
        for i in range(N):
            if not sink_mask[i]:
                continue
            opc = opcodes[i]
            if opc == 63:   # call
                fn = sink_fn_names.get(i, "unknown")
                sinks.append({"node": i, "type": "dangerous_call", "fn": fn})
            elif opc == 29: # getelementptr
                sinks.append({"node": i, "type": "unguarded_gep", "fn": "getelementptr"})
            elif opc == 26: # alloca with non-constant size (VLA)
                sinks.append({"node": i, "type": "vla_alloca", "fn": "alloca"})
    else:
        # Fallback: scan for call, GEP, and VLA alloca nodes when sink_mask absent
        for i in range(N):
            opc = opcodes[i]
            if opc == 63 and i in sink_fn_names:
                sinks.append({"node": i, "type": "dangerous_call",
                               "fn": sink_fn_names[i]})
            elif opc in (29, 26):
                # Only flag if it has a non-constant DFG predecessor
                preds = []
                for e in range(E):
                    if int(edge_type[e]) == 1 and int(edge_index[1, e]) == i:
                        preds.append(int(edge_index[0, e]))
                const_ids = {IDX_CONST_INT, IDX_CONST_FP, IDX_UNDEF, IDX_CONTEXT}
                if any(opcodes[p] not in const_ids for p in preds):
                    fn = "getelementptr" if opc == 29 else "alloca"
                    kind = "unguarded_gep" if opc == 29 else "vla_alloca"
                    sinks.append({"node": i, "type": kind, "fn": fn})

    # ---- div/rem sinks (non-constant divisor) --------------------------
    # Guard for these is icmp ne ... 0 (null_check), which IS sufficient —
    # unlike buffer writes where null_check is inadequate.
    _DIV_OPCODES_MAP = {5: "udiv", 6: "sdiv", 7: "urem", 8: "srem"}
    for i, opname in div_sink_names.items():
        sinks.append({"node": i, "type": "div_by_zero", "fn": opname})

    # Fallback: also scan opcodes directly if div_sink_names absent/empty
    if not div_sink_names:
        for i in range(N):
            opc = opcodes[i]
            if opc in _DIV_OPCODES_MAP:
                preds = [int(edge_index[0, e]) for e in range(E)
                         if int(edge_type[e]) == 1 and int(edge_index[1, e]) == i]
                const_ids = {IDX_CONST_INT, IDX_CONST_FP, IDX_UNDEF, IDX_CONTEXT}
                divisor = preds[1] if len(preds) >= 2 else (preds[0] if preds else None)
                if divisor is not None and opcodes[divisor] not in const_ids:
                    sinks.append({"node": i, "type": "div_by_zero",
                                  "fn": _DIV_OPCODES_MAP[opc]})

    # ---- input channels ------------------------------------------------
    input_channels = []
    if any(opc == IDX_ARGUMENT for opc in opcodes):
        input_channels.append("function_argument")
    if any(opc == IDX_MOCK for opc in opcodes):
        input_channels.append("external_call_return")
    if not input_channels:
        input_channels.append("internal_computation")

    # ---- external input flag -------------------------------------------
    # True if a known input-source function (recv/read/fgets/...) appears as
    # a mock node in the slice — meaning network/user data reaches the sink.
    is_external_input = bool(source_fn_names)
    external_sources  = sorted(set(source_fn_names.values()))

    # ---- guard check ---------------------------------------------------
    guard_count = sum(1 for opc in opcodes if opc in ICMP_OPCODES)
    has_guard   = guard_count > 0

    # ---- guard direction -----------------------------------------------
    # Classify which kinds of comparisons guard this slice.
    # bounds_check: relational (<, <=, >, >=) — protects buffer writes
    # null_check:   equality (==, !=) — protects pointer dereferences
    bounds_check_count = sum(1 for opc in opcodes if opc in _BOUNDS_CHECK_OPCODES)
    null_check_count   = sum(1 for opc in opcodes if opc in _NULL_CHECK_OPCODES)
    # Dominant guard type; "mixed" when both present
    if bounds_check_count > 0 and null_check_count > 0:
        guard_type = "mixed"
    elif bounds_check_count > 0:
        guard_type = "bounds_check"
    elif null_check_count > 0:
        guard_type = "null_check"
    else:
        guard_type = "none"
    # Collect the specific predicate labels present
    guard_predicates = sorted({_ICMP_LABEL[opc]
                                for opc in opcodes
                                if opc in ICMP_OPCODES and opc in _ICMP_LABEL})

    # ---- sink-source hop distance --------------------------------------
    # BFS forward from all argument and input-source mock nodes through DFG edges.
    # Records minimum hop count to each sink node.
    source_nodes = {i for i, opc in enumerate(opcodes)
                    if opc == IDX_ARGUMENT or i in source_fn_names}
    sink_node_ids = {s["node"] for s in sinks}

    dist: dict[int, int] = {n: 0 for n in source_nodes}
    queue = deque(source_nodes)
    while queue:
        node = queue.popleft()
        for nxt in fwd_dfg.get(node, []):
            if nxt not in dist:
                dist[nxt] = dist[node] + 1
                queue.append(nxt)

    # Attach distance to each sink entry
    for s in sinks:
        s["distance"] = dist.get(s["node"])   # None if unreachable from sources

    min_distance = (min((s["distance"] for s in sinks if s["distance"] is not None),
                        default=None)
                    if sinks else None)

    # ---- integer truncation signal ------------------------------------
    # trunc (opcode 48) narrows an integer type (e.g. i64->i32).
    # When present in a slice that also has size-taking sinks, it is a
    # precursor pattern for integer-truncation vulnerabilities.
    _SIZE_SINKS = frozenset({
        "memcpy", "memmove", "memset", "bcopy",
        "malloc", "calloc", "realloc", "xmalloc", "xrealloc",
        "read", "recv", "recvfrom", "pread",
        "snprintf", "vsnprintf", "fgets", "alloca",
    })
    trunc_count = sum(1 for opc in opcodes if opc == 48)
    has_trunc   = trunc_count > 0 and any(
        s.get("fn") in _SIZE_SINKS for s in sinks
    )

    # ---- deduplicate sinks by function name (preserve first-seen order) ----
    from collections import Counter, OrderedDict
    sink_counts: dict[str, int] = Counter(s.get("fn") or "unknown" for s in sinks)
    seen: set[str] = set()
    unique_sinks = []
    for s in sinks:
        fn = s.get("fn") or "unknown"
        if fn not in seen:
            seen.add(fn)
            unique_sinks.append(s)

    # ---- natural language + harness hint (deduplicated) -----------------
    sink_strs  = []
    hint_parts = []

    for s in unique_sinks:
        fn      = s.get("fn") or "unknown"
        display = _DISPLAY_NAMES.get(fn, fn)
        count   = sink_counts[fn]
        info    = _SINK_INFO.get(fn)
        suffix  = f" ×{count}" if count > 1 else ""
        if info:
            what, probe = info
            sink_strs.append(f"`{display}`{suffix} ({what})")
            if f"fuzz {probe}" not in hint_parts:
                hint_parts.append(f"fuzz {probe}")
        else:
            sink_strs.append(f"`{display}`{suffix} (dangerous operation)")
            if "fuzz all arguments" not in hint_parts:
                hint_parts.append("fuzz all arguments")

    if not sinks:
        sink_strs  = ["no explicit dangerous sink identified — scored by full-graph structure"]
        hint_parts = ["fuzz all inputs broadly"]

    # ---- guard density -------------------------------------------------
    n_sinks = len(sinks)
    if n_sinks == 0:
        guard_density       = 0.0
        guard_density_label = "no sinks"
    elif not has_guard:
        guard_density       = float("inf")
        guard_density_label = "UNGUARDED"
    else:
        guard_density = n_sinks / guard_count   # sinks per guard — higher = worse
        if guard_density >= 10:
            guard_density_label = "very sparse"
        elif guard_density >= 5:
            guard_density_label = "sparse"
        elif guard_density >= 2:
            guard_density_label = "moderate"
        else:
            guard_density_label = "well-covered"

    channel_note = " or ".join(input_channels)
    if not has_guard:
        guard_note = "no comparison (icmp) in slice — sink appears UNGUARDED"
    elif n_sinks == 0:
        guard_note = f"{guard_count} comparison(s) in slice"
    else:
        guard_note = (
            f"{guard_count} guard(s) / {n_sinks} sink(s)"
            f" = {guard_density:.1f} sinks/guard ({guard_density_label})"
        )

    ext_note = ""
    if is_external_input:
        src_list = ", ".join(external_sources) if external_sources else "external source"
        ext_note = f" [network/user-controlled via {src_list}]"

    dist_note = ""
    if min_distance is not None:
        dist_note = f" Minimum source-to-sink distance: {min_distance} hop(s)."

    natural_language = (
        f"Function `{fn_name}` contains: {'; '.join(sink_strs)}. "
        f"Input originates from: {channel_note}{ext_note}. "
        f"Guard status: {guard_note}. "
        f"{dist_note}"
        f"Slice: {N} nodes, {n_sinks} sink(s) ({len(unique_sinks)} unique type(s))."
    )

    # Buffer-write sink set — used for guard-type-aware hints below.
    _BUFFER_WRITE_FNS = frozenset({
        "strcpy", "strncpy", "strcat", "strncat",
        "memcpy", "memmove", "memset", "bcopy",
        "gets", "fgets", "sprintf", "vsprintf",
    })
    has_buffer_write_sink = any(s.get("fn") in _BUFFER_WRITE_FNS for s in sinks)

    if has_trunc:
        # Identify the size-taking sink the truncation feeds so the hint is specific.
        trunc_sinks = [s.get("fn") for s in sinks if s.get("fn") in _SIZE_SINKS]
        trunc_target = trunc_sinks[0] if trunc_sinks else "the size argument"
        hint_parts.append(
            f"fuzz integer truncation: a wide integer (e.g. i64) is narrowed to a "
            f"narrower type (e.g. i32) before reaching {trunc_target} — "
            f"derive the length from all input bytes without capping it; "
            f"do not artificially bound the output buffer; "
            f"try sizes near UINT32_MAX (0xFFFFFFFF) and values that differ only in "
            f"high bits (e.g. 0x100000001) to trigger the truncation wrap"
        )

    if guard_type == "null_check" and has_buffer_write_sink:
        # null_check (icmp eq/ne) protects pointer validity, not the size argument.
        # Without this note the LLM often assumes the guard is sufficient.
        hint_parts.append(
            "note: the guard is a null-pointer check (icmp eq/ne) — it does NOT bound "
            "the size argument; the buffer write is unprotected; fuzz the size without restriction"
        )

    if "function_argument" not in input_channels and "external_call_return" in input_channels:
        # Input arrives via struct field or callee return value, not a direct parameter.
        # Harnesses that just pass raw bytes will miss the actual data path.
        hint_parts.append(
            "input enters via struct field or callee return value — "
            "populate the input structure before the call rather than passing raw bytes directly"
        )

    if double_free:
        hint_parts.append(
            "fuzz double-free: call twice with same pointer; trigger via two code paths"
        )
    if use_after_free and not double_free:
        hint_parts.append(
            "fuzz use-after-free: free pointer then access via alias or stale reference"
        )

    # strcmp gate / routing gate (P-01 / P-02):
    # Group guards by which function parameter is the non-const operand.
    # If one parameter index appears in ≥2 guards with different literals →
    # routing gate (P-02): the function dispatches on that argument; the harness
    # must randomize across all literals, not hardcode one.
    # If each parameter index appears only once → credential gate (P-01): hardcode
    # the literal to get past the check and fuzz the other argument.
    if strcmp_guards:
        from collections import defaultdict
        by_param: dict = defaultdict(list)
        no_param: list = []
        for sg in strcmp_guards:
            idx = sg.get("fuzz_fn_arg_idx")
            if idx is not None:
                by_param[idx].append(sg)
            else:
                no_param.append(sg)

        routing_params  = {idx for idx, guards in by_param.items() if len(guards) >= 2}
        credential_params = {idx for idx, guards in by_param.items() if len(guards) == 1}

        if routing_params:
            # P-02: routing gate — randomize across all literals
            for idx in sorted(routing_params):
                guards   = by_param[idx]
                literals = [f'"{sg["literal"]}"' for sg in guards]
                lit_list = ", ".join(literals)
                hint_parts.append(
                    f"command router on parameter {idx}: `{guards[0]['fn']}` dispatches "
                    f"on this argument across {len(guards)} literals "
                    f"({lit_list}) — do NOT hardcode one value; randomize "
                    f"parameter {idx} across all {len(guards)} literals so every "
                    f"handler branch is reachable by the fuzzer"
                )

        if credential_params:
            # P-01: credential gate — hardcode the literal
            parts = []
            for idx in sorted(credential_params):
                sg = by_param[idx][0]
                parts.append(
                    f'`{sg["fn"]}` against "{sg["literal"]}" — '
                    f'hardcode "{sg["literal"]}" as the constant string argument; '
                    f'pass `Data` (as a null-terminated copy) into parameter {idx} '
                    f'of `{fn_name}` (the non-constant argument)'
                )
            gate_strs = " | ".join(parts)
            hint_parts.append(
                f"strcmp gate: {gate_strs} — without this, the fuzzer cannot reach "
                f"the dangerous sink past the credential check"
            )

        if no_param:
            # Guards where we couldn't trace back to a function parameter
            parts = [f'`{sg["fn"]}` against "{sg["literal"]}" — '
                     f'hardcode the constant and fuzz the other argument'
                     for sg in no_param]
            hint_parts.append("strcmp gate: " + " | ".join(parts))

    # Split-input pattern: when both buffer pointer and length are independent
    # function arguments feeding the same sink with no guard, calling the function
    # with matching (Data, Size) will never trigger an overflow because libFuzzer
    # guarantees Data is exactly Size bytes.  The harness must create a mismatch.
    _PTR_LEN_SINKS = frozenset({
        "memcpy", "memmove", "memset", "bcopy",
        "strcpy", "strncpy", "strcat", "strncat",
        "read", "recv", "recvfrom", "pread",
    })
    has_ptr_len_sink = any(s.get("fn") in _PTR_LEN_SINKS for s in sinks)
    if (has_ptr_len_sink
            and "function_argument" in input_channels
            and guard_type in ("none", "null_check")
            and arg_count >= 2):
        hint_parts.append(
            "split-input pattern required: both the buffer pointer and the length "
            "are independent function arguments — calling with (Data, Size) will not "
            "trigger an overflow because they always match; instead, derive the source "
            "buffer from a small fixed-size region (e.g. first 64 bytes of Data) and "
            "let the length argument be fuzzed freely from the remaining bytes so the "
            "two can diverge"
        )

    harness_hint = " | ".join(hint_parts)

    return {
        "fn_name":            fn_name,
        "slice_size":         N,
        "n_sinks":            n_sinks,
        "n_unique_sinks":     len(unique_sinks),
        "sinks":              sinks,
        "sink_counts":        dict(sink_counts),
        "input_channels":     input_channels,
        "is_external_input":  is_external_input,
        "external_sources":   external_sources,
        "guard_count":        guard_count,
        "has_guard":          has_guard,
        "guard_type":         guard_type,
        "guard_predicates":   guard_predicates,
        "bounds_check_count": bounds_check_count,
        "null_check_count":   null_check_count,
        "guard_density":      guard_density,
        "guard_density_label":guard_density_label,
        "min_distance":       min_distance,
        "trunc_count":        trunc_count,
        "has_trunc":          has_trunc,
        "double_free":        double_free,
        "use_after_free":     use_after_free,
        "freed_ptrs":         freed_ptrs,
        "caller_validated":   caller_validated,
        "caller_count":       caller_count,
        "caller_names":       caller_names,
        "strcmp_guards":      strcmp_guards,
        "arg_count":          arg_count,
        "natural_language":   natural_language,
        "harness_hint":       harness_hint,
    }


def format_for_llm(summary: dict, score: float | None = None,
                   width: int = 60) -> str:
    """
    Format a slice summary as a labelled block for LLM prompt injection.

    Example output:
        === GNN Vulnerability Context ===
        Suspicion score : 73.2%  (SUSPICIOUS)
        Sinks           : memcpy (copies n bytes without bounds check)
        Input channels  : function_argument
        Guard status    : no comparison in slice — sink UNGUARDED
        Harness target  : fuzz n relative to dest buffer size; n=0, n=SIZE_MAX
        Slice           : 31 nodes, 1 sink
        ==================================
    """
    sep = "=" * width
    fn  = summary.get("fn_name", "unknown")
    lines = [sep, f"Function: {fn}  |  GNN Vulnerability Context"]

    if score is not None:
        flag = "SUSPICIOUS" if score >= 0.5 else "low suspicion"
        lines.append(f"Suspicion score : {score:.1%}  ({flag})")

    # Deduplicate: one label per unique sink type, with ×N count
    sink_counts = summary.get("sink_counts", {})
    seen: set[str] = set()
    sink_labels = []
    for s in summary["sinks"]:
        fn = s.get("fn", "unknown")
        if fn in seen:
            continue
        seen.add(fn)
        display = _DISPLAY_NAMES.get(fn, fn)
        info    = _SINK_INFO.get(fn)
        short   = info[0][:50] if info else "dangerous operation"
        count   = sink_counts.get(fn, 1)
        tag     = f" ×{count}" if count > 1 else ""
        sink_labels.append(f"{display}{tag} — {short}")
    lines.append("Sinks           : " + ("; ".join(sink_labels) if sink_labels
                                          else "none identified"))

    # Input channels + external input flag
    channels = ", ".join(summary["input_channels"])
    if summary.get("is_external_input"):
        srcs = ", ".join(summary.get("external_sources", []))
        channels += f"  [external_input=YES via {srcs}]" if srcs else "  [external_input=YES]"
    lines.append("Input channels  : " + channels)

    n_sinks = summary["n_sinks"]
    gc      = summary["guard_count"]
    gtype   = summary.get("guard_type", "none")
    preds   = summary.get("guard_predicates", [])
    pred_str = f" ({', '.join(preds)})" if preds else ""
    if not summary["has_guard"]:
        guard = "NO icmp in slice — sink appears UNGUARDED"
    elif n_sinks == 0:
        guard = f"{gc} comparison(s){pred_str} present"
    else:
        gd    = summary.get("guard_density", n_sinks / gc)
        label = summary.get("guard_density_label", "")
        if gtype == "bounds_check":
            gtype_str = "bounds-check"
        elif gtype == "null_check":
            gtype_str = "null-check only — may not protect buffer writes"
        elif gtype == "mixed":
            gtype_str = "bounds-check + null-check"
        else:
            gtype_str = gtype
        guard = (f"{gc} guard(s){pred_str} [{gtype_str}]"
                 f" / {n_sinks} sink(s) = {gd:.1f} sinks/guard ({label})")
    lines.append("Guard status    : " + guard)

    # Sink-source distance
    min_dist = summary.get("min_distance")
    if min_dist is not None:
        lines.append(f"Distance        : {min_dist} hop(s) source→sink")

    if summary.get("has_trunc"):
        lines.append(f"Trunc warning   : {summary['trunc_count']} integer narrowing(s) — "
                     f"wide integer narrowed before size arg; values near UINT32_MAX trigger wrap")
    if summary.get("double_free"):
        ptrs = summary.get("freed_ptrs", [])
        ptr_str = ", ".join(ptrs[:3]) + (" ..." if len(ptrs) > 3 else "")
        lines.append(f"Double-free risk: YES  ptr(s): {ptr_str}")
    elif summary.get("use_after_free"):
        ptrs = summary.get("freed_ptrs", [])
        ptr_str = ", ".join(ptrs[:3]) + (" ..." if len(ptrs) > 3 else "")
        lines.append(f"Use-after-free  : YES  freed ptr(s): {ptr_str}")
    if summary.get("caller_validated"):
        callers = summary.get("caller_names", [])
        caller_str = ", ".join(callers[:3]) + (" ..." if len(callers) > 3 else "")
        lines.append(f"Caller guard    : icmp found in caller(s): {caller_str}  — may be validated upstream")
    strcmp_guards = summary.get("strcmp_guards", [])
    if strcmp_guards:
        from collections import defaultdict as _dd
        _by_param: dict = _dd(list)
        for _g in strcmp_guards:
            _by_param[_g.get("fuzz_fn_arg_idx")].append(_g)
        _routing  = {idx for idx, gs in _by_param.items() if idx is not None and len(gs) >= 2}
        _parts = []
        for idx, gs in sorted(_by_param.items(), key=lambda kv: (kv[0] is None, kv[0])):
            lits = "; ".join(f'"{g["literal"]}"' for g in gs)
            if idx in _routing:
                _parts.append(f"param {idx} → router({lits})")
            elif idx is not None:
                _parts.append(f'{gs[0]["fn"]}("{gs[0]["literal"]}") → credential gate param {idx}')
            else:
                _parts.append("; ".join(f'{g["fn"]}("{g["literal"]}")' for g in gs))
        lines.append("Strcmp gate     : " + "; ".join(_parts))
    lines.append("Harness target  : " + summary["harness_hint"])
    lines.append(f"Slice           : {summary['slice_size']} nodes, "
                 f"{summary['n_sinks']} sink(s)")
    lines.append(sep)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Standalone CLI (demo mode — parses IR directly without a trained model)
# ---------------------------------------------------------------------------

def _demo_cli():
    import argparse
    import json as _json
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ir_file", help=".ll file to analyse")
    ap.add_argument("--function", type=str, default=None,
                    help="Only analyse this function name (default: all functions in file)")
    ap.add_argument("--json",  action="store_true", help="output raw JSON summary")
    ap.add_argument("--debug", action="store_true", help="show parse errors instead of silencing them")
    args = ap.parse_args()

    from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg

    import re
    ir_text = Path(args.ir_file).read_text(errors="replace")

    import llvmlite.binding as _llvm
    try:
        _mod = _llvm.parse_assembly(ir_text)
    except Exception as exc:
        if args.debug:
            print(f"Module parse FAILED: {exc}")
        print(f"ERROR: could not parse {args.ir_file}: {exc}")
        sys.exit(1)

    all_functions = [fn.name for fn in _mod.functions if not fn.is_declaration]

    if not all_functions:
        print(f"ERROR: no non-declaration functions found in {args.ir_file}")
        sys.exit(1)

    if args.function:
        if args.function not in all_functions:
            print(f"ERROR: function '{args.function}' not found in {args.ir_file}")
            print(f"Available: {', '.join(all_functions)}")
            sys.exit(1)
        functions = [args.function]
    else:
        functions = all_functions

    for fn_name in functions:
        if args.debug:
            print(f"[{fn_name}] parse OK (full-module mode)")
        g = ir_to_graph_slice_pdg(ir_text, fn_name=fn_name)
        if g is None:
            print(f"[{fn_name}] — could not extract graph (no basic blocks)\n")
            continue

        summary = summarize_slice(g, fn_name=fn_name)

        if args.json:
            print(_json.dumps({k: v for k, v in summary.items()
                                if k != "sinks"}, indent=2))
        else:
            print(format_for_llm(summary))
            print(f"Natural language:\n  {summary['natural_language']}\n")


if __name__ == "__main__":
    _demo_cli()
