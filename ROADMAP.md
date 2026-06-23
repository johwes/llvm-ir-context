# Roadmap

Items are grouped by priority. P0 are confirmed production failures observed
in the scarnet harness generation run (2026-06-21). P1 are high-value
improvements with clear implementation paths. P2 are research directions
documented in `ideas.md`.

---

## P0 — Must fix (confirmed harness failures)

*All P0 items resolved. See Completed table.*

---

## P1 — High value, clear implementation path

Items are ordered by dependency: P1.0 unblocks P1.1, P1.3, and P1.7.
P1.2 and P1.3 share the caller_map infrastructure and should be done together
or in sequence.

---

### 0. API cleanup (`api.py` + `__main__.py`)

**Problem:** The core logic in `preprocess_slice_pdg.py`, `slice_context.py`,
and `score_deterministic.py` is importable but the CLI modules mix `argparse`
and `sys.exit` into code paths that also run during library use. Anything that
needs to call the slicer programmatically (blank-shooter check, patch re-validation,
call-graph reachability) has to work around this.

**Fix:** Extract a clean programmatic entry point:

- `llvm_ir_context/api.py` — single function `get_vulnerability_context(ir_text, fn_name) -> dict`; never prints, never calls `sys.exit`; all errors returned as `{"error": ...}` in the payload
- `llvm_ir_context/__main__.py` — thin CLI wrapper around `api.py`; enables `python -m llvm_ir_context`
- Strip any `sys.exit` from non-CLI code paths in existing modules

**Why first:** P1.1, P1.3, and P1.7 all need to call the slicer
programmatically from within other scripts. Doing this cleanup first means
those items are written against a stable internal interface instead of working
around CLI entanglements.

**Bonus:** Clean `api.py` also makes unit testing straightforward — no
`sys.argv` mocking needed.

**Files:** new `llvm_ir_context/api.py`, new `llvm_ir_context/__main__.py`,
minor cleanup in existing modules

---

### 1. Harness IR validation (blank-shooter check)

*Implemented. See Completed table.*

---

### 2. Call-graph reachability query

**Motivation:** Given a known-dangerous function (e.g. `dangerous_c_function`
introduced in the RFE discussion), answer: "what are all the call paths from
the public API surface down to this function?" This is the forward complement
to the existing backward slice: scoring finds *what* is dangerous, reachability
finds *from where it can be triggered* and *what harness entry point to use*.

**What it is:** Transitive BFS/DFS backward through the cross-file call graph,
starting from the target function, terminating at functions with no callers or
at functions present in the public header.

**Infrastructure:** `score_deterministic.py` already builds `_caller_map`
internally for score propagation. This item surfaces that map as a queryable
structure and adds the traversal. The heavy lifting is already done.

**Output:** For each path from a root entry point to the target:
```
dispatch → handle_del → scar_store_free   [depth 2, entry in header: YES]
session_login → scar_store_free           [depth 1, entry in header: YES]
```

**New CLI flag:** `ir-score --reachability-query dangerous_c_function --ir-dir /tmp/ir/`

**Files:** `llvm_ir_context/score_deterministic.py` (expose `_caller_map`,
add traversal), `llvm_ir_context/api.py` (add `get_call_paths()` entry point)

---

### 3. Interprocedural score propagation — calibration

**Implemented (basic form):** When a callee scores ≥ 0.50, its score × 0.75
is propagated to known callers. This lifts `dispatch` from rank 18 (28%) to
rank 8 (61.9%) — correctly surfacing it for harness generation.

**Open question:** The weights (0.75, 0.50) were tuned against scarnet. A more
principled approach propagates **categorical signals** rather than score fractions:
- callee has `double_free=True` → caller gets double_free floor (0.92)
- callee has `use_after_free=True` → caller gets UAF floor (0.88)
- callee has unguarded call sink + `function_argument` → caller gets fixed
  interprocedural floor (e.g. 0.70)

This makes propagation defensible on any codebase without knowing the answer
key. The current continuous approach is correct in direction but scarnet-tuned
in magnitude.

**Note:** In a priority-queue loop (`--skip-if-unchanged`), exact propagation
weights matter less — dispatch will eventually be picked when higher-ranked
functions are exhausted. Propagation primarily ensures dispatch isn't buried
so deep it takes dozens of iterations to reach.

**Shares infrastructure with P1.2** — the same `_caller_map` used for
reachability queries drives categorical propagation. Implement together or
immediately after.

**File:** `llvm_ir_context/score_deterministic.py`, `preprocess_slice_pdg.py`

---

### 4. tree-sitter-c for C source extraction

**Problem:** `extract_fn_source` in `gen_harness.py` uses regex + brace
counting to extract function bodies from `.c` files. This breaks on:
- Macros that expand to `{` or `}`
- `#ifdef` blocks that alter brace nesting
- Inline assembly with curly braces
- Unconventional formatting (K&R style, single-line bodies)

**Fix:** Replace with `tree-sitter-c` (Python bindings via `tree-sitter` +
`tree-sitter-c` packages). Parse the file, query for
`(function_definition)` nodes by name, extract the exact source range.
100% syntactically correct, handles all valid C.

**Effort:** Medium — add `tree-sitter` dependency, rewrite `extract_fn_source`.
**Impact:** Production correctness for arbitrary codebases; scarnet/zlib work
fine with current regex so this is only visible on unusual C code.

**File:** `gen_harness.py` (`extract_fn_source`)

---

### 5. Structured-input / streaming pattern (P-08) — zlib inflate validated

**Observed (zlib validation run):** `inflate` harness compiled clean, called
`inflateInit` correctly without any hint (model read the header — generality
confirmed). Coverage stayed flat at cov:5 for 50k runs with and without seed
corpus. Two root causes:

**P-08a — magic-byte gate:** `inflate` validates the zlib header (2-byte magic +
CMF/FLG fields) at entry. Random bytes fail immediately. Without a seed containing
a valid zlib stream, the fuzzer can't reach any decompression logic.

**P-08b — streaming pattern:** `inflate` is designed for a call loop — it returns
`Z_BUF_ERROR` when `avail_out` exhausts. The single-call harness exited after the
first call without refilling, so even with valid input no deep state was reached.

**Fix path:**
- P-08a: detect `icmp` against small integer constant within 1–2 hops of input
  buffer offset 0/1 near function entry → emit hint "provide seed corpus with a
  valid `<format>` stream; fuzzer cannot reach sink without it"
- P-08b: detect return-value-as-loop-condition shape (function returns status int,
  caller loops while status == CONTINUE) → emit hint "call in a loop; refill
  output buffer each iteration"
- Short-term: `--src-dir` source injection should surface the streaming pattern
  without a hint — model didn't loop even with source available; may need an
  explicit system prompt rule for functions returning status codes

**File:** `llvm_ir_context/slice_context.py` (hints), `gen_harness.py` (system prompt)

See `patterns.md § P-08` for full spec.

---

### 6. IR-hash + coverage change detection (CI integration)

**Problem:** `--skip-existing` skips functions that already have a harness,
permanently. New dangerous code introduced in a refactor is invisible to the
pipeline — the function already has a harness so it's never re-scored or
re-fuzzed.

**Two-layer detection:**

**Layer 1 — IR hash:** On each pipeline run, hash the compiled IR for each
function. If the hash changed since the harness was generated, re-score and
re-generate the harness. IR change = code change = harness may be stale.

**Layer 2 — Coverage regression:** Even if the IR looks structurally similar,
the existing harness may not exercise new paths. Store a coverage baseline
(edge count or branch bitmap) per harness. If coverage drops on re-fuzz,
flag for harness review — new code may be unreachable.

**Reframes `--skip-existing` as `--skip-if-unchanged`:**
- unchanged = same IR hash AND coverage hasn't regressed
- Cheap to compute (IR hashing is fast, no LLM cost)
- Maps naturally to CI: run scoring + hash check on every PR, spend LLM
  tokens only when IR actually changed

**Relationship to OSS-Fuzz-Gen:** Coverage is used here as a change detector,
not as the primary discovery signal. IR structural scoring remains the driver
for which functions to fuzz; coverage validates that existing harnesses stay
effective as code evolves.

**File:** `gen_harness.py` (`--skip-if-unchanged` flag), new `ir_hash.py`
utility, coverage baseline storage in `.llvm-ir-context/coverage/`

---

### 7. Patch re-validation via slicer

After an LLM generates a fix, compile the patched function to IR and diff the
`summarize_slice` output against the original. Reject if `guard_type` is still
`none` for the same sink; flag for human review if sink count dropped to zero
(function may have been deleted rather than fixed).

All machinery exists. Only new piece: a comparison function over two slice
summaries and wiring into a patch validation CLI.

**Depends on:** P1.0 (calls summarize_slice programmatically without CLI overhead)

See `ideas.md § Patch re-validation via slicer`.

**File:** new `ir-validate-patch` CLI or function in `slice_context.py`

---

## P2 — Research / future

### 1. GNN training levers (in `johwes/llvm-ir-vuln-gnn`)
- Lever 1: Juliet pretraining (§27) — cleaner training signal
- Lever 2: guard direction + taint source as node features
- Lever 3: RankNet pairwise loss (§28) — aligns training to ranking use case

---

## Completed (reference)

| Item | Where |
|---|---|
| **P1.0** API cleanup: `api.py` (`get_vulnerability_context`, `rank_directory`), `__main__.py` (`python -m llvm_ir_context`), `score_ir_dir()` extracted from `main()`, `caller_map` exposed | `llvm_ir_context/api.py`, `llvm_ir_context/__main__.py`, `score_deterministic.py` |
| mem2reg false negative fix (synthetic store→load bridge) | `preprocess_slice_pdg.py` |
| zcfree false positive fix (`has_substantive_call_sink`) | `score_deterministic.py` |
| Compile-error retry loop (multi-turn Qwen) | `gen_harness.py` |
| Header-aware auto-pick (skips non-public functions) | `gen_harness.py` |
| IR signature injection (prevents hallucinated signatures) | `gen_harness.py` |
| Null termination requirement in prompt | `gen_harness.py` |
| Self-harm check on harness IR | `gen_harness.py` |
| `--top-k`, `--skip-existing`, `--output-dir` flags | `gen_harness.py` |
| Trunc hint sharpened (no output cap, concrete trigger values) | `slice_context.py` |
| 13/13 scarnet answer key | validated |
| `scar_log` format string crash confirmed (`%+`, `%0`) | validated |
| **P0.1** strcmp gate detection → `fuzz_fn_arg_idx` hint in context | `slice_context.py`, `preprocess_slice_pdg.py` |
| **P0.2** Split-input hint for (ptr, len) functions | `slice_context.py` |
| **P0.3** Routing gate (P-02): distinguish N-literal dispatch from credential gate | `slice_context.py`, `preprocess_slice_pdg.py` |
| System prompt (security researcher framing, no safety caps) | `gen_harness.py` |
| C source injection (`--src-dir`): target function body included in prompt | `gen_harness.py` |
| **P-05** Interprocedural prompt (callee vulnerability + caller entry point) | `gen_harness.py` |
| `scar_log` format string crash confirmed (`%+`, `%0`) | validated |
| `handle_stats` divide-by-zero confirmed (SIGFPE on first input, `\012`) | validated |
| `handle_del` double-free confirmed (ASAN, 2nd input, `\254\012`, SET→DEL harness) | validated |
| `session_login` coverage: strcmp gate opened (cov 9→10); bug is latent (null-terminator only surfaces via caller) | validated |
| `session_frag` heap-buffer-overflow confirmed (ASAN, READ 258 bytes past 28-byte alloc, pipeline harness) | validated |
| `patterns.md` — harness pattern taxonomy and evaluation rubric | documented |
| `design.md` — design goals, boundary rules, generic-first principle | documented |
| SIGFPE → DIV_BY_ZERO rule_id fix in `crash_to_findings.py` | `crash_to_findings.py` |
| `--replace` flag to drop stale same-file findings on re-run | `crash_to_findings.py` |
| Sizeof guard rule: `Size >= N + sizeof(type)` for multi-byte reads | `gen_harness.py` system prompt |
| State clamp rule: fuzz-seeded counts must be clamped to valid range | `gen_harness.py` system prompt |
| fuzz→repair→fuzz loop validated end-to-end: handle_stats div-by-zero found, SCAR patched, re-fuzz confirmed fix, handle_del double-free unmasked | validated |
| Clean-slate validation: fresh IR + fresh harnesses, 4/7 crashes found (parse_cmd heap-OOB, scar_alloc_copy alloc-too-big, scar_log format-string, session_frag heap-OOB), zero manual harness fixup | validated |
| **P1.5** zext64 false positive: `zext i32→i64` before mul → overflow unreachable on 64-bit; ×0.60 score discount + `+zext64` flag | `score_deterministic.py`, `slice_context.py` |
| System prompt: `#include` header rule (no struct redefinition) | `gen_harness.py` |
| System prompt: `free()` pointer return values rule | `gen_harness.py` |
| `--save-prompt` flag: writes full LLM prompt to `harness_<fn>_prompt.md` | `gen_harness.py` |
| `_extract_header_for_fn`: transitive typedef expansion (captures struct body), integer/hex `#define` constants (Z_OK, Z_NO_FLUSH), empty-output fallback — validated on zlib-ng `inflate`/`deflate` | `gen_harness.py` |
| Prompt module system (`build_task_block`): M-01–M-07 modules selected by slicer signals | `gen_harness.py` |
| M-02 routing gate module: multi-call sequence, `Data[i]` verb selection per call | `gen_harness.py` |
| M-05 double-free precondition module: two-phase SETUP+TRIGGER harness structure | `gen_harness.py` |
| Callee flag propagation (`_enrich_with_callee_flags`): double_free/UAF from direct callees merged into prompt summary | `gen_harness.py` |
| `--function` with `--ir-dir`: bypass ranking, generate exactly the named function | `gen_harness.py` |
| `--function` / `--ir-dir` bug fix: `_find_ll_for_function` regex uses `@fn\s*(` not `\b@fn\b` | `gen_harness.py` |
| `dispatch` → `handle_del` double-free confirmed via pipeline: IR scoring → M-02+M-05 prompt → SET→DEL harness → ASAN crash | validated |
| `_generate_interprocedural` updated to use `build_task_block` (consistent with `generate_one`) | `gen_harness.py` |
| sroa+mem2reg pass: `apply_mem2reg()` strips `optnone`, runs `sroa,mem2reg` — fully promotes -O0 array/scalar allocas; typestate `double_free` detection now works correctly; `_ir_has_double_free` text fallback removed | `preprocess_slice_pdg.py`, `gen_harness.py` |
| `-Xclang -disable-O0-optnone` added to all compile commands — prevents optnone at source so mem2reg never needs to strip it | `score_deterministic.py`, `gen_harness.py`, docs |
| `apply_patch.py`: strips markdown fences, `--all` flag, pure-insertion anchor fix, auto-applies all SCAR patches from `scar-results.json` | `apply_patch.py` |
| `crash_to_findings.py`: auto-detects `llvm-symbolizer-20`, injects `ASAN_SYMBOLIZER_PATH` when re-running fuzzer binary | `crash_to_findings.py` |
| End-to-end scarnet walkthrough: 4/4 bugs found+patched+verified on clean repo (scar_log, scar_alloc_copy, dispatch→handle_del, session_frag) | `slice-context-guide.md` |
| **M-08** output buffer sizing module: fires on buffer-write sinks only (not printf/format-string); code template with 4MB cap (`OUT_CAP_MAX`), never from fuzz bytes; `_trim_header()` trims large headers to ~6KB focused on target function | `gen_harness.py` |
| **P1.1** blank-shooter check: slice `LLVMFuzzerTestOneInput` using target fn as extra sink; fail if `function_argument` not in `input_channels`; retry with specific message; OK line shows node count + guard type | `gen_harness.py` |
| Bug fix: `_build_include_preamble` received header file content instead of path, producing garbage `#include` line; renamed to `header_path`, threaded `args.header` through `generate_one` and `_generate_interprocedural` | `gen_harness.py` |
| Bug fix: system prompt `#include` rule contradicted M-00; replaced with "do not write any `#include` lines — they are injected automatically" | `gen_harness.py` |
| **M-04** teardown hardened: require `deflateEnd`/`inflateEnd`/`free` on all exit paths; prohibit `deflateReset` misuse; recommend `goto cleanup` pattern | `gen_harness.py` |
| `LLM_ENDPOINT` / `LLM_MODEL` / `LLM_API_KEY` env vars: switch model without code change | `gen_harness.py` |
| zlib validation (deepseek-r1-distill-qwen-14b): inflate+deflate both `Done 50000 runs` clean; model follows multi-constraint prompts reliably | validated |
| `_extract_header_for_fn`: drop multi-line comment blocks outside struct bodies (99KB→12KB for inflate) | `gen_harness.py` |
| P2: zlib harness experiment (inflate+deflate pipeline validation) | validated |
