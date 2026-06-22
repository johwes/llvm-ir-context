# Roadmap

Items are grouped by priority. P0 are confirmed production failures observed
in the scarnet harness generation run (2026-06-21). P1 are high-value
improvements with clear implementation paths. P2 are research directions
documented in `ideas.md`.

---

## P0 — Must fix (confirmed harness failures)

### 1. strcmp gate → coverage flatness
**Observed:** `session_login` fuzzer ran 10,000 iterations at `cov: 9 ft: 10` —
flat from start to finish. A `strcmp(pass, "scarnet123")` early-exit prevents
the fuzzer from reaching the `memcpy` null-terminator bug.

**Fix (two parts, implement together):**

a. **Strcmp hint in `slice_context.py`** — when the slicer detects an `icmp`
fed by `call @strcmp`/`@strncmp`/`@memcmp` against a known `@.str` global,
emit a harness hint: "argument `X` is gated by a strcmp against the literal
`"scarnet123"` — hardcode that value and fuzz only the other arguments."
Same mechanism as the existing `trunc` hint.

b. **String literal dict extraction** — walk `@.str*` globals referenced in
the function body, decode the byte array, write a `<fn_name>.dict` file.
Pass to libFuzzer via `-dict=`. Low effort, complementary to (a).

Detection: in the backward slice, look for `icmp` node whose operand is a
`call @strcmp` where one argument is a `getelementptr` into a `@.str` global.

**File:** `llvm_ir_context/slice_context.py` (hint), `llvm_ir_context/score_deterministic.py` or new `dict_extract.py` (dict)

---

### 2. Split-input pattern for (ptr, len) functions
**Observed:** `scar_alloc_copy` fuzzer ran 10,000 iterations at `cov: 5 ft: 6`
— flat. The harness called `scar_alloc_copy(Data, Size)` — libFuzzer
guarantees `Data` is exactly `Size` bytes so `memcpy(buf, s, len)` never
reads out of bounds. The vulnerability is caller-side API misuse: `len`
larger than `s`'s actual allocation.

**Fix:** Detect the (ptr, len) pattern and emit a split-input hint.

Conditions: function takes a buffer pointer + length; dangerous sink uses the
length parameter; length comes from `function_argument`; no guard compares
length against the allocation.

Hint text: "split input — derive `len` from one region and `s` from another
so they can diverge; use a small fixed-size source buffer (e.g., 64 bytes)
and let `len` be fuzzed freely."

**File:** `llvm_ir_context/slice_context.py`

---

## P1 — High value, clear implementation path

### 3. Harness IR validation (blank-shooter check)
Compile harness + target to combined IR via `llvm-link`, run slicer with
`fn_name="LLVMFuzzerTestOneInput"`. Check `"function_argument" in
summary["input_channels"]` — if false, `Data`/`Size` never reach the sink.
Feed failure back to the LLM with a specific error before wasting fuzzer CPU.

Currently the self-harm check (step 4 in `gen_harness.py`) catches harness
bugs but not blank-shooters. This adds the missing complementary check.

See `ideas.md § Harness IR validation` for full implementation sketch.

**File:** `gen_harness.py` (new `validate_harness()` function)

---

### 4. Interprocedural guard propagation
Internal helpers (e.g., `lm_init` in zlib) consistently score high because
their guards live in the caller. `header-aware auto-pick` filters them from
harness generation, but they still pollute the ranking output and require
`--no-gep-only` to suppress.

When `caller_validated=True` and all input channels are
`external_call_return` (no direct `function_argument`), apply a score
reduction (×0.70) to reflect the likely upstream guard.

Requires tracking which caller `icmp` guards which argument slot — a
meaningful extension to the cross-file caller scan.

See `ideas.md § Interprocedural guard propagation` for caveats.

**File:** `llvm_ir_context/score_deterministic.py`

---

### 5. Patch re-validation via slicer
After an LLM generates a fix, compile the patched function to IR and diff the
`summarize_slice` output against the original. Reject if `guard_type` is still
`none` for the same sink; flag for human review if sink count dropped to zero
(function may have been deleted rather than fixed).

All machinery exists. Only new piece: a comparison function over two slice
summaries and wiring into a patch validation CLI.

See `ideas.md § Patch re-validation via slicer`.

**File:** new `ir-validate-patch` CLI or function in `slice_context.py`

---

## P2 — Research / future

### 6. zlib harness experiment
Run `gen_harness.py --ir-dir /tmp/zlib-ir/ --no-gep-only --top-k 2 --header
/usr/include/zlib.h` targeting `inflate` and `inflateBack` (+trunc, unguarded
memcpy). Validates the trunc hint and `inflateInit` requirement against a
well-understood library. zlib is in OSS-Fuzz so a new bug is unlikely; the
goal is pipeline validation.

### 7. GNN training levers (in `johwes/llvm-ir-vuln-gnn`)
- Lever 1: Juliet pretraining (§27) — cleaner training signal
- Lever 2: guard direction + taint source as node features
- Lever 3: RankNet pairwise loss (§28) — aligns training to ranking use case

---

## Completed (reference)

| Item | Where |
|---|---|
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
| `patterns.md` — harness pattern taxonomy and evaluation rubric | documented |
| `design.md` — design goals, boundary rules, generic-first principle | documented |
