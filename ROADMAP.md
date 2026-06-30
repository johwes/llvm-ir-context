# Roadmap

Items are grouped by priority. P0 are confirmed production failures observed
in the scarnet harness generation run (2026-06-21). P1 are high-value
improvements ordered by impact. P2 are research directions documented in
`ideas.md`.

---

## P0 — Must fix (confirmed harness failures)

*All P0 items resolved. See Completed table.*

---

## P1 — High value, ordered by priority

Items are ordered by the following logic: P1.0 benchmark is complete — findings
drove the priority order. P1.1 (wrapper dedup) and P1.3 (sink expansion) are
independent and can run in parallel. P1.4 (interprocedural guard attribution)
depends on P1.0 findings (confirmed useful). P1.2 is a small cleanup. P1.6–P1.10
are deprioritised: polish, blocked by P1.4, or gated on CI integration.

---

### 0. Benchmark on a real hardened target

*Completed. See results below.*

**Target:** OpenSSL 3.0.7 (pinned before 3.0.8 security fixes), 11,248 functions
across `ssl/` and `crypto/`.

**Answer key (6 CVEs in scope):**
| CVE | Function | Bug type | In-scope? |
|---|---|---|---|
| CVE-2022-4450 | `PEM_read_bio_ex` | double-free | Yes |
| CVE-2023-0215 | `BIO_new_NDEF` | cross-function UAF | Yes — but interprocedural blind spot |
| CVE-2023-0286 | `GENERAL_NAME_cmp` | type confusion / invalid ptr | No — no dangerous sink |
| CVE-2023-0216 | `d2i_PKCS7` | invalid pointer deref | No — no dangerous sink |
| CVE-2023-0401 | `PKCS7_signatureVerify` | null deref | No — out of scope by design |
| CVE-2022-4203 | `name_constraint_check` | buffer over-read | No — GEP suppressed / name mismatch |

**Results (post constant-length memcpy fix):**
- `PEM_read_bio_ex` ranked **2nd** — hit
- `BIO_new_NDEF` missed — cross-function UAF, typestate is intra-procedural only
- P@6 = 1/6 (16.7%); on in-scope CVEs only: **1/2 (50%)**

**Key findings:**
1. **Constant-length memcpy false positives** dominated the top 40 before the fix
   (`fe_copy`, `EVP_CIPHER_CTX_get_*`, `curve448_*_copy` etc. — all 100% scored).
   Fixed during benchmark run by skipping constant-length sinks. This was the
   single highest-impact fix the benchmark produced.
2. **Wrapper/alias cluster** is the dominant remaining noise: ranks 7–23 are 16
   `PEM_read_*` thin wrappers that all delegate to `PEM_read_bio_ex` (rank 2).
   One underlying code path, 16 ranking entries. → New P1.1.
3. **Interprocedural typestate gap**: `BIO_new_NDEF` UAF is cross-function (free
   in one function, dangling use in caller via `BIO_pop()`). Intra-procedural
   typestate can't see it. → Confirms P1.3 (function summary approach).
4. **Out-of-scope CVEs**: 4 of 6 answer-key bugs are null deref, type confusion,
   or pointer deref without a call-based sink — correctly outside the tool's stated
   scope. The scoring model is working as designed.

---

### 1. Wrapper/alias deduplication

**Problem:** The benchmark revealed that ranks 7–23 are all thin wrapper functions
that immediately delegate to a single higher-ranked function (`PEM_read_bio_ex` at
rank 2). All 16 `PEM_read_*` variants share the same underlying sink and the same
code path — they add no information to the ranking but consume 17 of the top-23
slots, burying genuinely distinct findings below them.

This is a systematic pattern in any large C codebase with a public API layer:
the public API functions are thin wrappers over internal implementation functions.
The implementation function is the real target; the wrappers are noise.

**Detection:** A function is a wrapper candidate when:
- It has exactly one non-GEP call sink
- That call sink is itself a ranked function scoring above some threshold
- Its own body contributes no additional sinks or guards beyond the call

**Fix:** When a function's only sinks are a single call to a higher-ranked function
already in the output, suppress it from the ranked table (or annotate it as
`[wrapper of <fn>]` and group it). The implementation function keeps its rank; the
wrappers are listed as aliases beneath it rather than as separate entries.

**Effort:** Medium — requires one post-ranking pass over the summaries. The call
graph is already built; this is a filter on top of the existing output.

**Files:** `llvm_ir_context/score_deterministic.py` (`score_ir_dir`, `_print_table`)

---

### 3. Sink list expansion — command injection and path traversal

**Problem:** The current sink set covers memory-safety hazards almost
exclusively (memcpy/strcpy/malloc family). Two whole CVE categories with the
same backward-slice detection shape are missing:

- **Command injection:** `system()`, `popen()`, `execv()`/`execvp()`/`execve()`
  — user-controlled string reaches a shell or exec call without sanitisation.
- **Path traversal:** `open()`, `fopen()`, `unlink()`, `rename()`, `openat()`
  — user-controlled string reaches a filesystem call without path canonicalisation
  check.

Both have the same detectable IR shape as existing sinks: function-argument
source, no sanitisation guard between entry and call, the dangerous function
name in the callee. The only addition is new entries in the sink registry and
a new scoring tier.

**Fix:**
- Add `system`, `popen`, `execv`, `execvp`, `execve`, `execle` to the sink
  list with a new `command_injection` category.
- Add `open`, `openat`, `fopen`, `fopen64`, `unlink`, `rename`, `rmdir` to
  the sink list with a new `path_traversal` category.
- Add a scoring tier for each (suggested: same base as unguarded call sink,
  no buffer-write multiplier, no format-only discount).
- Add harness hints: command injection → "argument reaches shell/exec call;
  inject shell metacharacters"; path traversal → "argument reaches filesystem
  call; inject `../` sequences".
- Add entries to `patterns.md`.

**Effort:** Low–medium — a day of work on the sink registry and scoring,
plus test cases.

**Files:** `llvm_ir_context/score_deterministic.py` (sink registry),
`llvm_ir_context/slice_context.py` (hints), `patterns.md`

---

### 4. Interprocedural guard attribution

**Problem:** Internal helper functions that have their guards in the caller
consistently rank high (e.g. `lm_init` in zlib — no `icmp` in its body, but
`deflateInit2_` validates `windowBits` before calling it). The current
`caller_validated` flag is too coarse: it checks whether *any* caller of this
function contains *any* `icmp`, not whether the `icmp` in the caller guards
*the specific argument slot* that feeds the sink.

The completed interprocedural score propagation (P1.3) addresses the
complementary case (caller is clean, callee is dangerous). This item addresses
the inverse: function looks dangerous, caller actually guards it.

**Fix:** Argument-slot-level guard attribution rather than score propagation.
When the slicer sees a function where:
- All input channels are `external_call_return` (no direct `function_argument`), and
- `caller_validated` is true

...traverse one hop into callers and check whether the specific argument slot
feeding the sink has an `icmp` guard in the caller's slice. If yes, apply a
score reduction (suggested 0.70×) and annotate with `[+caller_guarded:argN]`.
If the guard protects a different argument slot, do not reduce.

This is more precise than the current heuristic and directly addresses the
dominant false-positive pattern expected on mature codebases.

**Depends on:** P1.0 (benchmark will confirm whether this is the dominant
false-positive category before investing 2–3 weeks here)

**Effort:** High — requires tracking which argument slot a caller's `icmp`
feeds, which is a meaningful extension to the cross-file caller scan.

**Files:** `llvm_ir_context/score_deterministic.py` (caller scan),
`llvm_ir_context/preprocess_slice_pdg.py` (argument slot tracking)

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
- P-08a: dominator tree walk from sink basic block to function entry; collect all
  `icmp`/`switch` instructions on the dominator path whose operands are integer
  literals or enum constants. Emit prompt hint with the extracted constraint values
  (e.g. "to reach this sink, input offset 0–3 must equal `0x789c` (zlib magic)").
  This is strictly more powerful than the original "near function entry" heuristic —
  it catches guards anywhere in the function and extracts the actual required values
  rather than just flagging that a gate exists. Scope: extractable constraints only
  (literal `icmp` operands); struct-field state guards and multi-hop format parsers
  are out of scope (see P2.2).
- P-08b: detect return-value-as-loop-condition shape (function returns status int,
  caller loops while status == CONTINUE) → emit hint "call in a loop; refill
  output buffer each iteration"
- Short-term: `--src-dir` source injection should surface the streaming pattern
  without a hint — model didn't loop even with source available; may need an
  explicit system prompt rule for functions returning status codes

**File:** `llvm_ir_context/slice_context.py` (hints), `gen_harness.py` (system prompt)

See `patterns.md § P-08` for full spec.

---

### 6. `ir-context` CLI cleanup

**Problem:** `pyproject.toml` exposes the `ir-context` entry point as
`slice_context:_demo_cli` — a private function as a named console script.
The `ir-score` CLI went through the P1.0 API cleanup and now has a clean
`__main__.py` path. `ir-context` was not updated at the same time.

**Fix:** Move `_demo_cli` logic into a proper public function or into
`__main__.py` following the same pattern as `ir-score`. Update `pyproject.toml`
to point at the public entry point. Remove the leading underscore or relocate
the function.

**Effort:** Small — an hour of cleanup.

**Files:** `llvm_ir_context/slice_context.py`, `llvm_ir_context/__main__.py`,
`pyproject.toml`

---

### 7. tree-sitter-c for C source extraction

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

### 8. Patch re-validation via slicer

After an LLM generates a fix, compile the patched function to IR and diff the
`summarize_slice` output against the original. Reject if `guard_type` is still
`none` for the same sink; flag for human review if sink count dropped to zero
(function may have been deleted rather than fixed).

All machinery exists. Only new piece: a comparison function over two slice
summaries and wiring into a patch validation CLI.

**Caution:** Until P1.2 (interprocedural guard attribution) is in place, a
patch that moves a guard one function up will look like a failed patch to the
re-validator — producing false rejections on legitimate fixes. Either implement
P1.2 first, or document this blind spot prominently in the CLI output.

**Files:** new `ir-validate-patch` CLI or function in `slice_context.py`

See `ideas.md § Patch re-validation via slicer`.

---

### 9. IR-hash + coverage change detection (CI integration)

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

**File:** `gen_harness.py` (`--skip-if-unchanged` flag), new `ir_hash.py`
utility, coverage baseline storage in `.llvm-ir-context/coverage/`

---

### 10. IR-level linking for internal-linkage functions

**Problem:** `static` C functions cannot be called from a separately-compiled
harness `.c` file — the C linker enforces visibility, and `llvm-link` respects
it too (`define internal` symbols are not exported). Current pipeline skips them
or produces link errors. This leaves attack surface unfuzzed when the only
path to the bug is through a static function.

**Fix:** Treat the target IR as malleable rather than read-only:
1. **Linkage promotion** — before linking, rewrite `define internal ... @fn` to
   `define ... @fn` in the target `.ll` file (regex over IR text, trivial).
2. **`@main` suppression** — rename the target module's `@main` to
   `@__scar_disabled_main` so it does not collide with libFuzzer's `main`.
3. **`llvm-link`** — merge `harness.ll` (compiled from the generated C) with the
   promoted target `.ll` into a single IR module. Compile the merged module
   directly to the fuzzer binary — no source files or header paths needed.
4. **M-10 prompt module** — warns the model that `main` is suppressed and asks
   it to zero-initialize any global variables the target function reads.

**Alignment with the field:** FuzzGen (USENIX 2020) and OSS-Fuzz-Gen both work
from LTO bitcode and never try to externalize static symbols at the source level.
Working at the IR level is the standard approach for automated fuzzer generation.

**Three engineering hurdles (all addressed):**
- Linkage promotion: regex rewrite in IR text — implemented
- `@main` collision: rename in promoted IR — implemented
- Global init state: M-10 module warns model to initialize globals; zero-BSS
  is valid initial state for many server functions

**File:** `gen_harness.py` (`_promote_linkage_in_ir`, `_llvm_link`,
IR-link path in `generate_one`, M-10 module in `build_task_block`)

---

## P2 — Research / future

### 2. Format-gate detection — structured-input targets

**Observed (OpenSSL `PEM_read_bio_ex`):** Harness is correct and compiles cleanly.
Coverage plateaus at 272 edges despite a valid PEM seed corpus and PEM dictionary.
Root cause: the function applies a **format filter** before any vuln-relevant sink —
random-byte mutations cannot stay in valid base64 across the PEM header boundary, so
libFuzzer is trapped in the outer header-scanning layer and never reaches the DER/ASN.1
parser inside.

**What the pipeline currently sees:** The slicer traces `Data` → BIO → target call
correctly. It does not detect that the path to interesting sinks passes through a
format-parsing pre-condition (base64 decode, `-----BEGIN` scan) that random bytes
will almost never satisfy.

**Detection signal:** When the backward slice from interesting sinks passes through:
- Base64 decode functions (`EVP_DecodeBlock`, `BIO_f_base64`)
- Delimiter scanning (`BIO_gets`, `strncmp` against `"-----"`)
- Known format parsers (`PEM_get_type`, `d2i_*`)

...inject a note in the prompt that the function requires **structured input** and
suggest either (a) seeding with valid objects or (b) targeting a lower-level function
(e.g. `d2i_X509` for raw DER) that takes raw bytes directly.

**Related:** P1.5 (P-08a magic-byte gate) covers the simpler case of a `icmp` against
a small constant near entry. This item is the harder generalization: multi-hop format
validation across an opaque BIO/decode boundary.

**Effort:** Medium — requires a known-format-parser list in the slicer and a new
prompt module that fires when the call graph between entry and sink contains one.

**Files:** `llvm_ir_context/slice_context.py` (format gate detection),
`gen_harness.py` (new prompt module)

---

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
| **M-08** output buffer sizing module: fires on buffer-write sinks only (not printf/format-string); generic constraint (no malloc(Size), hard cap, no Data-derived sizes) — zlib-specific code template removed | `gen_harness.py` |
| **M-04** generic teardown: zlib-specific names removed; `deflateReset` anti-pattern note now conditional on streaming sinks only | `gen_harness.py` |
| **M-05** generic resource language: "stores a key" (scarnet-specific) replaced with "creates or acquires a resource" | `gen_harness.py` |
| **P1.1** blank-shooter check: slice `LLVMFuzzerTestOneInput` using target fn as extra sink; fail if `function_argument` not in `input_channels`; retry with specific message; OK line shows node count + guard type | `gen_harness.py` |
| Bug fix: `_build_include_preamble` received header file content instead of path, producing garbage `#include` line; renamed to `header_path`, threaded `args.header` through `generate_one` and `_generate_interprocedural` | `gen_harness.py` |
| Bug fix: system prompt `#include` rule contradicted M-00; replaced with "do not write any `#include` lines — they are injected automatically" | `gen_harness.py` |
| Validation: generic prompt modules confirmed on scarnet top-k 7 — 5/7 crashes (scar_log SEGV, scar_alloc_copy alloc-too-big, dispatch heap-OOB, parse_cmd heap-OOB, session_frag heap-OOB); parse_cmd newly found vs prior 4/7 baseline | validated |
| **P1.2** call-graph reachability: `get_call_paths(target, caller_map)` BFS traversal; `--reachability-query FN_NAME` CLI flag; `get_call_paths()` in `api.py`; validated on scarnet: `main -> handle_client -> dispatch -> handle_del [depth 3]` | `score_deterministic.py`, `api.py` |
| **P1.3** categorical interprocedural propagation: replaced scarnet-tuned 0.75x/0.50 constants with signal-based floors (df->0.92, uaf->0.88, call->0.70, fallback x0.75); details show driving signal e.g. `[+prop:handle_del(df->0.92)]` | `score_deterministic.py` |
| `LLM_ENDPOINT` / `LLM_MODEL` / `LLM_API_KEY` env vars: switch model without code change | `gen_harness.py` |
| zlib validation (deepseek-r1-distill-qwen-14b): inflate+deflate both `Done 50000 runs` clean; model follows multi-constraint prompts reliably | validated |
| `_extract_header_for_fn`: drop multi-line comment blocks outside struct bodies (99KB→12KB for inflate) | `gen_harness.py` |
| P2: zlib harness experiment (inflate+deflate pipeline validation) | validated |
| Extern injection from IR: `_extract_global_decls` + `_inject_global_externs_and_reset` — strips model-written externs, injects correct `extern` decls + `memset`/zero resets from IR type info; M-10 module replaced with "pipeline handles this" | `gen_harness.py` |
| Bug fixes: missing `break` after fd-reader SKIP; no-code-block sentinel bypassing all checks; `_global_decls` missing from `generate_one` retry loop | `gen_harness.py` |
| Self-harm retry message printed to stdout (both `generate_one` and `_generate_interprocedural`) | `gen_harness.py` |
| Callee injection: `priority_callees` on `_callee_source_block`; when `df_callees`/`uaf_callees` non-empty, inject only those (bypass same-file guard); `generate_one` reordered so enrichment runs before callee block — `dispatch` now injects `handle_del` (763 chars) instead of irrelevant session callees (~1097 chars) | `gen_harness.py` |
| M-02/M-05 conflict fix: suppress M-02 when M-05 has specific callees; verb rule added | `gen_harness.py` |
| **P1.7** tree-sitter-c source extraction: replaced regex+brace-counting `extract_fn_source` with AST-based implementation; call sites and comments are structurally excluded; macro-generated functions (no `function_definition` node) return `""` cleanly; regex fallback retained for environments without the package; `tree-sitter>=0.25` + `tree-sitter-c>=0.23` added to `pyproject.toml` | `gen_harness.py`, `pyproject.toml` |
| Bug fix: `ir-context --json` excluded `sinks` from serialized summary, causing `get_context_json()` to always return empty sinks list — `_has_read_sink` was always False, `is_context_reader` was always False, M-11 never fired for any context-handle function (BIO*, FILE*, EVP_MD_CTX*) on any codebase | `llvm_ir_context/slice_context.py` |
