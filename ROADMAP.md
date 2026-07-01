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
6. **Path traversal sink false positives at API boundaries:** Library functions
   whose documented purpose is to accept a caller-supplied path (e.g. `BIO_new_file`,
   `openssl_fopen`) score 100% on path traversal because `function_argument → fopen,
   no guard` is structurally identical to a genuine traversal bug. The distinction
   requires knowing whether the caller receives that filename from attacker-controlled
   input — which requires whole-program IR (P2.3). Per-TU analysis cannot
   differentiate "API boundary that accepts a path by design" from "path traversal
   vulnerability." These should be filtered or down-ranked when the function name
   matches a well-known file-opening API wrapper pattern.

5. **Format gate + byte-level fuzzing ceiling (CVE-2022-4450):** The pipeline
   correctly ranked `PEM_read_bio_ex` #2 and generated a harness that gets past
   the PEM header and base64 gate (cov: 272 → 434 with M-13 envelope approach).
   Coverage plateaued at 434 — the ASN.1/DER structure inside the decoded payload
   is a second gate that byte-level fuzzing cannot maintain across mutations.
   The bouncer (PEM/base64/DER) and the bug (double-free) are in the same function;
   there is no lower-level entry point to bypass the bouncer.
   **How CVE-2022-4450 was likely found:** code review — the double-free is visible
   statically without exercising the format parsing path. Structure-aware fuzzers
   (libprotobuf-mutator, grammar-based) or OSS-Fuzz harnesses targeting sub-functions
   (`d2i_X509`) are the dynamic path, but those require per-target engineering.
   **Pipeline conclusion:** the slicer's value on this target was correct ranking
   and structured prompt generation. End-to-end crash reproduction via byte-level
   fuzzing alone is not achievable for bugs behind multi-layer format gates.
   This is an honest scope boundary, not a pipeline failure.

---

### 1. Wrapper/alias deduplication

*Implemented. See Completed table.*

---

### 3. Sink list expansion — command injection and path traversal

*Implemented. See Completed table.*

<!--

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
-->

---

### 11. Sparse guard ratio score boost

*Implemented. See Completed table.*

---

### 12. Write-path / read-path disambiguation

*Implemented (heuristic #1). See Completed table.*

---

### 4. Interprocedural guard attribution

*Implemented. See Completed table.*

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

*Implemented. See Completed table.*

---

### 3. Whole-program IR input (LTO bitcode)

**External review:** A glibc maintainer and CNA flagged that per-TU IR analysis
will accumulate false positives at scale because LTO can substantially transform
IR across the final link boundary — the IR we analyze may not be what the CPU
executes. Covscan-style tools mirror the full build and analyze the post-link IR
to avoid this. They also raised that OSS-Fuzz-Gen uses the project build system
directly, which gives higher-quality call graph resolution.

**Honest scope assessment:** This tool is a *signal generator for LLM harness
generation*, not a SAST tool. A SAST tool needs near-zero false positives because
a human triages every finding. We need directionally useful signal — the LLM is
the final reasoning layer and can discard implausible findings from context. A 30%
false positive rate is acceptable if it eliminates 70% of the LLM's blind spots.
The codebase-agnostic design constraint means we deliberately do not require
build-system integration; our value is that any `.ll` file works without per-target
engineering.

That said, the LTO transformation gap is real. It is most acute when:
- A function that looks dangerous in per-TU IR is actually inlined into a call
  site that guards it — we see the function as unguarded; it isn't at link time.
- Multiply-defined symbols (already hit in OpenSSL with `--only-needed`) mean
  the IR we analyze may be a different instantiation than what the linker chose.

**Fix:** Accept a pre-linked whole-program `.bc` file as an alternative to a
directory of per-TU `.ll` files. The caller builds with `clang -flto -fuse-ld=lld`
and passes the resulting `.bc` directly. We already use `llvm-link`; the only new
piece is a `--whole-program-ir` input path that feeds the same analysis pipeline
with a single already-merged module. This collapses the callee resolution problem
and eliminates the LTO transformation gap without requiring build-system knowledge.

Building with `-flto` is a one-flag change to a `CFLAGS` environment variable for
autoconf/cmake projects; it is not "integrating with the build system" in the
covscan sense.

**Effort:** Medium — `score_deterministic.py` walks a directory of `.ll` files;
needs a single-file entry path. Analysis logic is unchanged.

**Files:** `llvm_ir_context/score_deterministic.py` (single-module entry path),
`llvm_ir_context/__main__.py` (`--whole-program-ir` flag), `gen_harness.py`
(pass single `.bc` to `llvm-link` rather than a directory)

---

### 4. Adaptive fuzzing loop

**Observation (libarchive LHA run):** Coverage gains required three manual interventions —
seed corpus creation, `-max_len` increase, and dict injection with strcmp-gate tokens
extracted from the slicer output. Each intervention was driven by a recognisable stall
pattern (coverage delta < N over M seconds) and a corresponding lever the slicer already
had the data to suggest.

**Design:** A lightweight `fuzz_loop.py` wrapper that:
1. Launches the fuzzer as a subprocess and tails its output.
2. Detects stalls (coverage delta < threshold over a configurable window).
3. Applies a fixed ladder of levers derived from the slicer summary already available at
   harness-generation time:
   - **Strcmp gates** → generate a libFuzzer `-dict` file from the gate constants
     (`memcmp` / `strcmp` operands emitted by `slice_context.py`).
   - **Max-len** → double `-max_len` (starting from 4096, up to a configurable ceiling).
   - **Corpus seeds** → emit minimal valid seeds whose magic bytes satisfy any format-gate
     constraints (slicer already extracts these for M-13).
   - **Time budget** → extend `-max_total_time` up to a configured ceiling.
4. Restarts the fuzzer with the new lever active and the accumulated corpus preserved.

**LLM lever (optional):** The slicer summary (sink types, gate constants, guard density)
can be fed to the model to suggest lever ordering and seed shape — the model already
reasons about this when generating the harness prompt. Defer until the rule-based ladder
is validated; the ladder covers ≥80% of the value.

**Integration point:** `gen_harness.py` already writes the slicer summary alongside the
harness. `fuzz_loop.py` reads it, no pipeline change required.

**Effort:** Medium — subprocess management, output parsing, lever state machine.
No slicer changes needed; all required signals are already emitted.

**File:** new `fuzz_loop.py`; reads slicer summary JSON from `--output-dir`.

---

### 5. Targeted PoC generation (slicer-driven, no fuzzer)

**Observation (libarchive RAR run):** The slicer's trunc warning already identified
the vulnerable field class and the trigger values (`0xFFFFFFFF`, `0x80000000`,
`0x100000000`). The fuzzer took 91M executions to find the LHA analogue; a
correctly-crafted 57-byte input would have found it in milliseconds. The gap is
knowing *which bytes in the input map to that field* — the IR trace knows this but
the pipeline doesn't yet use it.

**Design:** After scoring and slicing, generate targeted PoC inputs directly from
slicer signals — no fuzzer required for the first pass:

- **Trunc warning** → enumerate the truncation sites; for each, emit one input with
  that field set to `0xFFFFFFFF`, one at `0x80000000`, one at `0x100000000`. Requires
  knowing the byte offset and endianness of the field in the input stream — derivable
  from the IR load instruction that feeds the narrowing cast.
- **Format/strcmp gate** → prepend the required magic bytes / satisfy the literal
  comparisons extracted by the slicer before setting the target field.
- **Double-free / UAF** → emit a two-input sequence: first input allocates the
  resource, second triggers the free path — same structure as M-05 but as a
  concrete byte sequence rather than a harness template.

**Agent loop this enables:**
```
score → ir-context → generate targeted PoCs → replay → crash? → done
                              ↓ no crash in <N inputs
                     run fuzzer bounded (e.g. 30 min)
                              ↓ plateau / no crash
                     conclude "not reachable from this entry point"
                     flag for human if sinks/guard is extreme
```

**The hard part:** Mapping IR load instructions back to input byte offsets requires
either (a) format schema knowledge (external, per-target), or (b) dynamic taint
tracing on a valid input to discover which bytes flow into which loads. Option (b)
is codebase-agnostic but requires instrumented execution, not just static IR.
Option (a) can be LLM-assisted: given the source file and the IR load site, the
model can often identify the struct field and its wire offset.

**Prerequisite:** P2.4 (adaptive fuzzing loop) — the bounded fuzzer fallback is the
same infrastructure.

**Effort:** High. Static field-offset recovery is tractable for simple formats;
the general case requires dynamic taint. Likely a multi-month research item.

**Why it matters:** Converts the pipeline from "find candidates for a human to fuzz"
to "find candidates and prove exploitability automatically." Closes the loop that
LHA demonstrated: scorer found it, slicer named it, fuzzer confirmed it in 30 min.
The targeted PoC step cuts that 30 min to seconds for the trunc/OOM bug class.

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
| **P1.3** Sink expansion: command injection (`system`, `popen`, `execv*`, `posix_spawn` — ×1.30 multiplier) and path traversal (`open`, `fopen`, `unlink`, `rename`, `stat`, `access`, `chmod`, `symlink` + 20 more — ×1.20 multiplier); full `_SINK_INFO` entries with harness hints for all new sinks | `preprocess_slice_pdg.py`, `score_deterministic.py`, `slice_context.py` |
| **P2.2** Format gate detection: `FORMAT_PARSERS` dict (PEM, base64, ASN.1/DER, zlib, JSON, XML, TLS, HTTP families); `_extract_format_gates()` scans call graph; `format_gates` field in slice summary; M-13 prompt module instructs envelope-construction or seed corpus | `preprocess_slice_pdg.py`, `slice_context.py`, `gen_harness.py`, `patterns.md` |
| Prefer direct `.a` compile over IR merge when `--lib` provided: eliminates `--allow-multiple-definition` symbol mixing that caused spurious ASAN crashes; IR merge path retained for closed-source / can't-rebuild scenario | `gen_harness.py` |
| gen_harness UX #1: warn when `--function` matches multiple TUs (ambiguous name) — lists all matches and names the one picked, prompts user to use `--ll` to pin | `gen_harness.py` |
| gen_harness UX #2: allow `--ll` and `--ir-dir` together — `--ll` pins the TU, `--ir-dir` provides the full directory for P-05 caller search; previously mutually exclusive | `gen_harness.py` |
| gen_harness UX #3: BFS transitive P-05 caller search (up to 3 hops) — previously only searched one level up, missing public entry points 2+ hops away (e.g. `read_header` → `archive_read_format_rar_read_header` → `archive_read_support_format_rar`) | `gen_harness.py` |
| **P1.11** Sparse guard ratio score boost: ×1.15 when sinks/guard > 5, ×1.25 when > 10; only fires when guards exist and call sinks are present — pushes high-sink sparse-guard functions from mid-band into top ranks without target-specific tuning | `score_deterministic.py` |
| **P1.1** Wrapper/alias deduplication: BFS from each impl upward through caller_map; pure-delegation callers (no own sinks) and subset-sink callers both marked; chained wrappers (PEM_read → PEM_read_bio → PEM_read_bio_ex) handled; grouped beneath impl in table with └─ | `score_deterministic.py` |
| Sink suffix false-positive fixes: disabled suffix match for strcat/strcpy/sprintf/printf/link/symlink families — archive_strcat, archive_entry_set_nlink etc. no longer flagged as dangerous sinks; exact-name matches unaffected | `preprocess_slice_pdg.py` |
| **P1.12** Write-path / read-path disambiguation: fd-source backward check in `_read_fd_from_arg` — when `read`/`recv`/`pread` fd argument traces to a struct load or global (not a function argument), `is_external_input` is suppressed; drops zisofs_rewind_boot_file (reads from internal temp fd) without any libarchive-specific tuning | `preprocess_slice_pdg.py` |
| **P1.4** Interprocedural arg-slot-level caller guard attribution: `_check_caller_guards` extended to build per-caller SSA tracing infrastructure (`arg_ptr_ids`, `alloca_to_arg`, `instr_by_pid`) and trace each argument passed to the target back to the caller's own arguments; `caller_guarded_args: list[int]` stored through graph→summary pipeline; 0.70× score multiplier fires when any guarded slot matches and the callee receives `function_argument` input; annotation `+caller_guarded:argN` in rank table and "Caller guard: arg-slot" in context output | `preprocess_slice_pdg.py`, `score_deterministic.py`, `slice_context.py` |
