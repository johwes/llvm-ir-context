# Harness Pattern Taxonomy

Reference spec for the IR slicer → context hint → harness pipeline.

For each pattern: the IR shape the slicer must detect, the hint the context
block must emit, and what a correct harness must do. Use this as the
evaluation rubric: a generated harness is correct if and only if it satisfies
the "Correct harness" column.

---

## P-01 · Credential gate

**What it is:** A single strcmp/strncmp call compares one function argument
against a hardcoded string literal. Failing the check causes an early return
before any dangerous sink.

**IR shape:**
- `call @strcmp` (or strncmp/memcmp/strcasecmp) with one operand a
  `getelementptr` into a `@.str` global
- The call result feeds an `icmp` that dominates a branch guarding the sink
- One strcmp call; one literal; one function argument is the non-const operand

**Hint (slice_context.py must emit):**
```
strcmp gate: `strcmp` against "LITERAL" — hardcode "LITERAL" as the constant
argument; pass Data (as a null-terminated copy) into parameter N of `fn`
(the non-constant argument)
```

**Correct harness:**
- The gated argument is hardcoded to the literal value
- The other argument(s) receive fuzzed Data
- The fuzzer can reach the sink on every run

**Status:** Implemented. `fuzz_fn_arg_idx` traces the non-const operand
through the -O0 alloca chain back to the function parameter index.

**Known gap:** Does not yet emit a `.dict` file with the literal for libFuzzer.

---

## P-02 · Routing gate

**What it is:** Multiple strcmp calls compare the **same function argument**
against **different literals**, each selecting a different code path. This is
a command/verb dispatcher, not a credential check.

**IR shape:**
- N strcmp calls (N ≥ 2) all reading the same function argument (same
  `fuzz_fn_arg_idx`)
- Each call feeds an independent `icmp eq` branch
- Literals are all different (verb strings: "AUTH", "SET", "GET", …)

**Hint (must emit):**
```
command router — verb must be one of: "AUTH", "SET", "GET", "DEL", "STATS",
"FRAG"; initialize state before calling and randomize verb from this set
```

**Correct harness:**
- Picks a verb from the detected set (randomly or by splitting fuzz input)
- Does NOT hardcode a single verb (that only exercises one handler)
- If one verb is an auth/init step, calls it first with fixed credentials,
  then randomizes the subsequent verb

**Status:** NOT implemented. Current code treats all strcmp-against-literal
as credential gates and hardcodes the first literal found. Observed failure:
`dispatch` harness hardcoded verb="AUTH", never reached handle_del or
handle_stats.

**Detection:** same `fuzz_fn_arg_idx` across ≥ 2 strcmp_guards entries →
routing gate, not credential gate.

---

## P-03 · Split-input / (ptr, len)

**What it is:** Function takes a buffer pointer and a separate length. Calling
it with `(Data, Size)` never triggers OOB because libFuzzer guarantees Data
is exactly Size bytes. The bug is caller-side API misuse: len larger than the
actual allocation.

**IR shape:**
- Dangerous sink (memcpy/memmove/memset) uses a `function_argument` as the
  length operand
- A separate `function_argument` is the source pointer
- Guard is `none` or `null_check` only (no bounds comparison of len vs
  allocation size)

**Hint (must emit):**
```
split-input pattern required: use first N bytes of Data as the source buffer
(fixed small size, e.g. 64 bytes), derive len from the remaining bytes so
source and length can diverge; do not call with matching (Data, Size)
```

**Correct harness:**
- Source buffer is a fixed-size region (not Size)
- Length is derived independently from a different fuzz region
- The two can diverge so len > sizeof(source) is reachable

**Status:** Implemented. Fires when guard_type in ("none", "null_check") and
arg_count >= 2 and buffer-write sink uses function_argument as length.

---

## P-04 · Integer truncation

**What it is:** A wide integer (i64/i32) function argument is truncated to a
narrower type (i16/i8) before being used as a size or index. Values above
the truncation threshold wrap to small/negative, causing OOB or logic errors.

**IR shape:**
- `trunc iN %arg to iM` node in the slice (N > M)
- Result used as operand to a dangerous sink (memcpy len, array index, alloc
  size)

**Hint (must emit):**
```
integer truncation: fuzz values at and above the truncation boundary
(e.g. 0x100, 0x8000, 0x10000); do not artificially bound the output buffer
```

**Correct harness:**
- No `if (Size > 1024) return 0` or similar cap
- Exercises values that cross truncation boundaries

**Status:** Implemented.

---

## P-05 · Interprocedural sink (danger in callee)

**What it is:** The ranked/target function is a dispatcher or thin wrapper.
Its own body is safe (routing logic, snprintf responses). The dangerous sinks
are one call level down in internal helpers.

**IR shape:**
- Target function has many call sites to sub-functions
- Sub-functions contain the actual dangerous sinks
- Target function's own slice score is low (few direct dangerous ops)

**Scoring impact:** Target ranks low (dispatch: #18 at 28%) despite being the
correct public entry point. Internal helpers rank high but are not directly
fuzzable.

**Hint:** No direct hint needed — the harness should target the dispatcher.
The ranking problem is: how do we surface the dispatcher as the right target?

**Correct harness:**
- Targets the dispatcher, not the internal helper
- Drives the dispatcher through enough states to reach dangerous callees

**Status:** NOT implemented. Current ranking is purely local to the function's
own IR slice. Cross-callee sink aggregation not yet built.

**Proposed fix (P1):** When scoring, if a function's callees contain
unguarded sinks, propagate a fraction of that score up to the caller. Weight
by whether the callee is reachable from a public-API function argument.

---

## P-06 · Latent / interprocedural write-then-read

**What it is:** A function writes to a shared struct field without a null
terminator (or similar). The bug only manifests when a *different* function
later reads that field as a string. Single-function harness never crashes.

**Example:** `session_login` fills `sess->username` without null terminator.
Bug fires when a caller reads `sess->username` via `strlen`/`printf`/`strcmp`.
Current scarnet code never reads it back, so the bug is dormant.

**IR shape:** Detectable via write-without-terminator pattern in one function
+ string-read of same field in another. Requires cross-function field tracking
— beyond current 1-hop caller analysis.

**Correct harness:**
- Calls the writer (session_login) then the reader in sequence
- Multi-step harness, not single-function

**Status:** NOT implemented. Out of scope for current 1-hop analysis.
Documented here as a known blind spot.

---

## Evaluation rubric

Given a generated harness, mark it:

| Check | Pass condition |
|---|---|
| Compiles | `clang -fsanitize=fuzzer,address` succeeds |
| Not blank-shooter | `ir-score` on harness IR shows `function_argument` in input_channels |
| Gate handled | If P-01 gate: literal hardcoded. If P-02 gate: verb randomized. |
| No artificial caps | No `if (Size > N) return 0` |
| Correct API | Function called with correct number and type of arguments |
| Finds bug | Running 50k iterations crashes with ASAN report |

A harness that passes the first five but fails the last is a pipeline gap
worth documenting — the slicer context was insufficient to guide the model
to the actual vulnerability.
