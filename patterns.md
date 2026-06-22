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

**What it is:** A high-scoring function is not directly fuzzable because it
is an internal helper — not in the public header. The dangerous sink is in
this function but the fuzzer entry point must be its caller. The caller may
itself be low-scoring locally because its own body is safe routing logic.

**Concrete example (scarnet):**
- `handle_del` ranks #11 at 60% — double-free detected in its body
- `handle_del` is not in `scarnet.h` — not directly fuzzable
- `dispatch` is in `scarnet.h` but ranks #18 at 28% — its own body is safe
- Correct target: `dispatch`, exercising the DEL path to reach `handle_del`

**IR shape (callee — the vulnerable function):**
- High local score with real sink (double-free, OOB write, etc.)
- Not present in the public header

**IR shape (caller — the harness entry point):**
- Present in the public header
- `caller_names` in the callee's slice summary names it (already tracked)
- May have a routing gate (P-02) that must be navigated to reach the callee

**Prompt shape needed:**
```
## Static analysis — vulnerable function: handle_del
<IR slice context for handle_del — shows the double-free>

## Vulnerable function (C source)
<handle_del body>

## Caller / harness entry point: dispatch
<dispatch C source>

## Task
Write a harness targeting `dispatch` that drives it through the path
that reaches `handle_del` to trigger the identified vulnerability.
```

This is a different prompt structure from the 1:1 case. The model sees the
bug location (callee) and the entry point (caller) separately, and must
reason about how to connect them.

**Correct harness:**
- Entry point is the caller (public API function)
- Exercises the specific path through the caller that reaches the callee
- Handles any gates on that path (auth, routing, etc.)

**Status:** NOT implemented. Requires three new pieces:

**1. Detection (score_deterministic.py or gen_harness.py):**
- After ranking, for each function not in the header, check if it has a
  high score and a known caller that IS in the header
- Signal: `not fn_in_header(fn, header) and score >= threshold
  and caller_names non-empty and any caller in header`

**2. Caller resolution:**
- `caller_names` is already populated by the cross-file caller scan (task #11)
- Need to pick the best caller: prefer the one that is in the header;
  if multiple, prefer the one with the most direct path to the callee

**3. Prompt assembly (gen_harness.py):**
- Run `summarize_slice` on the callee → gets the vulnerability context
- Run `extract_fn_source` on both callee and caller C source
- Build the two-section prompt above
- Set the harness target to the caller, not the callee
- If caller has a routing gate (P-02), include that context too

**Ranking fix (score_deterministic.py):**
- When a non-public function scores high, propagate a weighted score
  fraction to its public caller so the caller surfaces in `--top-k` output
- Weight: caller_score_boost = callee_score × 0.6 (caller inherits danger
  but is one step removed)
- Only apply when the callee is not in the header and the caller is

**Implementation order:**
1. Detection + prompt assembly in gen_harness.py (highest value, no ranking change)
2. Score propagation in score_deterministic.py (surfaces the right target automatically)

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

## P-07 · Stateful / multi-step bug

**What it is:** The vulnerability requires a specific sequence of calls to
reach. A single-call harness can never trigger it because the precondition
must be established by a prior call.

**Concrete example (scarnet):**
- `handle_del` double-free: `log_key` freed on match inside the loop, then
  freed again unconditionally. Requires: SET a key → DEL the same key.
- A single-call harness with an empty store never finds a match — the loop
  body never runs — so the double-free is unreachable.
- Masked by shallower bug: `handle_stats` divide-by-zero crashes on input
  `\012` (STATS verb, nstore=0) before the fuzzer explores DEL at all.

**IR shape (detection signals):**
- Double-free or use-after-free detected in the slice (`double_free=True`)
- The freed pointer originates from a prior allocation that must be seeded
  via a different code path (different verb, different call)
- Coverage stays flat because the precondition branch is never taken

**The masking problem:**
When a shallow bug (few instructions from entry, small input space) coexists
with a deeper stateful bug, libFuzzer always finds the shallow one first and
stops. The stateful bug is effectively invisible without a targeted harness.

**Correct harness:**
- Multi-step: call a setup function first to establish precondition state
- Then fuzz the triggering call with state already in place
- Harness must understand the state model — which call creates the resource
  that the vulnerable call then mishandles

**What the pipeline must do:**
The slicer already detects the double-free (`double_free=True` in the slice
summary). What's missing is translating that into a multi-step harness hint.

**Hint (not yet implemented):**
```
double-free detected: this bug requires a prior call to establish the
resource that is freed twice. Identify which call creates the freed pointer
and call it first to seed the state before fuzzing the vulnerable path.
```

**Prompt shape needed:**
```
## Static analysis — vulnerable function: handle_del
<IR slice context showing double_free=True>
<handle_del C source — shows log_key freed twice>

## Caller / harness entry point: dispatch
<dispatch C source — shows SET populates store, DEL reads it>

## Task
The double-free in handle_del requires a key to exist in the store before
DEL is called. Call dispatch with SET first (hardcoded key), then call
dispatch with DEL on the same key to trigger the double-free.
```

**Status:** NOT implemented as an automatic hint. Manually confirmed:
- `handle_del` double-free: ASAN crash on 2nd input with SET→DEL harness
- Crash input: `\254\012` (2 bytes)
- The pipeline detected `double_free=True` in the slice but did not generate
  the multi-step harness automatically

**Implementation path:**
1. In `slice_context.py`: when `double_free=True`, emit a hint naming the
   setup step — requires identifying which public function creates the resource
   (cross-function analysis, harder than 1-hop)
2. In `gen_harness.py`: when the hint says "double-free requires prior call",
   include both the setup function source and the target function source, and
   instruct the model to call setup first
3. Short-term workaround: the P-05 two-section prompt already gives the model
   `dispatch` source — a smarter model might infer the SET→DEL sequence if
   the hint says "double-free detected, establish precondition first"

---

## P-08 · Structured-input / format-validated sink

**What it is:** A function whose input channel passes through a format-validation
check before any dangerous sink is reachable. Random bytes fail the header check
and the function returns an error code immediately. Coverage stays flat regardless
of how many runs the fuzzer does.

**Concrete example (zlib):**
- `inflate` validates the zlib magic bytes and checksum in the first two bytes.
  Random input → `Z_DATA_ERROR` in ~5 instructions. No decompression logic reached.
  Coverage: cov:5 after 50k runs with and without seed corpus.
- `inflate` also uses a streaming call model: it returns `Z_BUF_ERROR` when
  `avail_out` exhausts. A single-call harness that doesn't refill `next_out`
  never advances past the first output page even with valid input.

**IR shape (detection signals):**
- Input flows through an `icmp` against a small set of constants (magic byte check)
  near the function entry — before any memcpy/GEP sink
- The check is on a field offset 0–2 of the input buffer (header bytes)
- `external_call_return` feeds a struct pointer that is then passed to the sink
  (the state object initialized by `inflateInit`)

**Two sub-patterns:**

### P-08a · Magic-byte / header validation gate
The function rejects input that doesn't match a format header.
libFuzzer discovers valid headers quickly with a seed corpus, but without one
the fuzzer is blind.

**What the pipeline must do:**
- Detect: `icmp` near entry against small integer constants, operand is a load
  from input-buffer offset 0 or 1
- Hint: "provide a seed corpus containing at least one valid `<format>` stream;
  without a seed the fuzzer cannot reach any decompression logic"
- Optionally: emit a `.dict` file containing the magic bytes

**Status:** NOT implemented. Seed corpus generation is out of scope for the
current pipeline (no output file path knowledge). The hint is implementable
— detecting a header-byte icmp near entry is a 1-hop check.

### P-08b · Streaming / incremental-call pattern
The function is designed to be called in a loop: it processes as much input as
`avail_in` / `avail_out` allows and returns a status code indicating more work
is needed. A single-call harness never processes a complete stream and therefore
never reaches deep decompression state.

**What the pipeline must do:**
- Detect: function returns a status integer; the sink is inside a loop controlled
  by that return value; the function takes `(state_ptr, flush_flag)` shape
- Hint: "this function is streaming — call it in a loop until return value
  indicates completion or error; refill `next_out` / `avail_out` each iteration"

**Status:** NOT implemented. Detecting the streaming pattern requires recognising
the return-value-as-loop-condition shape — feasible but not yet implemented.

**Short-term workaround:** For known streaming functions (inflate, deflate),
the C source injection (`--src-dir`) gives the model enough context to
write a loop if it reads the source carefully. The inflate harness above did NOT
do this — it called inflate once and exited. Providing source for streaming
functions should be mandatory for this pattern.

**Correct harness:**
- Provides seed corpus entry with valid format header
- Calls the function in a loop, refilling output buffer each iteration
- Terminates on `Z_STREAM_END` or error return

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
