# Ideas and experimental improvements

Possible extensions to the IR slice pipeline. These are not planned work —
they are recorded here so the reasoning doesn't get lost.

---

## Harness IR validation

### The problem

LLM-generated fuzzing harnesses frequently compile and run but don't actually
test what they are supposed to test. Common failure modes:

- **Blank shooters** — the harness never passes `data` or `size` into the
  target function. The fuzzer mutates bytes that have no effect on the target.
- **Self-harm bugs** — the harness itself contains a memory error (e.g., reads
  `data[10]` without checking `size > 10`). The fuzzer crashes immediately on
  the harness, not the target.
- **Ignored constraints** — the slice context said "fuzz n near SIZE_MAX" but
  the LLM hardcoded a small safe constant instead.

Running the fuzzer to discover these failures wastes hours of CPU. The
validation should happen before the fuzzer starts.

### The idea

Compile the LLM-generated harness to LLVM IR and run the existing slicer over
it before fuzzing. The harness is standard C with a `LLVMFuzzerTestOneInput`
entry point — the same `clang -O0 -emit-llvm` pipeline applies.

Three checks, all using existing machinery:

**1. Blank shooter check (data flow)**

Treat the call to the target function as the sink. Run the backward BFS from
it. Check whether `function_argument` appears in `input_channels` — i.e.,
does `data` or `size` from the harness entry point reach the call arguments?
This is exactly what the slicer already computes; the only addition is
treating "call to `inflate`" (or whatever target) as the sink when analysing
harness IR rather than analysing the target itself.

**2. Self-harm check (harness memory safety)**

Run `ir-score` on the harness IR the same way you would on any library. If
the harness has an unguarded GEP (array access without size check) or an
unguarded `memcpy`, the slicer will flag it. A high-scoring vulnerability in
the harness is a bug in the test code, not the target.

**3. Size argument check**

Verify that `size` (the second parameter of `LLVMFuzzerTestOneInput`) reaches
the target call site, not just `data`. A harness that passes `data` but
hardcodes the length to a small constant won't explore the boundary values
identified by the trunc/truncation warnings in the slice context.

### Implementation sketch

**Preferred approach: linked IR.**

Compile the harness and the target library together into a single `.ll` file
rather than keeping them separate:

```bash
# Compile both to IR, then link into one module
clang-20 -O0 -fno-inline -S -emit-llvm harness.c -o harness.ll
llvm-link harness.ll target.ll -o combined.ll -S
```

Then run the slicer on the combined module with the harness entry point as the
function under analysis:

```python
g = ir_to_graph_slice_pdg(combined_ir_text, fn_name="LLVMFuzzerTestOneInput")
summary = summarize_slice(g, fn_name="LLVMFuzzerTestOneInput")
```

Because the target function body is present in the combined IR (not a `declare`
stub), the slicer's backward BFS follows DFG edges all the way from the
dangerous sink inside the target, through the call site in the harness, back to
the `data` and `size` arguments of `LLVMFuzzerTestOneInput`. No custom sink
extension needed — the existing dangerous sink list already covers `memcpy`,
`strcpy`, etc. in the target function.

Checks on the resulting summary:

1. `"function_argument" in summary["input_channels"]` — blank-shooter check.
   If false, `data`/`size` never reach the sink; reject and tell the LLM which
   call argument is disconnected.
2. `philosophy2_score(summary)` above a threshold on the harness IR itself —
   self-harm check. An unguarded array access in the harness body scores high
   and is a bug in the test code.
3. Sink types in `summary["sinks"]` match what the original target analysis
   flagged — confirms the harness is targeting the right code path.

The alternative (compile harness alone, treat target call as a custom sink)
also works but sees only a `declare` stub for the target — enough for the
blank-shooter check but not for tracing through the target's internal data
flow.

### Pipeline position

```
IR slicer  →  LLM writes harness  →  compile harness to IR
                                              ↓
                                    ir-validate-harness
                                         ↙        ↘
                                      FAIL        PASS
                                        ↓            ↓
                              feedback to LLM    run fuzzer
```

Validation is cheap (seconds). Failing fast here avoids the hour-scale fuzzer
CPU cost of a blank-shooter harness.

### Caveats

- Structural check only — same limitations as the main slicer. "Data flows to
  the call" does not guarantee it flows to the *right* argument in the *right*
  way. Value-level correctness (e.g., is SIZE_MAX actually reachable?) is not
  checkable without symbolic execution.
- The linked IR approach requires the target source or IR to be available at
  validation time. When analysing a pre-compiled binary (no source), fall back
  to the stub approach — enough for the blank-shooter check, not for tracing
  through the target's internals.
- Guard presence in the harness is not the same as guard correctness (same
  caveat as the main slicer). A harness with `if (Size < 4) return 0` is
  correct and necessary — don't penalise guards in the harness body, only flag
  unguarded *accesses* in the harness itself.

---

## Interprocedural guard propagation

### The problem

Internal helpers consistently score high because their guards live in the
caller. `lm_init` in zlib has no `icmp` but `deflateInit2_` validates
`windowBits` before calling it. The slicer sees an unguarded function and
ranks it first; a human reviewer sees `+caller?` and deprioritises it.

The current mitigation (`+caller?` annotation, scoring down `external_call_return`
vs `function_argument`) is a heuristic. It works on scarnet but produces
noise in the zlib ranking (rank 1 is `lm_init`, not a real target).

### The idea

When `caller_validated` is true and all input channels are
`external_call_return` (no direct `function_argument`), apply a moderate score
reduction — say 0.70× — to reflect that an upstream guard probably exists.
The reduction should not be too aggressive: the guard in the caller may protect
a different parameter, not the one that reaches the sink.

### Caution

This requires understanding which caller's `icmp` guards which argument of
which call. The current `caller_validated` flag only checks whether *any*
caller of this function contains *any* `icmp` — too coarse to be authoritative.
Implementing this correctly requires tracking which argument slot the guard
comparison feeds, which is a meaningful extension to the cross-file caller
scan in `score_deterministic.py`.

---

## Patch re-validation via slicer

### The problem

LLMs asked to fix a vulnerability sometimes produce patches that are
structurally wrong in non-obvious ways: replacing `memcpy` with a hardcoded
safe response, deleting the check rather than adding it, or adding a guard
that compares the wrong variable. Standard test suites don't catch this —
the code compiles, functional tests pass, and the patch looks plausible in a
diff. The only way to know the vulnerability is actually gone is to re-analyse
the patched code structurally.

### The idea

After an LLM produces a patch, compile the patched function to IR and re-run
the slicer on it. Compare the new summary against the original:

- If the original had `guard_type="none"` and the patch still has
  `guard_type="none"` for the same sink — the patch didn't add a guard.
  Reject and tell the LLM which sink is still unguarded.
- If the original had a `trunc` warning and the patch still does — the
  narrowing wasn't addressed.
- If the sink count dropped to zero — the LLM may have deleted the
  functionality rather than fixing it. Flag for human review.
- If `guard_type` changed to `bounds_check` and guard density is reasonable —
  the patch structurally addressed the issue.

The feedback to the LLM is concrete and tool-derived, not a vague "try again":
`"Patch rejected: memcpy in do_inflate still has no icmp guard in its slice.
The size argument still originates from function_argument with no bounds check."`

### Why this is tractable

We already have all the machinery. The only new piece is a diff between two
`summarize_slice` outputs on the same function name — before and after the
patch. No new analysis, no new sinks, no new pass manager. The comparison
logic is a handful of conditionals.

### Caveats

- Same intra-procedural blind spot as the main slicer. A patch that moves the
  guard into a wrapper function will look unguarded here even if it's correct.
- Deletion of the sink (function removed or renamed) is ambiguous — it could
  be a correct refactor or a cop-out. Human review is the right gate for that
  case, not automated rejection.
- This validates structural pattern, not semantic correctness. A guard that
  compares the wrong variable (`if (src_len < limit)` when `dst_len` is what
  matters) looks identical to a correct guard in the IR slice.

---

## Harness quality: strcmp guards block fuzzer coverage

### The problem

When a target function has a hardcoded credential check early (e.g.,
`strcmp(pass, "scarnet123") == 0`), libFuzzer's random mutations never flip
that branch. Coverage freezes, and the real bug downstream (e.g., a
null-terminator-less `memcpy` into a fixed-size buffer) is never reached.

`session_login` in scarnet demonstrates this exactly: the fuzzer ran 10,000
rounds at `cov: 9 ft: 10` — flat from start to finish — because the strcmp
exit path never opened up.

### Two complementary improvements

**1. String literal extraction for fuzzer dictionaries**

LLVM IR contains all hardcoded string constants as global `@.str` symbols:

```llvm
@.str.1 = private unnamed_addr constant [11 x i8] c"scarnet123\00"
```

The slicer already reads IR text. A post-pass that extracts string constants
reachable in the backward slice and emits a `.dict` file would give libFuzzer
the tokens it needs to flip strcmp branches. Implementation: walk `@.str*`
globals referenced in the slice function body, decode the byte array, write
to `<fn_name>.dict`. Low effort, high payoff for credential-checking targets.

**2. Strcmp guard hint in slice_context.py**

Higher value than a dictionary: when the slicer detects an `icmp` guard fed
by a `call @strcmp` (or `@strncmp`, `@memcmp`) with a known global string
argument, emit a harness hint: "argument `X` is gated by a strcmp against the
literal `"scarnet123"` — hardcode that value and fuzz only the other
arguments." This is the same mechanism as the `trunc` hint already in
`slice_context.py`: a structural IR observation → concrete harness guidance.

A harness that hardcodes `pass = "scarnet123"` and fuzzes only `user` would
have found the `memcpy` null-terminator bug in scarnet in milliseconds.

### Detection sketch

In the backward slice, look for an `icmp` node whose operands include:
1. A `call` to `strcmp`/`strncmp`/`memcmp`
2. One argument of that call is a `getelementptr` into a `@.str` global

When both conditions hold, record the literal value and which argument index
holds the constant — that's the argument to hardcode in the harness; the other
argument is the one to fuzz.

### Caveats

- Only detects direct strcmp against a string constant. Indirect comparisons
  (hash check, custom equality function) are not visible in the IR slice.
- The extracted literal is the expected value in the one function; other
  callers may use different credentials — the hint is function-scoped.

---

## Harness quality: split-input pattern for alloc+copy functions

### The problem

`scar_alloc_copy(const char *s, size_t len)` has an unguarded `memcpy(buf, s, len)`
that the slicer correctly flags. But the harness Qwen generates is:

```c
scar_alloc_copy((const char *)Data, Size);
```

libFuzzer guarantees `Data` is exactly `Size` bytes, so `memcpy` always reads
within bounds. Coverage hits 5 counters — every reachable branch — and stays
flat for 10,000 runs. The slicer was right about the risk; the harness is
wrong about how to exercise it.

The vulnerability is a **caller-side API misuse bug**: `len` exceeds the actual
allocation of `s`. This class of bug cannot be triggered by calling the function
with a matching `(data, size)` pair. It requires the harness to deliberately
create a mismatch.

### The split-input pattern

For alloc+copy functions where the dangerous call is `memcpy(buf, s, len)`:

```c
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;
    // First byte controls source buffer size; remaining bytes are copy length
    size_t s_len    = (Data[0] % 64) + 1;
    size_t copy_len = Size - 1;
    char *s = malloc(s_len + 1);
    if (!s) return 0;
    memcpy(s, Data + 1, s_len < Size - 1 ? s_len : Size - 1);
    s[s_len] = '\0';
    scar_alloc_copy(s, copy_len);   // copy_len >> s_len → heap OOB read
    free(s);
    return 0;
}
```

`copy_len` grows with `Size`; `s_len` is bounded to 64. libFuzzer quickly
finds inputs where `copy_len > s_len`, which are the inputs that trigger the
heap read overflow ASAN would catch.

### How to detect this case in the slicer

The split-input pattern is appropriate when:
1. The function takes two parameters — a buffer pointer and a length
2. The dangerous sink (`memcpy`, `strcpy`) uses the length parameter
3. The length parameter is the `function_argument` source (not derived from
   the buffer itself via `strlen` or similar)
4. There is no guard comparing the length against an allocation or buffer size

When all four hold, the slice context hint should say: "split input — derive
`len` from one region and `s` from another so they can diverge; use a small
fixed-size `s` (e.g., 64 bytes) and let `len` be fuzzed freely."

### Three coverage-flatness root causes now documented

| Root cause | Example | Fix |
|---|---|---|
| Credential strcmp gate | `session_login` (strcmp vs "scarnet123") | Literal extraction → dict or hardcode-arg hint |
| API misuse only triggerable by caller | `scar_alloc_copy` (len vs s allocation) | Split-input harness pattern hint |
| Internal helper (no public entry) | `lm_init` | Header-aware auto-pick (already implemented) |

---

## Harness generation — zlib trunc targets

A concrete experiment enabled by the current pipeline: generate a fuzzing
harness for `inflate` or `inflateBack` (ranks 2–3 in the zlib `--no-gep-only`
output, both `+trunc` with unguarded `memcpy`).

The slice context for these functions already specifies:
- Sink: `memcpy` — copies n bytes, no bounds check
- Trunc warning: integer narrowing — supply values near `INT_MAX` / `UINT32_MAX`
- Harness target: fuzz `avail_in` near integer width boundaries

A harness that sets `z.avail_in` to values near `0xFFFFFFFF`, feeds a
corresponding compressed stream, and calls `inflate()` in a loop would be the
correct output. The harness IR validation check above would confirm:
- `data` and `size` from `LLVMFuzzerTestOneInput` reach `inflate`'s arguments
- The harness itself has no unguarded array accesses

zlib has been in OSS-Fuzz for years so a new bug is unlikely. The value of
this experiment is validating that the pipeline produces a correct, targeted
harness without hand-holding — not breaking zlib.
