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

A ~50-line addition to `score_deterministic.py` (or a new `ir-validate-harness`
CLI entry point) that:

1. Accepts the harness `.ll` file and the target function name as arguments
2. Runs the existing `ir_to_graph_slice_pdg` with the target call treated as
   the sink (may require a small extension to accept a custom sink name)
3. Checks `input_channels` for `function_argument`
4. Runs `philosophy2_score` on the harness IR itself and warns if anything
   scores above a threshold (self-harm check)
5. Returns pass/fail + structured reason so the orchestration layer can loop
   back to the LLM with specific feedback

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
- The harness likely calls into a compiled library rather than containing the
  target function definition. The slicer will see a `declare` stub for the
  target. That is enough to detect whether arguments flow into the call site —
  the actual body is not needed for the blank-shooter check.
- Guard presence in the harness is not the same as guard correctness (same
  caveat as the main slicer).

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
