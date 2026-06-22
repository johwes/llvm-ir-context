# Design Goals

Core principles for llvm-ir-context. Read this before adding any feature.

---

## What this tool is

A translation layer between a SAST tool and an LLM.

The SAST side (IR slicer, score_deterministic.py) extracts structural facts
from LLVM IR: where dangerous sinks are, what guards are present, where input
originates, which comparison patterns gate which code paths. These facts are
deterministic and codebase-agnostic.

The LLM side (gen_harness.py) receives those facts as a structured prompt
block and generates harness code. The LLM is treated as a system with known
failure modes that can be engineered around deterministically.

The translation layer's job is to pre-compute the hard analysis step so the
LLM only has to do the easy step: generate code from a specification rather
than reason about data flow itself.

---

## Design goals

### 1. Generic — works on any C codebase

The tool must produce useful output for any C project without configuration,
training data, or prior knowledge of the target.

**What this means in practice:**
- Hints describe structural IR patterns, not domain concepts
- No codebase-specific literals, protocol names, or assumed call sequences
  in the hint emitter
- If a hint would only make sense if you already knew the target, it is wrong

**Where domain reasoning belongs:** In the LLM, guided by the function
signature and API reference. The slicer tells the model *what* the shape is;
the model figures out *what to do about it* given the API.

**The test:** Does this hint produce a correct harness on a codebase the
authors have never seen? If not, it is too specific.

### 2. Bidirectional translation

The pipeline translates in both directions:

- **Outbound (SAST → LLM):** Summarises structural findings into a prompt
  block the LLM can act on without re-analysing the IR.
- **Inbound (LLM failure modes → hints):** Encodes known LLM failure modes
  as explicit harness hints so the model does not need to rediscover them.

Known LLM failure modes currently handled (see `patterns.md`):
- strcmp credential gates → fuzzer never flips the branch (P-01)
- strcmp routing gates → fuzzer hardcodes one handler, misses others (P-02)
- matching (ptr, len) → libFuzzer guarantee prevents OOB (P-03)
- integer truncation → model adds safety caps that prevent the bug (P-04)

### 3. Structural facts, not conclusions

The slicer emits facts. The LLM draws conclusions.

| Slicer emits | LLM concludes |
|---|---|
| "strcmp on param 0 across 6 literals" | "AUTH must come first to initialize session" |
| "memcpy with function_argument as length" | "I need to split Data into src and len regions" |
| "trunc i64 to i32 before malloc" | "I should fuzz values near UINT32_MAX" |

If the slicer is emitting conclusions ("call AUTH first"), it has taken on
reasoning that belongs to the LLM. This makes hints brittle and
target-specific.

### 4. The ranking output is a pre-filter, not a verdict

`ir-score` ranks functions by local vulnerability signal. It is a triage
tool — it surfaces candidates worth fuzzing. It does not replace human
review or a full taint analysis.

The score is calibrated for **precision as a pre-filter**: a high score
should reliably mean "worth generating a harness for", even if recall is
imperfect (some true vulnerabilities rank low). See `ROADMAP.md` for known
ranking blind spots (interprocedural sinks, latent write-then-read bugs).

### 5. Harness correctness is measurable

A generated harness is correct or not against a concrete rubric (see
`patterns.md § Evaluation rubric`). The rubric is the ground truth —
not whether the harness "looks reasonable". If it doesn't find the bug
under 50k runs with ASAN, it failed regardless of how clean it looks.

---

## The intended workflow: fuzz → repair → fuzz

The pipeline is designed for an iterative loop, not a single-shot run.

```
ir-score                    → rank functions by vulnerability signal
gen_harness.py              → generate harness for top candidate
fuzzer                      → find crash (or confirm clean)
  ↓ crash found
LLM repair                  → generate patch for the confirmed bug
slicer re-validation        → diff summarize_slice before/after patch;
                              reject if guard_type still "none" for same sink
recompile + re-fuzz         → run same harness against patched binary
  ↓ no new crash
move to next ranked target
```

**Why iteration matters — the masking problem:**

Shallow bugs block discovery of deeper bugs. When a function has multiple
vulnerabilities, libFuzzer finds the easiest-to-reach one and stops. The
deeper bug is never explored.

Concrete example from scarnet:
- `handle_stats` divide-by-zero: reachable with 1-byte input `\012` (STATS
  verb, empty store). Found immediately.
- `handle_del` double-free: requires SET then DEL with the same key — a
  two-call sequence. Masked by the divide-by-zero; never reached.

Trying to solve this with a smarter single-call harness (P-07) is the wrong
approach. The right solution is the repair loop:

1. Fuzzer finds `handle_stats` div-by-zero
2. Repair loop patches it (add `nstore == 0` guard)
3. Slicer validates patch — `sdiv` no longer reachable from unguarded input
4. Fuzzer runs again — div-by-zero path closed, coverage opens into DEL path
5. Fuzzer finds `handle_del` double-free
6. Repeat until fuzzer runs clean or no unguarded sinks remain

**The slicer's role in the repair loop:**

The slicer validates each patch structurally — not by re-running the fuzzer,
but by checking whether the IR slice for the patched function still shows an
unguarded sink. This catches:
- Incomplete patches (guard added but wrong condition)
- Deleted functions (sink count drops to zero — suspicious, flag for review)
- Regressions (new sink introduced by the patch)

This is P1.3 in `ROADMAP.md` — not yet implemented, but the machinery exists:
`summarize_slice` before and after the patch, diff `guard_type` and `n_sinks`.

**What this means for harness design:**

A harness does not need to be stateful or multi-step. It just needs to reach
the target function's entry with fuzz-controlled input. The repair loop handles
the sequencing across bugs — the fuzzer handles the sequencing within a run.

The only case where a multi-step harness is genuinely needed is when two bugs
are in the same function and one masks the other within a single call — which
is rare. For interprocedural masking (bug in callee A masked by bug in callee B
of the same dispatcher), the repair loop is always the right answer.

---

## What this tool is not

- **Not a full taint analysis.** We follow 1 hop up to the caller for guard
  context. Cross-function data flow beyond that is out of scope.
- **Not a Joern/CodeQL replacement.** Those tools build full program graphs.
  We work directly from LLVM IR for portability and simplicity.
- **Not an LLM-only approach (TitanFuzz, FuzzGPT).** Those ask the model to
  reason about vulnerability from source. We give the model pre-computed
  structural facts and use it only for code generation.
- **Not a raw SAST→LLM pipeline (OSS-Fuzz-Gen, CodeQL+LLM).** Those pass
  raw SAST output and let the model interpret it. We encode LLM failure modes
  explicitly and correct for them before the model sees the prompt.

---

## Boundary rules for contributors

When adding a new hint or modifying an existing one, check:

1. **Is the hint text codebase-agnostic?** Remove any literal names,
   protocol-specific verbs, or assumed call sequences.
2. **Is it a structural fact or a conclusion?** If it tells the LLM *what
   to do* beyond the pattern, push that reasoning into the system prompt's
   general rules instead.
3. **Is there a pattern entry in `patterns.md`?** Every hint must correspond
   to a documented pattern with an IR shape, hint spec, and correct-harness
   definition. Add the pattern entry first, then implement.
4. **Does the evaluation rubric cover it?** If the rubric can't tell whether
   a harness handles this pattern correctly, extend the rubric.
