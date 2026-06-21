# Context enrichment design

How the IR slice pipeline works, why it was built this way, what it can and
cannot do, and where it fits in the SCAR harness generation workflow.

---

## The problem it solves

LLM-based harness generation works well when the model knows three things:

1. Which function is worth fuzzing
2. What the dangerous operation is and why it's reachable
3. What input values are likely to trigger a bug

Without pre-computed structural context, a small model spends most of its
token budget on step 1 and 2 — reading source, tracing data flow, identifying
sinks — and has little capacity left for step 3. The output is a generic
harness that covers the happy path but misses the specific boundary condition
that matters.

The slice pipeline offloads steps 1 and 2 deterministically. The model only
has to do step 3: write code from a specification.

---

## Why LLVM IR

Source code is ambiguous. Macros expand in non-obvious ways, typedefs hide
sizes, `#ifdef` chains change behaviour per build target. LLVM IR is the
canonical post-preprocessing, post-macro-expansion representation — what the
compiler actually sees. Several properties make it the right layer to work at:

**Explicit types and sizes.** Every integer operation has a concrete bit width.
`i64` vs `i32` vs `i16` are distinct. A narrowing from `i64` to `i32` (a
`trunc` instruction) is visible and unambiguous — no inference required.

**Explicit data flow.** IR is in SSA form: every value has exactly one
definition, and every use names that definition. The data flow graph is a
first-class object, not something to reconstruct from variable names and
pointer aliasing heuristics.

**Explicit control flow.** Basic blocks and branch instructions are visible.
A comparison (`icmp slt`) that guards a memory operation is a graph edge, not
something to infer from indentation or brace structure.

**Compiler-normalised.** Platform differences, calling conventions, and ABI
details are resolved. `strcpy` compiled with FORTIFY_SOURCE becomes
`__strcpy_chk` in IR — we normalise these back, but the point is that the IR
reflects what actually executes, not what the programmer wrote.

**Independent of source availability.** Once compiled, the IR can be analysed
without the original `.c` files. Useful when SCAR operates on pre-compiled
targets.

The trade-off: IR is verbose and loses some high-level semantic information
(variable names, comments, some type annotations). That is acceptable because
we extract structural facts that don't depend on names.

---

## How the backward slice works

The slicer answers one question per function:

> Does a value derived from external input reach a dangerous sink without
> passing through a bounds-checking comparison?

### Step 1 — identify dangerous sinks

A dangerous sink is any IR instruction that can cause memory unsafety if its
arguments are attacker-controlled:

- **Call-based:** `memcpy`, `strcpy`, `malloc`, `recv`, `sprintf`, and ~30
  others (plus their `__foo_chk` FORTIFY_SOURCE variants)
- **Instruction-based:** `getelementptr` with a non-constant index (array
  subscript that can go out of bounds), `alloca` with a non-constant size
  (variable-length stack allocation)

### Step 2 — build the PDG backward slice

From each sink node, the slicer walks backwards through two edge types:

- **DFG edges** (data flow): the value used by the sink was produced by some
  earlier instruction — follow its definition chain back to the function
  boundary
- **Control dependence edges**: the basic block containing the sink only
  executes if some earlier branch condition is true — include that condition
  and its operands

The result is the **program dependence graph (PDG) slice**: the minimal
subgraph of the function that can influence whether and how the sink executes.
Nodes outside this slice are irrelevant to the vulnerability question.

### Step 3 — check for guards

A guard is an `icmp` (integer comparison) instruction in the slice. Two kinds:

- **Bounds check** — relational comparison (`slt`, `ule`, `sgt`, etc.) — this
  is what actually protects buffer writes. If the size passed to `memcpy` is
  compared against the destination buffer capacity before the call, a bounds
  check is present.
- **Null check** — equality comparison (`eq`, `ne`) — protects pointer
  dereferences but does not protect buffer writes. A function that checks
  `if (ptr == NULL)` before calling `memcpy(ptr, src, user_len)` has a null
  check but no bounds check on `user_len`. This is a common false-security
  pattern.

Guard density (sinks per guard) measures how well guards cover the slice. One
guard for 40 sinks is structurally different from one guard per sink.

### Step 4 — detect integer truncation

A `trunc` instruction narrows an integer to a smaller type. When a `trunc`
appears in a slice that contains a size-taking sink (`memcpy`, `malloc`,
`recv`, etc.), it is a precursor pattern for truncation vulnerabilities: a
value computed as 64-bit (e.g., a decompressed stream length) is narrowed to
32-bit before being passed as the size argument. The truncated value can wrap
to a small positive number, making the sink believe it has a small, safe input
when the actual data is much larger.

This is checked before the guard logic because truncation is suspicious
regardless of whether other guards exist — the guards may protect pointer
validity (null checks) while leaving the truncated size unchecked.

### Step 5 — identify input sources

The slice is annotated with where input originates:

- **`function_argument`** — a value flows from a parameter of the function
  being analysed. Direct attack surface if the function is externally callable.
- **`external_call_return`** — a value flows from the return of an external
  function (a struct field read, a call to `recv`, etc.). Indirect attack
  surface — the value was set by something outside this function.
- **`is_external_input`** — specifically, a known input-source function
  (`recv`, `read`, `fgets`, etc.) appears as a mock node in the slice. Network
  or user data demonstrably reaches the sink.

`function_argument` with no guards is stronger evidence than
`external_call_return` with no guards — the latter may have been validated by
the caller (intra-procedural blind spot, see limitations).

---

## Scoring — Philosophy 2

The score maps structural evidence to a priority signal:

| Condition | Score |
|---|---|
| `trunc` + call sink + no guard | 1.00 |
| `trunc` + call sink + guards present | 0.88 |
| call sink + no guard + `function_argument` | 0.90 |
| call sink + no guard + struct/return source | 0.70 |
| call sink + `null_check` only | 0.75 |
| GEP-only + no guard | 0.55 |
| call sink + bounds check, sparse (≥5 sinks/guard) | 0.70 |
| call sink + bounds check, moderate (≥2) | 0.55 |
| call sink + bounds check, good (<2) | 0.40 |
| GEP-only + bounds check | 0.18–0.40 |
| no sink | 0.05 |

Multipliers: `is_external_input` × 1.10 (network-facing attack surface).

The `trunc` check comes first because narrowing is suspicious even when other
guards exist — those guards may protect different things.

---

## Output — what the LLM receives

`format_for_llm()` produces a structured block ready for prompt injection:

```
============================================================
Function: fill_window  |  GNN Vulnerability Context
Sinks           : memcpy ×3 — copies n bytes from src to dest — no overlap or bounds check
Input channels  : external_call_return
Guard status    : 8 guard(s) (eq, ne, uge, ult) [bounds-check + null-check] / 82 sink(s) = 10.3 sinks/guard (very sparse)
Trunc warning   : 4 integer narrowing(s) — check size args for truncation
Harness target  : fuzz n relative to dest buffer size; n=0, n=SIZE_MAX, n=dest_size+1 | fuzz integer truncation: supply values > INT_MAX / > UINT32_MAX as size
Slice           : 312 nodes, 82 sink(s)
============================================================
```

Each field is directly actionable:

- **Sinks** — what the dangerous operation is and what it does
- **Guard status** — whether and how well the sink is protected
- **Trunc warning** — signals to try values that cross integer width boundaries
- **Harness target** — explicit fuzzing strategy, no inference required

---

## What it can detect

Structural data-flow patterns where attacker-controlled data reaches a
dangerous operation without an adequate guard:

- Buffer overflow via `memcpy`, `strcpy`, `memmove`, `memset`
- Allocation size overflow via `malloc`, `calloc`, `realloc`
- Format string via `printf`, `sprintf`, `syslog` with external format arg
- Unbounded input via `recv`, `read`, `gets`, `fgets`
- Integer truncation before a size argument
- Network-input-to-sink chains (`recv`/`read` mock node in slice)
- Out-of-bounds array access via GEP with unguarded non-constant index

---

## What it cannot detect

Anything that requires value-level or semantic reasoning:

- **Double-free** — no memory write sink; the bug is in the sequence of calls,
  not the data flowing into one
- **Divide-by-zero** — no recognised sink; the buggy operation is a `udiv` or
  `sdiv` instruction, not a function call, and the "guard" would be a zero
  check on the divisor — currently not modelled
- **Null dereference before write** — control flow bug; the function
  dereferences a pointer that may be null, but the structural check for this
  requires tracking which pointer values can be null, not just whether an
  `icmp` exists
- **Unaligned pointer cast** — type system bug; `*(uint32_t *)(buf+1)` has no
  recognisable sink in the IR
- **Off-by-one in a constant** — `buf[MAX]` when `MAX` should be `MAX-1`;
  the constant is embedded in the IR and looks identical to a correct bound
- **Wrong comparison operator** — `>` instead of `>=`; both produce an `icmp`
  in the slice, indistinguishable structurally

These are the 4 scarnet functions no approach detects: `handle_stats`
(divide-by-zero), `handle_del` (double-free), `handle_set` (null deref),
`session_consume_frag` (unaligned cast).

---

## Shortcomings and known false positives

**Intra-procedural only.** The slicer does not cross function boundaries
upward. If `lm_init` receives a size from `deflateInit2_` which validated it
against `windowBits`, `lm_init`'s slice contains no `icmp` and scores as
unguarded. The guard happened one frame up and is invisible. Symptoms: internal
helpers with `external_call_return` input and no guards score high despite
being safe. Mitigation: the scoring deprioritises `external_call_return` vs
`function_argument` for the unguarded tiers.

**GEP noise.** In codebases that do heavy table indexing (compression codecs,
Huffman decoders, CRC tables), every array access becomes a GEP sink and
dominates rankings. `--no-gep-only` suppresses functions whose only sinks are
GEP. Functions with both GEP and call-based sinks are unaffected.

**No alias analysis.** Two pointers may alias — `dst` and `src` pointing to
overlapping regions. The slicer does not model this; it only tracks whether the
arguments were checked, not whether the checked bound is the right one.

**Guard presence ≠ guard correctness.** An `icmp slt` in the slice is counted
as a bounds check. Whether it compares the right value against the right bound
is not checked — a comparison like `if (n < 0)` (signed underflow guard)
counts the same as `if (n < sizeof(buf))` (correct bounds check). The density
metric partially compensates: many sinks with few guards suggests the guards
are not covering the right paths.

**No interprocedural taint.** Whether data ultimately originates from a network
socket depends on the call chain above the function. The `is_external_input`
flag only fires when a known source function (`recv`, `read`, etc.) appears
directly as a mock node in the slice. Functions that receive pre-read data
through a struct field will not have this flag set.

---

## Why it still works despite the shortcomings

The tool is a **ranker**, not a verifier. It does not claim that rank 1 is
definitely vulnerable. It claims that rank 1 has more structural evidence of
an unguarded dangerous operation than rank 50. The LLM triage step handles
the semantic question of whether a specific input can actually trigger the
condition.

On scarnet (13 known-vulnerable, 19 total functions), the structural rule alone
achieves 9/13 recall — the same ceiling as every GNN variant. The 4 misses are
structurally undetectable by any IR-level method. The 9 detectable functions
all score above 0.70 and appear in the top half of the ranking.

On zlib (112 functions), the top 6 by score after `--no-gep-only` are all
functions with real call-based sinks (memcpy, memset) and either unguarded
paths or integer truncation — the correct targets for a fuzzing campaign.

---

## Where API documentation fits

The slice context handles structural analysis. The model still needs to know
how to call the function — the library's initialization sequence, struct layout,
required teardown. Three deterministic sources (no prose docs required):

1. **Header file** — struct definitions and function prototypes are more
   precise than prose. Inject `scarnet.h` or `zlib.h` alongside the slice
   block. Planned: `--include-header` flag on `slice_context.py`.

2. **Call sites** — for internal helpers, grep who calls the function and with
   what arguments. That is a usage example, extractable from the IR.

3. **Function signature from IR** — IR encodes exact parameter types.
   `fill_window(deflate_state *s)` tells the model it needs a properly
   initialised `deflate_state`, pointing it at `deflateInit2_` as setup.

---

## Relationship to the GNN

The GNN and the deterministic rule answer the same question (Philosophy 2) via
different mechanisms. The GNN learned structural patterns from Devign training
data; the rule encodes those patterns explicitly. On scarnet both reach 9/13.
The GNN's previous apparent 11/13 advantage came from Devign topology
fingerprinting accidentally scoring two structurally undetectable functions
(handle_set, session_consume_frag) — not from genuine detection.

The deterministic rule is preferred for production use: no checkpoint required,
no training data dependency, fully explainable output, and the tier-based
scoring is tunable without retraining.
