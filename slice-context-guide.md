# Slice context guide

How to use the PDG slicer and context generator to identify unguarded dangerous
sinks in LLVM IR and produce structured vulnerability context for LLM harness
generation.

## What this does

The slicer answers one question per function:

> Does a parameter reach a dangerous sink (memcpy, malloc, strcpy, …)
> without a bounds-checking guard?

It works entirely on compiled LLVM IR — no source parsing, no type inference,
no symbolic execution. It extracts a backward PDG slice from each dangerous
sink, checks whether an `icmp` comparison guards the data flow, and returns a
structured summary. That summary can feed directly into an LLM prompt for
targeted fuzzing harness generation.

Three files do all the work:

| File | Role |
|---|---|
| `llvm_ir_context/preprocess_slice_pdg.py` | Compile IR → PDG slice graph |
| `llvm_ir_context/slice_context.py` | Slice graph → structured vulnerability summary |
| `llvm_ir_context/score_deterministic.py` | Run both over a directory, rank by risk |

## Quick start

```bash
# Compile your target to LLVM IR
clang-20 -O0 -Xclang -disable-O0-optnone -fno-inline -S -emit-llvm -w src/foo.c -o /tmp/foo.ll

# Score all functions in an IR directory (no answer key needed)
ir-score --ir-dir /tmp/ --no-gep-only

# Inspect a single file in detail
ir-context /tmp/foo.ll
ir-context /tmp/foo.ll --json
```

## Compiling to IR

The slicer requires unoptimised IR so that the data-flow structure is
preserved. Optimisation passes inline, vectorise, and restructure code in ways
that lose the original sink→source relationships.

```bash
# Single file
clang-20 -O0 -Xclang -disable-O0-optnone -fno-inline -S -emit-llvm -w src/parse.c -o /tmp/parse.ll

# Multiple files — compile each separately, pass -I for headers
mkdir -p /tmp/ir
for f in src/*.c; do
    clang-20 -O0 -Xclang -disable-O0-optnone -fno-inline -S -emit-llvm -I include -w "$f" \
        -o "/tmp/ir/$(basename ${f%.c}).ll"
done

# ir-score --scarnet does this automatically for johwes/scarnet
```

`-O0 -fno-inline` — required. `-w` suppresses warnings that would corrupt the
`.ll` file. `-I include` — add only if the source needs headers.

## Running the ranker

`ir-score` compiles (or reads) IR, scores every function with the Philosophy 2
rule, and prints a ranked table.

```bash
# Unknown codebase — no answer key
ir-score --ir-dir /tmp/ir/

# With answer key for recall measurement
ir-score --ir-dir /tmp/ir/ --answer-key known-vulnerable.txt

# Suppress GEP-only false positives (recommended for compression/codec libs)
ir-score --ir-dir /tmp/ir/ --no-gep-only

# Clone and compile scarnet automatically
ir-score --scarnet --answer-key scarnet-answer-key.txt
```

### Score interpretation

| Score | Meaning |
|---|---|
| 1.00 | `trunc` + call sink + no guard — integer narrowing into unguarded call |
| 0.92+ | double-free detected (score floor) |
| 0.88+ | use-after-free detected (score floor); or `trunc` + call sink + guards |
| 0.90 | call sink + no guard + direct function argument |
| 0.75 | call sink + null-check only — pointer deref protected, buffer write is not |
| 0.70 | call sink + no guard + struct/return source; or unguarded divide/remainder |
| 0.62 | GEP-only + bounds check, sparse coverage |
| 0.55 | Sparse guards — some bounds checks but sink-to-guard ratio is high |
| 0.40 | Guarded — bounds checks present, ratio is reasonable |
| 0.05 | No sink found / no slice |

Multipliers (only when the base tier didn't already encode the risk):
buffer-write sinks ×1.50 — skipped when `trunc` or `null_check` drove the base;
external input ×1.10; free() ×1.05 — skipped when free() is the only call sink
(bare wrappers aren't a buffer overflow signal; UAF/double-free is handled via
typestate floors instead); format-only with guard ×0.70; allocation-only ×0.70.
Guard density uses call-sink count (excluding free()) when call sinks are present,
so GEP noise doesn't make guarded memcpy functions look sparse.

### `--no-gep-only`

By default, `getelementptr` (GEP) instructions are treated as sinks because
they are array index operations that can go out of bounds. In codebases that do
heavy table access (compression codecs, Huffman decoders, CRC lookup tables),
every constant-ish index becomes a GEP "sink" and dominates the ranking.

`--no-gep-only` suppresses any function whose only sinks are GEP — leaving only
functions with real call-based sinks (`memcpy`, `malloc`, `strcpy`, …) at the
top. It does not remove GEP sinks from functions that also have call sinks.

## Inspecting a single function

`ir-context` can be run standalone on any `.ll` file. It analyses every
non-declaration function in the file.

```bash
ir-context /tmp/parse.ll
```

Output:

```
============================================================
Function: process_packet  |  Vulnerability Context
Sinks           : memcpy ×3 — copies n bytes from src to dest — no overlap or bounds check
Input channels  : function_argument
Guard status    : NO icmp in slice — sink appears UNGUARDED
Harness target  : fuzz n relative to dest buffer size; n=0, n=SIZE_MAX, n=dest_size+1
Slice           : 47 nodes, 3 sink(s)
============================================================
Natural language:
  Function `process_packet` contains: `memcpy` ×3 (copies n bytes …). Input
  originates from: function_argument. Guard status: no comparison (icmp) in
  slice — sink appears UNGUARDED. Slice: 47 nodes, 3 sink(s) (1 unique type(s)).
```

For JSON output (useful when piping into another tool):

```bash
ir-context /tmp/parse.ll --json
```

## Using as a Python library

### Get a summary dict

```python
from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg
from llvm_ir_context.slice_context import summarize_slice, format_for_llm

ir_text = open("function.ll").read()
g       = ir_to_graph_slice_pdg(ir_text, fn_name="process_packet")

if g is None:
    # No dangerous sinks found — function is likely safe or has no slice
    pass
else:
    summary = summarize_slice(g, fn_name="process_packet")
    print(summary["n_sinks"])          # int — number of sink nodes
    print(summary["has_guard"])        # bool
    print(summary["guard_type"])       # "none" | "null_check" | "bounds_check" | "mixed"
    print(summary["is_external_input"])# bool — network/user data reaches sink
    print(summary["has_trunc"])        # bool — integer narrowing before size arg
    print(summary["double_free"])      # bool — same ptr freed twice (intra-procedural)
    print(summary["use_after_free"])   # bool — ptr used after free (intra-procedural)
    print(summary["caller_validated"]) # bool — a caller in the codebase has icmp guards
    print(summary["natural_language"]) # one-sentence description
    print(summary["harness_hint"])     # what to fuzz
```

### Format for LLM injection

```python
from llvm_ir_context.slice_context import format_for_llm
from llvm_ir_context.score_deterministic import philosophy2_score

score   = philosophy2_score(summary)   # 0.0–1.0
context = format_for_llm(summary, score=score)
# Inject `context` into your LLM harness-generation prompt
```

### Score without the full ranker

```python
from llvm_ir_context.score_deterministic import philosophy2_score

# summary comes from summarize_slice()
score = philosophy2_score(summary)
```

### Full pipeline example

```python
import llvmlite.binding as llvm
from pathlib import Path
from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg
from llvm_ir_context.slice_context import summarize_slice, format_for_llm
from llvm_ir_context.score_deterministic import philosophy2_score

def score_file(ll_path: Path, threshold: float = 0.5):
    ir_text = ll_path.read_text(errors="replace")
    # Pass full module IR so declare stubs remain visible for cross-function calls
    mod = llvm.parse_assembly(ir_text)

    results = []
    for fn in mod.functions:
        if fn.is_declaration:
            continue
        g = ir_to_graph_slice_pdg(ir_text, fn_name=fn.name)
        if g is None:
            continue
        summary = summarize_slice(g, fn_name=fn.name)
        score   = philosophy2_score(summary)
        if score >= threshold:
            results.append((fn.name, score, format_for_llm(summary, score)))

    return sorted(results, key=lambda r: r[1], reverse=True)

for fn, score, ctx in score_file(Path("/tmp/parse.ll")):
    print(f"\n{fn}  ({score:.1%})")
    print(ctx)
```

## End-to-end walkthrough: scarnet

This section walks through the full pipeline against
[johwes/scarnet](https://github.com/johwes/scarnet) — an intentionally
buggy C server used in the SCAR workshop. It assumes SCAR is cloned
alongside llvm-ir-context.

### Prerequisites

```bash
# LLVM 20 toolchain
clang-20 --version   # must exist
opt-20 --version     # must exist (for mem2reg)
llvm-symbolizer-20   # for symbolized ASAN stacks

# Python packages
pip install llvm-ir-context   # or: pip install -e ~/openshift/llvm-ir-context/
```

**Model:** `gen_harness.py` defaults to `Qwen3.6-35B-A22B` but is configured
via environment variables. `deepseek-r1-distill-qwen-14b` is recommended for
reliable multi-constraint instruction following:

```bash
export LLM_ENDPOINT=https://<your-litellm-endpoint>/v1/chat/completions
export LLM_MODEL=deepseek-r1-distill-qwen-14b
export LLM_API_KEY=sk-...
```

### 1. Clone repos

```bash
cd ~
git clone https://github.com/johwes/llvm-ir-context.git
git clone https://github.com/johwes/scarnet.git
git clone https://github.com/johwes/SCAR.git   # or wherever SCAR lives
mkdir scarnet-ir scarnet-harnesses
```

### 2. Score scarnet (clones + compiles IR automatically)

```bash
cd ~/llvm-ir-context
python -m llvm_ir_context.score_deterministic \
  --scarnet --keep-ir ~/scarnet-ir/ \
  --answer-key scarnet-answer-key.txt
```

Expected: 11/13 P@13, `handle_del` rank 1 with `+df`.

### 3. Generate harnesses

```bash
python gen_harness.py \
  --ir-dir ~/scarnet-ir/ \
  --src-dir ~/scarnet/src/ \
  --header ~/scarnet/include/scarnet.h \
  --output-dir ~/scarnet-harnesses/ \
  --top-k 7 --skip-existing
```

Expected: 7 harnesses generated (`scar_log`, `session_login`,
`scar_alloc_copy`, `scar_atoi`, `dispatch`, `parse_cmd`, `session_frag`).

Each harness goes through two automatic checks after compilation:

**Self-harm check** — slices `LLVMFuzzerTestOneInput` itself for dangerous
sinks. A high score means the harness has a memory bug in the test scaffolding
(not the target), which would produce ASAN crashes that mask real bugs. Score
≥ 0.85 triggers a retry with a specific error message.

**Blank-shooter check** — slices backward from the call to the target function
inside `LLVMFuzzerTestOneInput`, treating the target as a custom sink. Fails
if `Data`/`Size` never reach that call — i.e. the harness calls the target
with hardcoded or locally-computed values the fuzzer cannot influence. The OK
line shows the slice node count and guard type so you can verify the check ran:

```
── blank-shooter check ──────────────────────────────
OK — Data/Size reach `scar_log` (5 node(s) in slice, guard=null_check)
```

`guard=null_check` here means the slicer saw the `if (msg == NULL) return 0`
after `malloc` — a guard on allocation failure, not on the vulnerability. This
is expected and correct.

### 4. Compile harnesses

```bash
cd ~/scarnet-harnesses

for fn in scar_log session_login scar_alloc_copy scar_atoi dispatch parse_cmd session_frag; do
  clang-20 -fsanitize=fuzzer,address -g \
    -I ~/scarnet/include \
    harness_${fn}.c ~/scarnet/src/*.c \
    -o fuzzer_${fn}
done
```

### 5. Fuzz

```bash
for fn in scar_log session_login scar_alloc_copy scar_atoi dispatch parse_cmd session_frag; do
  echo "=== $fn ==="
  mkdir -p crashes/${fn}
  ./fuzzer_${fn} -runs=500000 -artifact_prefix=crashes/${fn}/ 2>&1 \
    | grep -E 'SUMMARY|ERROR|Done'
done
```

Expected crashes: `scar_log` (SEGV/format-string), `scar_alloc_copy`
(alloc-too-big), `dispatch` (double-free via `handle_del`),
`session_frag` (heap-buffer-overflow).

### 6. Symbolize and convert crashes to SCAR findings

```bash
# Map function → IR file → source file
declare -A LL=(
  [scar_log]=src_util      [scar_alloc_copy]=src_util
  [dispatch]=src_handler   [session_frag]=src_session
)
declare -A FN=(
  [dispatch]=handle_del
)

for fn in scar_log scar_alloc_copy dispatch session_frag; do
  crash=$(ls crashes/${fn}/crash-* 2>/dev/null | head -1)
  [ -z "$crash" ] && continue
  ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-20 \
    ./fuzzer_${fn} "$crash" 2>crashes/${fn}/asan.log
  target_fn=${FN[$fn]:-$fn}
  python ~/llvm-ir-context/crash_to_findings.py \
    --asan-log crashes/${fn}/asan.log \
    --ll ~/scarnet-ir/${LL[$fn]}.ll \
    --function "$target_fn" \
    --repo ~/scarnet/ --replace
done
```

### 7. Run SCAR repair loop

```bash
cd ~/SCAR
scar /tmp/no-ikos.sarif ~/scarnet/ \
  --triage-rounds 3 \
  --output ~/SCAR/scar-results.json
```

Expected: 4/4 patches accepted, all `VALID` confidence 1.0.

### 8. Apply patches

```bash
python ~/llvm-ir-context/apply_patch.py \
  --results ~/SCAR/scar-results.json \
  --repo ~/scarnet/
```

### 9. Re-fuzz to confirm fixes

```bash
cd ~/scarnet-harnesses

for fn in scar_log scar_alloc_copy dispatch session_frag; do
  clang-20 -fsanitize=fuzzer,address -g \
    -I ~/scarnet/include \
    harness_${fn}.c ~/scarnet/src/*.c \
    -o fuzzer_${fn}_patched 2>/dev/null
  echo "=== $fn ==="
  ./fuzzer_${fn}_patched -runs=500000 2>&1 | grep -E 'SUMMARY|ERROR|Done'
done
```

Expected: `Done 500000 runs` with no crashes for all 4.

---

## What the slicer can and cannot detect

**Detectable** — structural data-flow patterns:

- Buffer overflow via unguarded `memcpy`, `strcpy`, `memmove`, `memset`
- Allocation size overflow via `malloc`, `calloc`, `realloc` with no size guard
- Format string bugs via `printf`, `sprintf`, `syslog` with external format arg
- Integer truncation before a size argument (`trunc i64 → i32` feeding `memcpy`)
- Network-input-to-sink chains (when `recv`/`read`/`fgets` mock node is in slice)
- Out-of-bounds array access via GEP with non-constant, unguarded index
- Divide-by-zero via `sdiv`/`udiv`/`srem`/`urem` with non-constant, unguarded divisor
- Double-free — same pointer freed twice in the same function (typestate)
- Use-after-free — pointer used after free in the same function (typestate)

**Not detectable** — semantic / value-level bugs:

- Null dereference before write (control flow bug, not data flow to a sink)
- Unaligned pointer cast (type system, not address computation)
- Off-by-one in a constant, wrong comparison operator
- Cross-function UAF/double-free (typestate is intra-procedural only)

## Sink types recognized

The slicer recognises these call names as dangerous sinks (plus their
`__foo_chk` / `__foo_chk_warn` FORTIFY_SOURCE variants automatically):

**Memory copy/move:** `memcpy`, `memmove`, `memset`, `bcopy`, `llvm.memcpy.*`,
`llvm.memmove.*`, `llvm.memset.*`

**String operations:** `strcpy`, `strncpy`, `strcat`, `strncat`

**Formatted I/O:** `sprintf`, `snprintf`, `vsprintf`, `vsnprintf`, `printf`,
`fprintf`, `scanf`, `sscanf`, `fscanf`, `syslog`, `err`, `warn`

**Unbounded input:** `gets`, `fgets`, `read`, `recv`, `recvfrom`, `pread`

**Allocation:** `malloc`, `calloc`, `realloc`, `free`, `xmalloc`, `xrealloc`

**IR instructions:** `getelementptr` (non-constant index), `alloca`
(variable-length stack allocation), `sdiv`/`udiv`/`srem`/`urem`
(non-constant divisor — divide-by-zero risk)

## Integration with SCAR

The slice context is designed to pre-compute the hard structural analysis step
so that the LLM only has to do the easy step: write code from a specification.

```
ir-score / rank_directory()        →  ranked list of high-risk functions
slice_context.format_for_llm()     →  structured prompt block per function
LLM (deepseek-r1-distill-qwen-14b) →  fuzzing harness targeting the identified sink
```

The package (`llvm_ir_context`) is self-contained with no dependency on any
GNN training infrastructure. Install it with `pip install -e .` and call
`get_vulnerability_context()` or `rank_directory()` from `llvm_ir_context.api`
directly from any integration script.
