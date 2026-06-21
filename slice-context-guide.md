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
| `preprocess_slice_pdg.py` | Compile IR → PDG slice graph |
| `slice_context.py` | Slice graph → structured vulnerability summary |
| `score_deterministic.py` | Run both over a directory, rank by risk |

## Quick start

```bash
# Compile your target to LLVM IR
clang-20 -O0 -fno-inline -S -emit-llvm -w src/foo.c -o /tmp/foo.ll

# Score all functions in an IR directory (no answer key needed)
python score_deterministic.py --ir-dir /tmp/ --no-gep-only

# Inspect a single file in detail
python slice_context.py /tmp/foo.ll
python slice_context.py /tmp/foo.ll --json
```

## Compiling to IR

The slicer requires unoptimised IR so that the data-flow structure is
preserved. Optimisation passes inline, vectorise, and restructure code in ways
that lose the original sink→source relationships.

```bash
# Single file
clang-20 -O0 -fno-inline -S -emit-llvm -w src/parse.c -o /tmp/parse.ll

# Multiple files — compile each separately, pass -I for headers
mkdir -p /tmp/ir
for f in src/*.c; do
    clang-20 -O0 -fno-inline -S -emit-llvm -I include -w "$f" \
        -o "/tmp/ir/$(basename ${f%.c}).ll"
done

# score_deterministic.py --scarnet does this automatically for johwes/scarnet
```

`-O0 -fno-inline` — required. `-w` suppresses warnings that would corrupt the
`.ll` file. `-I include` — add only if the source needs headers.

## Running the ranker

`score_deterministic.py` compiles (or reads) IR, scores every function with
the Philosophy 2 rule, and prints a ranked table.

```bash
# Unknown codebase — no answer key
python score_deterministic.py --ir-dir /tmp/ir/

# With answer key for recall measurement
python score_deterministic.py --ir-dir /tmp/ir/ \
    --answer-key known-vulnerable.txt

# Suppress GEP-only false positives (recommended for compression/codec libs)
python score_deterministic.py --ir-dir /tmp/ir/ --no-gep-only

# Add GNN checkpoint for MAX ensemble
python score_deterministic.py --scarnet --answer-key key.txt \
    --gnn-checkpoint model_slice_pdg_v8.pt

# Clone and compile scarnet automatically
python score_deterministic.py --scarnet --answer-key scarnet-answer-key.txt
```

### Score interpretation

| Score | Meaning |
|---|---|
| 1.00 | Unguarded sink — no `icmp` anywhere in the backward slice |
| 0.75–0.82 | Null-check only — pointer deref protected but buffer write is not |
| 0.55–0.77 | Sparse guards — some bounds checks but sink-to-guard ratio is high |
| 0.40–0.44 | Guarded — bounds checks present, ratio is reasonable |
| 0.05 | No sink found / no slice (safe or structurally undetectable) |

Multipliers applied on top: `is_external_input` × 1.10 (network/user data
reaches the sink), `has_trunc` × 1.05 (integer narrowing before size argument).

### `--no-gep-only`

By default, `getelementptr` (GEP) instructions are treated as sinks because
they are array index operations that can go out of bounds. In codebases that do
heavy table access (compression codecs, Huffman decoders, CRC lookup tables),
every constant-ish index becomes a GEP "sink" and dominates the ranking.

`--no-gep-only` suppresses any function whose only sinks are GEP — leaving only
functions with real call-based sinks (`memcpy`, `malloc`, `strcpy`, …) at the
top. It does not remove GEP sinks from functions that also have call sinks.

## Inspecting a single function

`slice_context.py` can be run standalone on any `.ll` file. It analyses every
non-declaration function in the file.

```bash
python slice_context.py /tmp/parse.ll
```

Output:

```
============================================================
GNN Vulnerability Context
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
python slice_context.py /tmp/parse.ll --json
```

## Using as a Python library

### Get a summary dict

```python
from preprocess_slice_pdg import ir_to_graph_slice_pdg
from slice_context import summarize_slice, format_for_llm

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
    print(summary["natural_language"]) # one-sentence description
    print(summary["harness_hint"])     # what to fuzz
```

### Format for LLM injection

```python
from slice_context import format_for_llm
from score_deterministic import philosophy2_score

score   = philosophy2_score(summary)   # 0.0–1.0
context = format_for_llm(summary, score=score)
# Inject `context` into your LLM harness-generation prompt
```

### Score without the full ranker

```python
from score_deterministic import philosophy2_score

# summary comes from summarize_slice()
score = philosophy2_score(summary)
```

### Full pipeline example

```python
import re
from pathlib import Path
from preprocess_slice_pdg import ir_to_graph_slice_pdg
from slice_context import summarize_slice, format_for_llm
from score_deterministic import philosophy2_score

def score_file(ll_path: Path, threshold: float = 0.5):
    ir_text = ll_path.read_text(errors="replace")

    # Split into per-function segments
    segs = re.split(r'(?=^define\b)', ir_text, flags=re.MULTILINE)
    header = "\n".join(l for l in ir_text.splitlines()
                       if not l.startswith("define"))

    results = []
    for seg in segs:
        seg = seg.strip()
        if not seg.startswith("define"):
            continue
        m = re.match(r'define\s+.*?@([\w.]+)\s*\(', seg)
        if not m:
            continue
        fn_name = m.group(1)
        fn_ir   = header + "\n\n" + seg

        g = ir_to_graph_slice_pdg(fn_ir, fn_name=fn_name)
        if g is None:
            continue
        summary = summarize_slice(g, fn_name=fn_name)
        score   = philosophy2_score(summary)
        if score >= threshold:
            results.append((fn_name, score, format_for_llm(summary, score)))

    return sorted(results, key=lambda r: r[1], reverse=True)

for fn, score, ctx in score_file(Path("/tmp/parse.ll")):
    print(f"\n{fn}  ({score:.1%})")
    print(ctx)
```

## What the slicer can and cannot detect

**Detectable** — structural data-flow patterns:

- Buffer overflow via unguarded `memcpy`, `strcpy`, `memmove`, `memset`
- Allocation size overflow via `malloc`, `calloc`, `realloc` with no size guard
- Format string bugs via `printf`, `sprintf`, `syslog` with external format arg
- Integer truncation before a size argument (`trunc i64 → i32` feeding `memcpy`)
- Network-input-to-sink chains (when `recv`/`read`/`fgets` mock node is in slice)
- Out-of-bounds array access via GEP with non-constant, unguarded index

**Not detectable** — semantic / value-level bugs:

- Double-free (no memory write sink)
- Divide-by-zero (no recognized sink, control flow not data flow to a call)
- Null dereference before write (control flow bug, not data flow)
- Unaligned pointer cast (type system, not address computation)
- Off-by-one in a constant, wrong comparison operator

The 4 scarnet functions that no approach detects (handle_stats, handle_del,
handle_set, session_consume_frag) all fall into the second category.

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
(variable-length stack allocation)

## Integration with SCAR

The slice context is designed to pre-compute the hard structural analysis step
so that the LLM only has to do the easy step: write code from a specification.

```
score_deterministic.py     →  ranked list of high-risk functions
slice_context.format_for_llm  →  structured prompt block per function
LLM (claude-opus-4-8)      →  fuzzing harness targeting the identified sink
```

The three files (`preprocess_slice_pdg.py`, `slice_context.py`,
`score_deterministic.py`) are self-contained and have no dependency on the GNN
training infrastructure. Copy them into SCAR and call `ir_to_graph_slice_pdg` +
`summarize_slice` + `format_for_llm` directly from `context_gen.py`.
