# llvm-ir-context

Deterministic LLVM IR → structured vulnerability context for LLM harness generation.

Answers one question per C function, without a trained model:

> Does a parameter reach a dangerous sink (memcpy, malloc, strcpy, …)
> without a bounds-checking guard?

The answer is expressed as a structured block ready to inject into an LLM prompt, so the model spends tokens writing a harness rather than reasoning about data flow.

## Install

```bash
pip install llvmlite numpy
pip install -e .
```

Requires `clang-20` on `$PATH` for IR compilation. `llvmlite` must match your LLVM version.

## Quick start

```bash
# Compile your target to unoptimised IR
clang-20 -O0 -Xclang -disable-O0-optnone -fno-inline -S -emit-llvm -I include -w src/parse.c -o /tmp/parse.ll

# Rank all functions by vulnerability risk
ir-score --ir-dir /tmp/

# Inspect a specific function
ir-context /tmp/parse.ll --function process_packet
```

## CLI

### `ir-score` — rank functions across a directory

```bash
ir-score --ir-dir /tmp/ir/                        # all .ll files, no answer key
ir-score --ir-dir /tmp/ir/ --no-gep-only          # suppress GEP-only false positives
ir-score --ir-dir /tmp/ir/ --answer-key key.txt   # measure recall against known-vulnerable list
ir-score --scarnet                                 # clone + compile johwes/scarnet automatically
```

Output includes score, sink types, guard status, and source filename for each function.

### `ir-context` — detailed slice context for one file

```bash
ir-context function.ll                    # all functions
ir-context function.ll --function foo     # single function
ir-context function.ll --function foo --json
```

## Python API

```python
# High-level — single function
from llvm_ir_context import get_vulnerability_context

ir_text = open("function.ll").read()
result  = get_vulnerability_context(ir_text, fn_name="process_packet")
print(result["score"], result["harness_hint"])

# High-level — score a whole directory
from llvm_ir_context import rank_directory

result = rank_directory("/tmp/ir/", no_gep_only=True)
for fn, score in result["ranked"][:5]:
    print(f"{score:.1%}  {fn}")
```

Low-level API (for custom pipelines):

```python
from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg
from llvm_ir_context.slice_context import summarize_slice, format_for_llm
from llvm_ir_context.score_deterministic import philosophy2_score

ir_text = open("function.ll").read()
g       = ir_to_graph_slice_pdg(ir_text, fn_name="process_packet")
summary = summarize_slice(g, fn_name="process_packet")
score   = philosophy2_score(summary)
context = format_for_llm(summary, score=score)
# inject `context` into your LLM harness generation prompt
```

## Score interpretation

| Score | Meaning |
|---|---|
| 1.00 | `trunc` + call sink + no guard — integer narrowing into unguarded call |
| 0.92+ | double-free detected (score floor) |
| 0.88+ | use-after-free detected (score floor); or `trunc` + call sink + guards |
| 0.90 | call sink + no guard + direct function argument |
| 0.75 | call sink + null-check only (doesn't protect buffer writes) |
| 0.70 | call sink + no guard, struct/return source; or unguarded divide/remainder |
| 0.62 | GEP-only + bounds check, sparse (≥5 sinks per guard) |
| 0.55 | GEP-only + no guard |
| 0.40 | call sink + bounds check, well-covered |
| 0.05 | no sink found |

Multipliers applied on top of base scores (only when the base tier didn't already encode the risk): buffer-write sinks (strcpy/memcpy/gets/…) ×1.50 — skipped when trunc or null_check drove the base tier; external input ×1.10; free() sink ×1.05 — skipped when free() is the only call sink (bare deallocation wrappers are not a buffer overflow signal; UAF/double-free risk is handled via typestate score floors instead); format-only sinks (snprintf/printf/…) with guard ×0.70; allocation-only sinks (malloc/calloc) ×0.70; double-free floor 0.92; UAF floor 0.88. Guard density for functions with mixed GEP+call sinks is computed over non-free call sinks only, so GEP count does not inflate sparseness.

## What it detects / doesn't

**Detectable:** unguarded memcpy/strcpy/malloc/sprintf, integer truncation before size arg, null-check-only on buffer write, network-input-to-sink chains, divide-by-zero (sdiv/udiv/srem/urem with non-constant divisor), double-free and use-after-free (intra-procedural typestate analysis).

**Not detectable:** null dereference, unaligned cast, off-by-one in a constant, wrong comparison operator. See [context-enrichment-design.md](context-enrichment-design.md) for the full breakdown.

## Design

See [context-enrichment-design.md](context-enrichment-design.md) for the full design rationale: why LLVM IR, how the PDG backward slice works, the scoring tier system, shortcomings, and SCAR integration.

See [slice-context-guide.md](slice-context-guide.md) for the practical usage guide.
