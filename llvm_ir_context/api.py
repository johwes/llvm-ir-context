"""
llvm_ir_context.api — Programmatic entry points, no sys.exit, no stdout.

Intended for use by other scripts, tests, and future agentic workflows.
All errors are returned as {"error": str} in the payload — callers must
never catch sys.exit or parse printed text.
"""

from __future__ import annotations

import math
from pathlib import Path


def get_vulnerability_context(ir_text: str, fn_name: str) -> dict:
    """Slice and summarise a single function from its LLVM IR text.

    Returns a slice_context summary dict with an added 'score' key.
    On any failure returns {"error": <message>}.

    Example::

        from llvm_ir_context.api import get_vulnerability_context
        result = get_vulnerability_context(open("parse.ll").read(), "process_packet")
        print(result["score"], result["harness_hint"])
    """
    try:
        from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg
        from llvm_ir_context.slice_context import summarize_slice
        from llvm_ir_context.score_deterministic import philosophy2_score

        g = ir_to_graph_slice_pdg(ir_text, fn_name=fn_name)
        if g is None:
            return {"error": f"could not extract PDG slice for '{fn_name}'"}

        summary = summarize_slice(g, fn_name=fn_name)
        summary["score"] = philosophy2_score(summary)

        # JSON safety: float("inf") is not valid JSON.
        if summary.get("guard_density") == math.inf:
            summary["guard_density"] = None

        return summary

    except Exception as exc:
        return {"error": str(exc)}


def rank_directory(
    ir_dir: str | Path,
    *,
    no_gep_only: bool = False,
    answer_key: set[str] | None = None,
) -> dict:
    """Score all functions in a directory of .ll files.

    Returns the result dict from score_ir_dir() which includes:
      ranked      — list of (fn_name, score) sorted descending
      summaries   — {fn_name: slice_summary_dict}
      details     — {fn_name: detail_str}
      fn_files    — {fn_name: Path}
      caller_map  — {callee: [caller, ...]} cross-file call graph
      no_slice    — list of fn_names with no extractable slice
      answer_key  — the answer_key set (possibly empty)

    On any failure returns {"error": <message>}.

    Example::

        from llvm_ir_context.api import rank_directory
        result = rank_directory("/tmp/scarnet-ir/", no_gep_only=True)
        for fn, score in result["ranked"][:5]:
            print(f"{score:.1%}  {fn}")
    """
    try:
        from llvm_ir_context.score_deterministic import score_ir_dir
        return score_ir_dir(
            Path(ir_dir),
            no_gep_only=no_gep_only,
            answer_key=answer_key,
        )
    except Exception as exc:
        return {"error": str(exc)}
