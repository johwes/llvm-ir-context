"""
llvm-ir-context — Deterministic LLVM IR → structured vulnerability context.

Preferred public API (programmatic, no sys.exit):
    from llvm_ir_context import get_vulnerability_context, rank_directory

Lower-level API:
    from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg
    from llvm_ir_context.slice_context import summarize_slice, format_for_llm
    from llvm_ir_context.score_deterministic import philosophy2_score, score_ir_dir
"""

from llvm_ir_context.api import get_vulnerability_context, rank_directory

__all__ = ["get_vulnerability_context", "rank_directory"]
