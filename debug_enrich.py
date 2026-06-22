#!/usr/bin/env python3
"""Diagnostic: trace _enrich_with_callee_flags for dispatch."""
import sys, re, glob, ctypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gen_harness import (get_context_json, _enrich_with_callee_flags,
                         _source_block, _fn_ir_body, _ir_has_double_free)
from llvm_ir_context.preprocess_slice_pdg import _ptr_id, VK_INSTRUCTION, VK_FUNCTION, VK_GLOBAL_VAR

IR_DIR  = Path.home() / "scarnet-ir-clean"
LL_PATH = str(IR_DIR / "src_handler.ll")
FN_NAME = "dispatch"
SRC_DIR = str(Path.home() / "scarnet/src")

src_block = _source_block(LL_PATH, FN_NAME, SRC_DIR)
summary   = get_context_json(LL_PATH, FN_NAME)
print(f"dispatch summary: double_free={summary.get('double_free')}, "
      f"use_after_free={summary.get('use_after_free')}")

ll_text = Path(LL_PATH).read_text(errors="replace")
define_re = re.compile(r"^define\b.*@(\w+)\s*\(", re.MULTILINE)

print("\n--- scanning callees ---")
for ll in sorted(glob.glob(str(IR_DIR / "*.ll"))):
    txt = Path(ll).read_text(errors="replace") if ll != LL_PATH else ll_text
    for m in define_re.finditer(txt):
        callee = m.group(1)
        if callee == FN_NAME:
            continue
        in_ir  = bool(re.search(rf"\bcall\b.*@{re.escape(callee)}\b", ll_text))
        in_src = bool(src_block and re.search(rf"\b{re.escape(callee)}\s*\(", src_block))
        if not (in_ir or in_src):
            continue
        cs = get_context_json(ll, callee)
        df = cs.get("double_free")
        uaf = cs.get("use_after_free")
        body = _fn_ir_body(txt, callee)
        ir_df = _ir_has_double_free(body) if body else False
        print(f"  {callee:30s} in_ir={in_ir} in_src={in_src} "
              f"double_free={df} use_after_free={uaf} ir_scan_df={ir_df}")

result = _enrich_with_callee_flags(summary, FN_NAME, LL_PATH, str(IR_DIR), src_text=src_block)
print(f"\nEnriched: double_free={result.get('double_free')}, "
      f"use_after_free={result.get('use_after_free')}")

# Deep-dive: trace _detect_double_free on handle_del directly
print("\n--- tracing _detect_double_free on handle_del ---")
import llvmlite.binding as llvm
llvm.initialize(); llvm.initialize_native_target(); llvm.initialize_native_asmprinter()
ll_text = Path(LL_PATH).read_text(errors="replace")
mod = llvm.parse_assembly(ll_text)
for fn in mod.functions:
    if fn.name != "handle_del":
        continue
    free_calls = []
    for block in fn.blocks:
        for instr in block.instructions:
            if instr.opcode == "call":
                ops = list(instr.operands)
                for op in ops:
                    if op.value_kind in (VK_FUNCTION, VK_GLOBAL_VAR) and "free" in op.name:
                        ptr_args = [o for o in ops if o.value_kind not in (VK_FUNCTION, VK_GLOBAL_VAR)]
                        if ptr_args:
                            p = ptr_args[0]
                            pid = _ptr_id(p)
                            p_str = str(p).strip()
                            free_calls.append((pid, p_str))
                            print(f"  free() call: ptr_id={pid:#x}  repr={p_str[:80]}")
    if len(free_calls) >= 2:
        same = free_calls[0][0] == free_calls[1][0]
        print(f"  same ptr_id: {same}  ({free_calls[0][0]:#x} vs {free_calls[1][0]:#x})")
    break
