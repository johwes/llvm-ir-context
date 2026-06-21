#!/usr/bin/env python3
"""
preprocess_slice_pdg.py — PDG backward-slice graphs from Devign LLVM IR.

§12 experiment: §11 (DFG-only backward slice) produced 56.64% — below the §7
baseline of 58.00%. Root cause: guard conditions are control dependence, not data
dependence. The `icmp`+`br` nodes that determine whether a dangerous call is safe
sit in a CFG predecessor block and have no DFG edge into the sink. DFG-only slicing
produces identical subgraphs for guarded (safe) and unguarded (vulnerable) code.

Fix: Program Dependence Graph (PDG) slice = DFG + control dependence.

Algorithm (fixed-point):
  1. Seed with dangerous sink nodes (same as §11 preprocess_slice.py).
  2. DFG backward BFS from all visited nodes.
  3. For each newly visited instruction node, add the terminator (br/switch) of
     each CFG predecessor block to the slice.
  4. Repeat until no new nodes are added.

In LLVM IR, `br i1 %cmp ...` has a DFG edge from `%cmp` (VK_INSTRUCTION operand).
Adding the `br` terminator automatically pulls in the `icmp` guard and its operands
via the next DFG BFS iteration — no special casing needed.

Output: data/{train,valid,test}_slice_pdg_graphs.pkl
  Same format as _slice_graphs.pkl — drop-in for train_slice_pdg.py.

Usage:
    python preprocess_slice_pdg.py --subset 200 --workers 1   # smoke test
    python preprocess_slice_pdg.py                             # full Devign
    python preprocess_slice_pdg.py --workers 8
"""

import argparse
import ctypes
import json
import pickle
import random
import re
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np
import llvmlite.binding as llvm

HERE = Path(__file__).parent
DATA = HERE / "data"

sys.path.insert(0, str(HERE))
from preprocess import compile_to_ir, download_devign

# ---------------------------------------------------------------------------
# Opcode vocabulary (identical to preprocess_instr.py — 110 entries)
# ---------------------------------------------------------------------------

OPCODE_VOCAB: dict[str, int] = {
    "add": 2,  "sub": 3,  "mul": 4,  "udiv": 5,  "sdiv": 6,
    "urem": 7, "srem": 8, "shl": 9,  "lshr": 10, "ashr": 11,
    "and": 12, "or": 13,  "xor": 14,
    "fadd": 15, "fsub": 16, "fmul": 17, "fdiv": 18, "frem": 19,
    "fneg": 20, "extractelement": 21, "insertelement": 22, "shufflevector": 23,
    "alloca": 26, "load": 27, "store": 28, "getelementptr": 29,
    "fence": 30, "cmpxchg": 31, "atomicrmw": 32,
    "br": 36, "switch": 37, "ret": 38, "invoke": 39,
    "resume": 40, "unreachable": 41, "indirectbr": 42, "callbr": 43,
    "icmp": 46, "fcmp": 47,
    "trunc": 48, "zext": 49, "sext": 50, "fptrunc": 51, "fpext": 52,
    "fptoui": 53, "fptosi": 54, "uitofp": 55, "sitofp": 56,
    "ptrtoint": 57, "inttoptr": 58, "bitcast": 59, "addrspacecast": 60,
    "phi": 61, "select": 62, "call": 63, "extractvalue": 64,
    "insertvalue": 65, "va_arg": 66, "landingpad": 67, "freeze": 68,
}
VOCAB_SIZE = 110

IDX_CONTEXT   = 0
IDX_ARGUMENT  = 1
IDX_MOCK      = 75
IDX_CONST_INT = 76
IDX_CONST_FP  = 77
IDX_UNDEF     = 78
IDX_UNKNOWN   = 79

_ICMP_PRED_RE = re.compile(r'\bicmp\s+(\w+)\b')
_FCMP_PRED_RE = re.compile(r'\bfcmp\s+(\w+)\b')

_ICMP_PRED_IDS: dict[str, int] = {
    "eq": 80,  "ne": 81,
    "slt": 82, "sle": 83, "sgt": 84, "sge": 85,
    "ult": 86, "ule": 87, "ugt": 88, "uge": 89,
}
_FCMP_PRED_IDS: dict[str, int] = {
    "false": 90, "oeq": 91, "ogt": 92, "oge": 93,
    "olt":  94,  "ole": 95, "one": 96, "ord": 97,
    "uno":  98,  "ueq": 99, "ugt": 100, "uge": 101,
    "ult":  102, "ule": 103, "une": 104, "true": 105,
}

VK_ARGUMENT     = 0
VK_BASIC_BLOCK  = 1
VK_FUNCTION     = 5
VK_GLOBAL_VAR   = 8
VK_UNDEF        = 14
VK_CONSTANT_INT = 18
VK_CONSTANT_FP  = 19
VK_INSTRUCTION  = 24
VK_POISON       = 25


def _instr_node_id(instr) -> int:
    op = instr.opcode
    if op == "icmp":
        m = _ICMP_PRED_RE.search(str(instr))
        if m:
            return _ICMP_PRED_IDS.get(m.group(1), IDX_UNKNOWN)
        return 46
    if op == "fcmp":
        m = _FCMP_PRED_RE.search(str(instr))
        if m:
            return _FCMP_PRED_IDS.get(m.group(1), IDX_UNKNOWN)
        return 47
    return OPCODE_VOCAB.get(op, IDX_UNKNOWN)


def _ptr_id(v) -> int:
    return ctypes.cast(v._ptr, ctypes.c_void_p).value


# ---------------------------------------------------------------------------
# Dangerous sink patterns (identical to preprocess_slice.py)
# ---------------------------------------------------------------------------

DANGEROUS_SINKS = frozenset({
    "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "memmove", "memset", "bcopy",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets", "scanf", "sscanf", "fscanf",
    "read", "recv", "recvfrom", "pread",
    "malloc", "calloc", "realloc", "free", "xmalloc", "xrealloc",
    "printf", "fprintf", "syslog", "err", "warn",
    # Integer conversion — unchecked return used as array index / size is a
    # common vulnerability pattern (scar_atoi in scarnet, CWE-190/191).
    "atoi", "atol", "atoll", "atof",
    "strtol", "strtoul", "strtoll", "strtoull", "strtod",
})

# Functions whose return value is user-controlled / network-facing input.
# A mock node for any of these in the slice means external data reaches the sink.
INPUT_SOURCES = frozenset({
    "read", "recv", "recvfrom", "pread",
    "fgets", "fread", "getline", "getdelim",
    "scanf", "sscanf", "fscanf",
    "gets",
})

_SINK_SUFFIXES = tuple(DANGEROUS_SINKS)


def _normalize_sink_name(name: str) -> str:
    """Strip compiler-added decorations to recover the base function name.

    Clang's FORTIFY_SOURCE replaces e.g. memcpy with __memcpy_chk — the
    resulting IR call is no longer in DANGEROUS_SINKS by exact match.
    Strip leading underscores and trailing _chk / _chk_warn suffixes so
    __memcpy_chk normalizes to memcpy and is recognized.
    """
    name = name.lstrip("_")
    for suffix in ("_chk_warn", "_chk"):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
            break
    return name


def _is_dangerous(name: str) -> bool:
    name = name.lstrip("@")
    if name in DANGEROUS_SINKS:
        return True
    # Normalize __foo_chk / __foo_chk_warn → foo before matching
    norm = _normalize_sink_name(name)
    if norm != name and norm in DANGEROUS_SINKS:
        return True
    for s in _SINK_SUFFIXES:
        if name.endswith(s) or name.endswith("_" + s):
            return True
    # LLVM memory intrinsics: e.g. llvm.memcpy.p0i8.p0i8.i64 / llvm.memcpy.p0.p0.i64
    for s in ("memcpy", "memmove", "memset", "bcopy"):
        if name.startswith(f"llvm.{s}."):
            return True
    return False


def _canonical_name(name: str) -> str:
    """Map IR callee name (including LLVM intrinsics) to canonical sink name."""
    name = name.lstrip("@")
    if name in DANGEROUS_SINKS:
        return name
    for s in ("memcpy", "memmove", "memset", "bcopy"):
        if name.startswith(f"llvm.{s}."):
            return s
    for s in _SINK_SUFFIXES:
        if name.endswith(s) or name.endswith("_" + s):
            return s
    return name


# ---------------------------------------------------------------------------
# PDG backward slice extractor
# ---------------------------------------------------------------------------

_CONSTANT_IDS = frozenset({IDX_CONST_INT, IDX_CONST_FP, IDX_UNDEF, IDX_CONTEXT})


def _extract_slice_pdg(x, edge_index, edge_type, mock_names,
                       instr_to_block, block_preds, block_last_instr):
    """
    PDG backward slice: DFG backward BFS + control dependence (block terminators).

    Fixed-point loop:
      1. DFG backward BFS from all visited nodes.
      2. For each newly visited instruction node, add the br/switch terminator
         of every CFG predecessor block (these have DFG edges from their icmp
         condition, so the guard comparison is pulled in on the next BFS pass).
      3. Repeat until stable.

    Returns None if no dangerous sinks found (caller falls back to full graph).
    """
    E = edge_index.shape[1] if edge_index.ndim == 2 and edge_index.shape[1] > 0 else 0

    fwd_dfg = defaultdict(list)
    rev_dfg = defaultdict(list)
    for i in range(E):
        if int(edge_type[i]) == 1:
            s, d = int(edge_index[0, i]), int(edge_index[1, i])
            fwd_dfg[s].append(d)
            rev_dfg[d].append(s)

    # Sink type 1: dangerous call sites
    dangerous_mocks = {nid for nid, nm in mock_names.items() if _is_dangerous(nm)}
    sink_ids:    set[int]       = set()
    sink_to_fn: dict[int, str] = {}   # old_node_id → dangerous function name
    for mid in dangerous_mocks:
        for consumer in fwd_dfg[mid]:
            if int(x[consumer, 0]) == 63:
                sink_ids.add(consumer)
                sink_to_fn[consumer] = _canonical_name(mock_names[mid])

    # Sink type 2: GEP or VLA alloca with non-constant operand
    # alloca(non-const) = variable-length array; same structural pattern as GEP
    for i in range(E):
        if int(edge_type[i]) == 1:
            s, d = int(edge_index[0, i]), int(edge_index[1, i])
            if int(x[d, 0]) in (29, 26) and int(x[s, 0]) not in _CONSTANT_IDS:
                sink_ids.add(d)

    if not sink_ids:
        return None

    visited      = set(sink_ids)
    ctrl_checked = set()

    changed = True
    while changed:
        changed = False

        # DFG backward BFS
        frontier = list(visited)
        while frontier:
            nxt = []
            for node in frontier:
                for pred in rev_dfg[node]:
                    if pred not in visited and pred != 0:
                        visited.add(pred)
                        nxt.append(pred)
                        changed = True
            frontier = nxt

        # Control dependence: add predecessor-block terminators for new nodes
        new_nodes = visited - ctrl_checked
        ctrl_checked |= new_nodes
        for node in new_nodes:
            block_id = instr_to_block.get(node)
            if block_id is None:
                continue
            for pred_block in block_preds.get(block_id, []):
                term_id = block_last_instr.get(pred_block)
                if term_id is not None and term_id not in visited and term_id != 0:
                    visited.add(term_id)
                    changed = True

    slice_nodes = sorted(visited)
    slice_size  = len(slice_nodes) + 1
    old_to_new  = {old: new + 1 for new, old in enumerate(slice_nodes)}

    if slice_size < 2:
        return None

    new_x = np.zeros((slice_size, 1), dtype=np.int64)
    new_x[0, 0] = IDX_CONTEXT
    for new_id, old_id in enumerate(slice_nodes, start=1):
        new_x[new_id, 0] = int(x[old_id, 0])

    # Map sink function names to new node indices
    sink_fn_names = {old_to_new[old_id]: fn
                     for old_id, fn in sink_to_fn.items()
                     if old_id in old_to_new}

    new_src, new_dst, new_et = [], [], []
    for i in range(E):
        et = int(edge_type[i])
        if et == 2:
            continue
        s, d = int(edge_index[0, i]), int(edge_index[1, i])
        if s in old_to_new and d in old_to_new:
            new_src.append(old_to_new[s])
            new_dst.append(old_to_new[d])
            new_et.append(et)

    for new_id in range(1, slice_size):
        new_src.extend([new_id, 0])
        new_dst.extend([0, new_id])
        new_et.extend([2, 2])

    new_edge_index = (np.array([new_src, new_dst], dtype=np.int64)
                      if new_src else np.zeros((2, 0), dtype=np.int64))
    new_edge_type  = (np.array(new_et, dtype=np.int64)
                      if new_et  else np.zeros(0, dtype=np.int64))

    # Collect input-source mock nodes that landed in the slice
    source_fn_names = {old_to_new[nid]: _canonical_name(mock_names[nid])
                       for nid, nm in mock_names.items()
                       if _canonical_name(nm) in INPUT_SOURCES
                       and nid in old_to_new}

    return {"x": new_x, "edge_index": new_edge_index, "edge_type": new_edge_type,
            "sink_fn_names": sink_fn_names, "source_fn_names": source_fn_names,
            "_sliced": True, "_n_sinks": len(sink_ids)}


# ---------------------------------------------------------------------------
# Graph builder — 5-pass algorithm + PDG slice extraction
# ---------------------------------------------------------------------------

def ir_to_graph_slice_pdg(ir_text, fn_name: str | None = None):
    """
    Build instruction-level graph then extract PDG backward slice.

    Additions over ir_to_graph_slice (§11):
    - Pass 1: instr_to_block tracks node_id → block ptr_id for instructions
    - Pass 2: block_preds and block_last_instr built alongside CFG edges
    - Calls _extract_slice_pdg() with control-dependence support

    fn_name: if given, select that specific function from a multi-function
             module. If None, picks the last non-declaration (single-function
             mode, original behaviour).

    Returns None if parsing fails or result has < 2 nodes.
    Caller adds 'y' and 'idx'.
    """
    try:
        mod = llvm.parse_assembly(ir_text)
    except Exception:
        return None

    target_fn = None
    for fn in mod.functions:
        if fn.is_declaration:
            continue
        if fn_name is None:
            target_fn = fn          # last non-declaration (original behaviour)
        elif fn.name == fn_name:
            target_fn = fn
            break
    if target_fn is None:
        return None

    # -- Pass 1: allocate nodes + track instruction→block membership ----------
    node_opcodes   = []
    ptr_to_id      = {}
    instr_to_block = {}   # node_id → block ptr_id (instructions only)
    node_counter   = 0

    node_opcodes.append(IDX_CONTEXT)
    node_counter = 1

    for arg in target_fn.arguments:
        ptr_to_id[_ptr_id(arg)] = node_counter
        node_opcodes.append(IDX_ARGUMENT)
        node_counter += 1

    block_first_instr = {}
    for block in target_fn.blocks:
        bpid = _ptr_id(block)
        first_in_block = True
        for instr in block.instructions:
            ipid = _ptr_id(instr)
            if first_in_block:
                block_first_instr[bpid] = node_counter
                first_in_block = False
            ptr_to_id[ipid]            = node_counter
            instr_to_block[node_counter] = bpid
            node_opcodes.append(_instr_node_id(instr))
            node_counter += 1

    if node_counter < 2:
        return None

    edges_src  = []
    edges_dst  = []
    edges_type = []

    # -- Pass 2: CFG edges + predecessor/terminator maps ----------------------
    block_preds      = defaultdict(list)
    block_last_instr = {}

    for block in target_fn.blocks:
        bpid    = _ptr_id(block)
        prev_id = None
        instrs  = list(block.instructions)
        for instr in instrs:
            cur_id = ptr_to_id[_ptr_id(instr)]
            if prev_id is not None:
                edges_src.append(prev_id)
                edges_dst.append(cur_id)
                edges_type.append(0)
            prev_id = cur_id
        if instrs:
            block_last_instr[bpid] = ptr_to_id[_ptr_id(instrs[-1])]
            terminator = instrs[-1]
            term_id    = ptr_to_id[_ptr_id(terminator)]
            for op in terminator.operands:
                if op.value_kind == VK_BASIC_BLOCK:
                    succ_bpid  = _ptr_id(op)
                    succ_first = block_first_instr.get(succ_bpid)
                    if succ_first is not None:
                        edges_src.append(term_id)
                        edges_dst.append(succ_first)
                        edges_type.append(0)
                    block_preds[succ_bpid].append(bpid)

    # -- Pass 3: DFG edges + mock name tracking --------------------------------
    constant_cache = {}
    mock_cache     = {}
    mock_names     = {}

    for block in target_fn.blocks:
        for instr in block.instructions:
            dst_id = ptr_to_id[_ptr_id(instr)]
            for op in instr.operands:
                vk = op.value_kind

                if vk == VK_INSTRUCTION or vk == VK_ARGUMENT:
                    src_id = ptr_to_id.get(_ptr_id(op))
                    if src_id is not None:
                        edges_src.append(src_id)
                        edges_dst.append(dst_id)
                        edges_type.append(1)

                elif vk == VK_CONSTANT_INT:
                    opid = _ptr_id(op)
                    if opid not in constant_cache:
                        constant_cache[opid] = node_counter
                        node_opcodes.append(IDX_CONST_INT)
                        node_counter += 1
                    edges_src.append(constant_cache[opid])
                    edges_dst.append(dst_id)
                    edges_type.append(1)

                elif vk == VK_CONSTANT_FP:
                    opid = _ptr_id(op)
                    if opid not in constant_cache:
                        constant_cache[opid] = node_counter
                        node_opcodes.append(IDX_CONST_FP)
                        node_counter += 1
                    edges_src.append(constant_cache[opid])
                    edges_dst.append(dst_id)
                    edges_type.append(1)

                elif vk in (VK_GLOBAL_VAR, VK_FUNCTION):
                    name = op.name
                    if name not in mock_cache:
                        mock_cache[name]     = node_counter
                        mock_names[node_counter] = name
                        node_opcodes.append(IDX_MOCK)
                        node_counter += 1
                    edges_src.append(mock_cache[name])
                    edges_dst.append(dst_id)
                    edges_type.append(1)

                elif vk in (VK_UNDEF, VK_POISON):
                    opid = _ptr_id(op)
                    if opid not in constant_cache:
                        constant_cache[opid] = node_counter
                        node_opcodes.append(IDX_UNDEF)
                        node_counter += 1
                    edges_src.append(constant_cache[opid])
                    edges_dst.append(dst_id)
                    edges_type.append(1)

    # -- Pass 4: global context edges (type 2) — bidirectional ----------------
    for i in range(1, node_counter):
        edges_src.extend([i, 0])
        edges_dst.extend([0, i])
        edges_type.extend([2, 2])

    x          = np.array(node_opcodes, dtype=np.int64).reshape(-1, 1)
    edge_index = (np.array([edges_src, edges_dst], dtype=np.int64)
                  if edges_src else np.zeros((2, 0), dtype=np.int64))
    edge_type  = (np.array(edges_type, dtype=np.int64)
                  if edges_type else np.zeros(0, dtype=np.int64))

    g = _extract_slice_pdg(x, edge_index, edge_type, mock_names,
                            instr_to_block, block_preds, block_last_instr)
    if g is None:
        g = {"x": x, "edge_index": edge_index, "edge_type": edge_type,
             "sink_fn_names": {}, "source_fn_names": {}, "_sliced": False, "_n_sinks": 0}

    return g


# ---------------------------------------------------------------------------
# Per-item processing
# ---------------------------------------------------------------------------

def process_item_slice_pdg(item):
    ir = compile_to_ir(item["func"])
    if ir is None:
        return None
    g = ir_to_graph_slice_pdg(ir)
    if g is None:
        return None
    g["y"]   = int(item["target"])
    g["idx"] = item.get("idx", 0)
    return g


def process_split_slice_pdg(jsonl_path, subset, workers, seed=42):
    with open(jsonl_path) as f:
        items = [json.loads(l) for l in f]

    rng = random.Random(seed)
    if subset:
        vuln  = [x for x in items if x["target"] == 1]
        fixed = [x for x in items if x["target"] == 0]
        rng.shuffle(vuln); rng.shuffle(fixed)
        items = vuln[:subset // 2] + fixed[:subset // 2]
    else:
        rng.shuffle(items)

    graphs, ok, fail = [], 0, 0
    total = len(items)
    print(f"  Processing {total} functions with {workers} workers ...")

    if workers == 1:
        for i, item in enumerate(items, 1):
            g = process_item_slice_pdg(item)
            if g:
                graphs.append(g); ok += 1
            else:
                fail += 1
            if i % 500 == 0:
                print(f"    {i}/{total}  ok={ok}  failed={fail}")
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(process_item_slice_pdg, it): it for it in items}
            for i, fut in enumerate(as_completed(futs), 1):
                g = fut.result()
                if g:
                    graphs.append(g); ok += 1
                else:
                    fail += 1
                if i % 500 == 0:
                    print(f"    {i}/{total}  ok={ok}  failed={fail}")

    attrition = fail / total * 100 if total > 0 else 0
    print(f"  Done: {ok} graphs built, {fail} failed ({attrition:.0f}% attrition)")

    node_counts = [g["x"].shape[0] for g in graphs]
    n_sliced    = sum(1 for g in graphs if g.get("_sliced", False))
    n_fallback  = ok - n_sliced
    if node_counts:
        print(f"  Slice stats: mean={np.mean(node_counts):.0f} nodes  "
              f"median={int(np.median(node_counts))}  max={max(node_counts)}")
        print(f"  Sliced: {n_sliced}/{ok} ({100*n_sliced/ok:.0f}%)  "
              f"Fallback (no sinks): {n_fallback}/{ok} ({100*n_fallback/ok:.0f}%)")

    for g in graphs:
        g.pop("_sliced", None)
        g.pop("_n_sinks", None)

    return graphs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subset",        type=int,  default=None)
    ap.add_argument("--workers",       type=int,  default=4)
    ap.add_argument("--seed",          type=int,  default=42)
    ap.add_argument("--skip-download", action="store_true")
    args = ap.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)

    if not args.skip_download:
        missing = any(not (DATA / f"{s}.jsonl").exists()
                      for s in ["train", "valid", "test"])
        if missing:
            print("\n-- Download --------------------------------------------------")
            download_devign()
        else:
            print("  data/*.jsonl present, skipping download.")

    for split in ["train", "valid", "test"]:
        src = DATA / f"{split}.jsonl"
        dst = DATA / f"{split}_slice_pdg_graphs.pkl"
        if not src.exists():
            print(f"Missing {src} -- run preprocess.py or drop --skip-download.")
            sys.exit(1)
        print(f"\n-- {split} ---------------------------------------------------")
        graphs = process_split_slice_pdg(src, subset=args.subset,
                                         workers=args.workers, seed=args.seed)
        with open(dst, "wb") as f:
            pickle.dump(graphs, f)
        print(f"  Saved {len(graphs)} graphs -> {dst}")

    print("\nDone. Run train_slice_pdg.py next.\n")


if __name__ == "__main__":
    main()
