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

import shutil
import subprocess

import numpy as np
import llvmlite.binding as llvm

HERE = Path(__file__).parent


_OPTNONE_RE = re.compile(r'\boptnone\b\s*')


def _strip_optnone(ir_text: str) -> str:
    """Remove optnone attribute from IR so mem2reg can promote allocas.

    clang -O0 sets the optnone function attribute, which causes opt to skip
    all optimization passes including mem2reg. Stripping it before running
    mem2reg is safe here — we only want SSA promotion for analysis, not
    full optimization.
    """
    return _OPTNONE_RE.sub('', ir_text)


def apply_mem2reg(ir_text: str) -> str:
    """Run mem2reg on IR text and return the promoted IR text.

    mem2reg promotes alloca/store/load patterns (emitted by clang -O0) into
    proper SSA registers. This makes data-flow analysis correct without
    requiring -O1 optimisations that would alter the vulnerability surface.

    Falls back to the original text if opt-20/opt is not available or fails.
    """
    # Strip optnone so opt does not skip -O0-compiled functions.
    prepped = _strip_optnone(ir_text)
    for opt in ("opt-20", "opt"):
        if not shutil.which(opt):
            continue
        try:
            r = subprocess.run(
                [opt, "-passes=sroa,mem2reg", "-S", "-o", "-", "-"],
                input=prepped, capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout
        except Exception:
            pass
    return ir_text
DATA = HERE / "data"

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

# Format-parsing functions: calling any of these on the data path means the
# input must conform to a structured format before the dangerous sink is reachable.
# Grouped by format family so the prompt module can name the format specifically.
FORMAT_PARSERS: dict[str, str] = {
    # PEM / base64
    "PEM_read_bio":         "PEM",
    "PEM_read_bio_ex":      "PEM",
    "PEM_read":             "PEM",
    "PEM_get_type":         "PEM",
    "EVP_DecodeBlock":      "base64",
    "EVP_DecodeUpdate":     "base64",
    "EVP_DecodeFinal":      "base64",
    "BIO_f_base64":         "base64",
    # ASN.1 / DER
    "d2i_X509":             "ASN.1/DER",
    "d2i_PKCS7":            "ASN.1/DER",
    "d2i_RSAPrivateKey":    "ASN.1/DER",
    "d2i_PrivateKey":       "ASN.1/DER",
    "d2i_PublicKey":        "ASN.1/DER",
    "ASN1_get_object":      "ASN.1/DER",
    "ASN1_item_d2i":        "ASN.1/DER",
    # BIO delimiter scanning (PEM header / line-based format gates)
    "BIO_gets":             "line-delimited",
    # Archive / compression
    "inflate":              "zlib",
    "inflateInit":          "zlib",
    "inflateInit2":         "zlib",
    "deflate":              "zlib",
    "BZ2_bzDecompress":     "bzip2",
    "LZ4_decompress_safe":  "lz4",
    # JSON / XML / structured text
    "json_tokener_parse":   "JSON",
    "xmlParseDoc":          "XML",
    "xmlReadMemory":        "XML",
    "cJSON_Parse":          "JSON",
    # TLS / protocol record layers
    "ssl3_get_record":      "TLS",
    "tls1_process_heartbeat": "TLS",
    # HTTP
    "http_parser_execute":  "HTTP",
    "llhttp_execute":       "HTTP",
}

_SINK_SUFFIXES = tuple(DANGEROUS_SINKS)

_STRCMP_FNS = frozenset({
    "strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp",
})


def _extract_str_globals(ir_text: str) -> dict[str, str]:
    """Return {global_name: decoded_string} for all i8-array string constants.

    Handles LLVM IR string escapes (\\XX hex only).  Strips trailing null bytes.
    """
    result: dict[str, str] = {}
    pattern = re.compile(
        r'@([\w.$]+)\s*=.*?constant\s+\[\d+\s+x\s+i8\]\s+c"((?:[^"\\]|\\[0-9a-fA-F]{2})*)"'
    )
    for m in pattern.finditer(ir_text):
        name = m.group(1)
        raw  = m.group(2)
        decoded = re.sub(r'\\([0-9a-fA-F]{2})',
                         lambda h: chr(int(h.group(1), 16)), raw)
        result[name] = decoded.rstrip('\x00')
    return result


def _detect_strcmp_guards(target_fn, str_globals: dict[str, str]) -> list[dict]:
    """Scan target_fn body for strcmp/strncmp/memcmp calls against a string literal.

    Returns list of {"fn": "strcmp", "literal": "scarnet123"}.  Does not require
    the strcmp to be in the backward slice — any strcmp-against-literal in the
    function body is reported, because any such gate can block fuzzer coverage.

    Handles both modern opaque-pointer IR (ptr @.str directly as an operand) and
    older typed-pointer IR (getelementptr inbounds @.str → VK_INSTRUCTION operand).
    """
    guards: list[dict] = []
    seen_lits: set[str] = set()

    # Build argument identity map: ptr_id → 0-based argument index in target_fn.
    arg_ptr_ids: dict[int, int] = {}
    for idx, arg in enumerate(target_fn.arguments):
        arg_ptr_ids[_ptr_id(arg)] = idx

    # At -O0, clang stores each argument into a local alloca immediately on entry.
    # Track alloca ptr_id → function argument index so we can trace strcmp operands
    # through the load/store chain back to the originating function argument.
    alloca_to_arg: dict[int, int] = {}
    for block in target_fn.blocks:
        for instr in block.instructions:
            if instr.opcode != "store":
                continue
            ops = list(instr.operands)
            if len(ops) < 2:
                continue
            val_op, ptr_op = ops[0], ops[1]
            if ptr_op.value_kind != VK_INSTRUCTION:
                continue
            if val_op.value_kind == VK_ARGUMENT:
                aidx = arg_ptr_ids.get(_ptr_id(val_op))
                if aidx is not None:
                    alloca_to_arg[_ptr_id(ptr_op)] = aidx

    # Build ptr_id → Instruction map for this function so we can follow
    # load → alloca chains without relying on Value.operands (which llvmlite
    # only supports on Instruction objects, not on generic Value operands).
    instr_by_pid: dict[int, object] = {}
    for block in target_fn.blocks:
        for instr in block.instructions:
            instr_by_pid[_ptr_id(instr)] = instr

    def _trace_to_fn_arg(op, _depth: int = 0) -> "int | None":
        """Return the 0-based function argument index that op ultimately loads from.

        Handles:
          - direct argument reference (VK_ARGUMENT)
          - load from an alloca that stored a function argument (-O0 pattern)
          - getelementptr (struct field / array index access): follow the base
            pointer operand, which is itself a load from an alloca holding the
            struct pointer argument (e.g. cmd->verb where cmd is arg 0)
        """
        if _depth > 4:  # guard against pathological chains
            return None
        if op.value_kind == VK_ARGUMENT:
            return arg_ptr_ids.get(_ptr_id(op))
        if op.value_kind == VK_INSTRUCTION:
            instr = instr_by_pid.get(_ptr_id(op))
            if instr is None:
                return None
            try:
                ops = list(instr.operands)
            except Exception:
                return None
            if instr.opcode == "load":
                if not ops:
                    return None
                alloca_op = ops[0]  # pointer operand of the load
                # Direct load-from-alloca-of-arg
                result = alloca_to_arg.get(_ptr_id(alloca_op))
                if result is not None:
                    return result
                # May be a load of a pointer that itself needs tracing (e.g.
                # loading the struct pointer before a GEP)
                return _trace_to_fn_arg(alloca_op, _depth + 1)
            if instr.opcode == "getelementptr":
                # ops[0] is the base pointer (the struct or array being indexed).
                # Trace through it to find the originating function argument.
                if not ops:
                    return None
                return _trace_to_fn_arg(ops[0], _depth + 1)
        return None

    for block in target_fn.blocks:
        for instr in block.instructions:
            if instr.opcode != "call":
                continue
            ops = list(instr.operands)
            # The callee is the last operand in llvmlite's operand list and has
            # VK_FUNCTION kind.  Check VK_FUNCTION first; fall back to VK_GLOBAL_VAR
            # only when no VK_FUNCTION operand is present (indirect call via function
            # pointer stored in a global).  This prevents @.str global arguments from
            # being mistaken for the callee.
            callee_name = ""
            for op in ops:
                if op.value_kind == VK_FUNCTION:
                    callee_name = _normalize_sink_name(op.name.lstrip("@"))
                    break
            if not callee_name:
                for op in ops:
                    if op.value_kind == VK_GLOBAL_VAR:
                        callee_name = _normalize_sink_name(op.name.lstrip("@"))
                        break
            if callee_name not in _STRCMP_FNS:
                continue

            # Find the literal operand and the non-literal operand.
            # The non-literal operand is traced back to the target function's
            # argument index — that is the parameter the harness should fuzz.
            # const_arg_idx is the strcmp-call argument index (for display);
            # fuzz_fn_arg_idx is the function-level parameter index to fuzz.
            str_arg_call_idx:  "int | None" = None
            lit_found:         "str | None" = None
            non_const_op  = None

            call_arg_idx = 0
            for op in ops:
                if op.value_kind == VK_FUNCTION:
                    continue  # callee
                if op.value_kind == VK_GLOBAL_VAR:
                    gname = op.name.lstrip("@")
                    if gname in str_globals:
                        str_arg_call_idx = call_arg_idx
                        lit_found        = str_globals[gname]
                    else:
                        non_const_op = op
                elif op.value_kind == VK_INSTRUCTION:
                    # Typed-pointer GEP into @.str
                    try:
                        gep_ops = list(op.operands)
                    except Exception:
                        non_const_op = op
                        call_arg_idx += 1
                        continue
                    if gep_ops and gep_ops[0].value_kind == VK_GLOBAL_VAR:
                        gname = gep_ops[0].name.lstrip("@")
                        if gname in str_globals:
                            str_arg_call_idx = call_arg_idx
                            lit_found        = str_globals[gname]
                        else:
                            non_const_op = op
                    else:
                        non_const_op = op
                else:
                    non_const_op = op
                call_arg_idx += 1

            if lit_found is not None and lit_found not in seen_lits:
                seen_lits.add(lit_found)
                fuzz_fn_arg_idx = (
                    _trace_to_fn_arg(non_const_op) if non_const_op is not None
                    else None
                )
                guards.append({
                    "fn":               callee_name,
                    "literal":          lit_found,
                    "const_arg_idx":    str_arg_call_idx,   # strcmp arg position
                    "fuzz_fn_arg_idx":  fuzz_fn_arg_idx,    # function param to fuzz
                })

    return guards


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
_DIV_OPCODES  = frozenset({5, 6, 7, 8})    # udiv, sdiv, urem, srem


def _extract_slice_pdg(x, edge_index, edge_type, mock_names,
                       instr_to_block, block_preds, block_last_instr,
                       extra_sinks: frozenset | None = None,
                       mock_is_function: set | None = None):
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
    def _is_sink(name: str) -> bool:
        return _is_dangerous(name) or (extra_sinks is not None and name in extra_sinks)

    # Sinks where the *length* argument makes the call dangerous only when
    # non-constant. If the length is a compile-time constant (e.g. sizeof(struct)),
    # the call is bounded and is not a taint-flow risk.
    # Argument index of the length parameter (0-based, after the callee mock):
    #   memcpy/memmove/memset/bcopy: arg2 (dst, src, len)
    #   strncpy/strncat:             arg2 (dst, src, n)
    #   snprintf/vsnprintf:          arg1 (buf, size, fmt, ...)
    #   fgets:                       arg1 (buf, size, stream)
    #   read/recv/recvfrom/pread:    arg2 (buf, len, ...)
    _LENGTH_ARG_IDX: dict[str, int] = {
        "memcpy": 2, "memmove": 2, "memset": 2, "bcopy": 2,
        "strncpy": 2, "strncat": 2,
        "snprintf": 1, "vsnprintf": 1,
        "fgets": 1,
        "read": 2, "recv": 2, "recvfrom": 2, "pread": 2,
    }

    # Build ordered DFG predecessor list per call node. llvmlite iterates
    # instr.operands as [arg0, arg1, ..., argN, callee_fn] — callee is last.
    # So call_dfg_preds[call_node] = [arg0_id, arg1_id, ..., argN_id, mock_id].
    # _LENGTH_ARG_IDX values are 0-based argument indices, which map directly
    # to pred list indices (callee at the end doesn't shift arg positions).
    call_dfg_preds: dict[int, list[int]] = {}
    for i in range(E):
        if int(edge_type[i]) == 1:
            s, d = int(edge_index[0, i]), int(edge_index[1, i])
            if int(x[d, 0]) == 63:   # call instruction opcode
                call_dfg_preds.setdefault(d, []).append(s)

    dangerous_mocks = {nid for nid, nm in mock_names.items() if _is_sink(nm)}
    sink_ids:    set[int]       = set()
    sink_to_fn: dict[int, str] = {}   # old_node_id → dangerous function name
    for mid in dangerous_mocks:
        canon = _canonical_name(mock_names[mid])
        len_idx = _LENGTH_ARG_IDX.get(canon)
        for consumer in fwd_dfg[mid]:
            if int(x[consumer, 0]) != 63:
                continue
            if len_idx is not None:
                preds = call_dfg_preds.get(consumer, [])
                if len(preds) > len_idx and int(x[preds[len_idx], 0]) in _CONSTANT_IDS:
                    continue   # constant-length call — not a dangerous sink
            sink_ids.add(consumer)
            sink_to_fn[consumer] = canon

    # Sink type 2: GEP or VLA alloca with non-constant operand
    # alloca(non-const) = variable-length array; same structural pattern as GEP
    for i in range(E):
        if int(edge_type[i]) == 1:
            s, d = int(edge_index[0, i]), int(edge_index[1, i])
            if int(x[d, 0]) in (29, 26) and int(x[s, 0]) not in _CONSTANT_IDS:
                sink_ids.add(d)

    # Sink type 3: div/rem instruction whose divisor (second operand, index 1) is non-constant.
    # The first DFG edge into a div/rem node is the dividend (index 0), the second is the divisor.
    # We flag div/rem only when the divisor is non-constant — a constant divisor can never be zero.
    # Track per-node edge count to identify the divisor edge (second DFG predecessor).
    div_dfg_preds: dict[int, list[int]] = {}   # node_id → [dfg_preds in order seen]
    for i in range(E):
        if int(edge_type[i]) == 1:
            s, d = int(edge_index[0, i]), int(edge_index[1, i])
            if int(x[d, 0]) in _DIV_OPCODES:
                div_dfg_preds.setdefault(d, []).append(s)
    for node_id, preds in div_dfg_preds.items():
        # In LLVM IR, operand order is [dividend, divisor]; divisor is the second operand.
        if len(preds) >= 2:
            divisor_src = preds[1]
            if int(x[divisor_src, 0]) not in _CONSTANT_IDS:
                sink_ids.add(node_id)
        elif preds:
            # Only one predecessor visible — flag conservatively when non-constant.
            if int(x[preds[0], 0]) not in _CONSTANT_IDS:
                sink_ids.add(node_id)

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

    # Record which old node IDs are div/rem sinks (for post-mapping below).
    _OPCODE_TO_DIVNAME = {5: "udiv", 6: "sdiv", 7: "urem", 8: "srem"}
    div_sink_old_ids: dict[int, str] = {
        nid: _OPCODE_TO_DIVNAME[int(x[nid, 0])]
        for nid in sink_ids & div_dfg_preds.keys()
    }

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

    # Map div/rem sink opcodes to new node indices
    div_sink_names = {old_to_new[old_id]: opname
                      for old_id, opname in div_sink_old_ids.items()
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

    # Global variables accessed in the slice (not sinks, not input sources).
    # These are file-scope state the function reads — relevant for harness init
    # when the function has internal linkage and @main is suppressed.
    _sink_names  = {_canonical_name(nm) for nm in sink_fn_names.values()}
    _input_names = set(INPUT_SOURCES)
    _fn_nodes = mock_is_function or set()
    global_vars_read = sorted({
        _canonical_name(nm)
        for nid, nm in mock_names.items()
        if nid in old_to_new
        and nid not in _fn_nodes              # exclude VK_FUNCTION entries
        and _canonical_name(nm) not in _sink_names
        and _canonical_name(nm) not in _input_names
        and not _is_sink(_canonical_name(nm))
        and not nm.startswith(".str")   # string literal constants, not state
        and not nm.startswith(".L")     # compiler-generated labels
    })

    return {"x": new_x, "edge_index": new_edge_index, "edge_type": new_edge_type,
            "sink_fn_names": sink_fn_names, "source_fn_names": source_fn_names,
            "div_sink_names": div_sink_names,
            "global_vars_read": global_vars_read,
            "_sliced": True, "_n_sinks": len(sink_ids)}


# ---------------------------------------------------------------------------
# Graph builder — 5-pass algorithm + PDG slice extraction
# ---------------------------------------------------------------------------

def ir_to_graph_slice_pdg(ir_text, fn_name: str | None = None,
                          extra_modules=None,
                          extra_sinks: frozenset | None = None):
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
        mod = llvm.parse_assembly(apply_mem2reg(ir_text))
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
    mock_cache        = {}
    mock_names        = {}
    mock_is_function  = set()  # node IDs added as VK_FUNCTION (not global vars)

    # Pre-pass: record store mappings so load instructions can trace values back
    # through alloca/store/load chains. At -O0, clang emits alloca+store+load for
    # every local variable instead of SSA form, breaking the backward BFS: the
    # DFG edge from load → alloca stops at the alloca, which has no incoming edge
    # from the stored argument. Collect alloca_ptr_id → [stored_val_node_id] here;
    # inject synthetic DFG edges (stored_val → load) below.
    alloca_stored_vals: dict[int, list[int]] = defaultdict(list)
    for block in target_fn.blocks:
        for instr in block.instructions:
            if instr.opcode != "store":
                continue
            ops = list(instr.operands)
            if len(ops) < 2:
                continue
            val_op, ptr_op = ops[0], ops[1]
            # Only bridge when the write target is a local alloca (VK_INSTRUCTION)
            if ptr_op.value_kind != VK_INSTRUCTION:
                continue
            ptr_pid = _ptr_id(ptr_op)
            if ptr_pid not in ptr_to_id:
                continue
            if val_op.value_kind in (VK_INSTRUCTION, VK_ARGUMENT):
                val_pid = _ptr_id(val_op)
                if val_pid in ptr_to_id:
                    alloca_stored_vals[ptr_pid].append(ptr_to_id[val_pid])

    for block in target_fn.blocks:
        for instr in block.instructions:
            dst_id = ptr_to_id[_ptr_id(instr)]

            # Synthetic store→load bridge: when a load reads from an alloca that
            # has stored values (args or computed values), add a direct DFG edge
            # from those values to this load node so the backward BFS can reach
            # function arguments through -O0 alloca/store/load sequences.
            if instr.opcode == "load":
                load_ops = list(instr.operands)
                if load_ops and load_ops[0].value_kind == VK_INSTRUCTION:
                    ptr_pid = _ptr_id(load_ops[0])
                    for stored_src_id in alloca_stored_vals.get(ptr_pid, ()):
                        edges_src.append(stored_src_id)
                        edges_dst.append(dst_id)
                        edges_type.append(1)

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
                        mock_cache[name]          = node_counter
                        mock_names[node_counter]  = name
                        if vk == VK_FUNCTION:
                            mock_is_function.add(node_counter)
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
                            instr_to_block, block_preds, block_last_instr,
                            extra_sinks=extra_sinks,
                            mock_is_function=mock_is_function)
    if g is None:
        g = {"x": x, "edge_index": edge_index, "edge_type": edge_type,
             "sink_fn_names": {}, "source_fn_names": {}, "div_sink_names": {},
             "global_vars_read": [],
             "_sliced": False, "_n_sinks": 0}

    # strcmp-against-literal gates: detect hardcoded credential checks that block
    # fuzzer coverage.  Scan the full IR text for @.str globals first.
    str_globals  = _extract_str_globals(ir_text)
    strcmp_guards = _detect_strcmp_guards(target_fn, str_globals)
    g["strcmp_guards"] = strcmp_guards

    # Dominator gate extraction (P-08a): walk CFG predecessors from sink-containing
    # blocks to function entry, collect icmp/switch against literal integer constants.
    # These are the format gates the fuzzer must satisfy to reach the dangerous sink.
    sink_fn_names_for_gates = g.get("sink_fn_names", {})
    dom_gates = _extract_dom_gates(target_fn, block_preds, ptr_to_id,
                                   sink_fn_names_for_gates)
    g["dom_gates"] = dom_gates

    # Format gate detection (P2.2): detect known format-parsing calls in the
    # function body — signals that input must conform to a structured format.
    g["format_gates"] = _extract_format_gates(target_fn, mock_names)

    # Count function arguments so the split-input hint can reference them by name.
    g["arg_count"] = sum(1 for _ in target_fn.arguments)

    # Attach free-pairing analysis (intra-procedural; independent of slice).
    free_info = _detect_double_free(target_fn)
    g["double_free"]    = free_info["double_free"]
    g["use_after_free"] = free_info["use_after_free"]
    g["freed_ptrs"]     = free_info["freed_ptrs"]

    # Shallow caller guard check: look for icmp in any direct caller.
    # extra_modules lets score_deterministic pass all loaded modules for cross-file coverage.
    if target_fn is not None and fn_name is not None:
        all_mods = [mod] + (list(extra_modules) if extra_modules else [])
        caller_info = _check_caller_guards(all_mods, target_fn.name)
        g["caller_count"]     = caller_info["caller_count"]
        g["caller_validated"] = caller_info["caller_validated"]
        g["caller_names"]     = caller_info["caller_names"]
    else:
        g["caller_count"]     = 0
        g["caller_validated"] = False
        g["caller_names"]     = []

    return g


# ---------------------------------------------------------------------------
# Dominator gate extractor — P-08a
# ---------------------------------------------------------------------------

_ICMP_LIT_RE = re.compile(
    r'\bicmp\s+\w+\s+\S+\s*,\s*(-?\d+|0[xX][0-9a-fA-F]+)\b'
)
_SWITCH_LIT_RE = re.compile(r'\bi(\d+)\s+(-?\d+|0[xX][0-9a-fA-F]+)\s*,')


def _extract_dom_gates(target_fn, block_preds: dict, ptr_to_id: dict,
                       sink_fn_names: dict) -> list[dict]:
    """Walk CFG predecessors from sink-containing blocks to entry.

    Collects icmp/switch instructions with a literal integer operand that
    dominate the path to the sink — these are the gates the fuzzer must
    satisfy to reach the dangerous sink.

    Returns a list of dicts:
      {"kind": "icmp"|"switch", "pred": str, "value": int, "hex": str,
       "ir_snippet": str}

    Scope: only literal (compile-time constant) operands. Struct-field loads
    and pointer comparisons are excluded — they are not extractable constraints.
    """
    # Map block ptr_id → list of instructions in that block
    block_instrs: dict[int, list] = {}
    for block in target_fn.blocks:
        bpid = _ptr_id(block)
        block_instrs[bpid] = list(block.instructions)

    # Find which blocks contain a dangerous sink call
    sink_call_ptrs: set[int] = set()
    for block in target_fn.blocks:
        bpid = _ptr_id(block)
        for instr in block_instrs[bpid]:
            if instr.opcode != "call":
                continue
            for op in instr.operands:
                if op.value_kind in (VK_FUNCTION, VK_GLOBAL_VAR):
                    name = _normalize_sink_name(op.name.lstrip("@"))
                    if name in sink_fn_names.values() or _is_dangerous(name):
                        sink_call_ptrs.add(bpid)
                        break

    if not sink_call_ptrs:
        return []

    # BFS upward through block_preds from sink blocks
    visited_blocks: set[int] = set(sink_call_ptrs)
    frontier = list(sink_call_ptrs)
    while frontier:
        nxt = []
        for bpid in frontier:
            for pred_bpid in block_preds.get(bpid, []):
                if pred_bpid not in visited_blocks:
                    visited_blocks.add(pred_bpid)
                    nxt.append(pred_bpid)
        frontier = nxt

    # Collect icmp/switch with literal operands from all visited blocks
    gates: list[dict] = []
    seen_values: set[int] = set()

    for bpid in visited_blocks:
        for instr in block_instrs.get(bpid, []):
            ir_text = str(instr).strip()

            if instr.opcode == "icmp":
                ops = list(instr.operands)
                # icmp: operands are [lhs, rhs] — look for a constant int rhs
                # Skip if the non-constant operand is a call return value:
                # those are error-check patterns (e.g. "if (EVP_Decode... < 0)")
                # not format gates on input data.
                const_val    = None
                non_const_op = None
                pred_str     = ""
                m_pred = _ICMP_PRED_RE.search(ir_text)
                if m_pred:
                    pred_str = m_pred.group(1)
                for op in ops:
                    if op.value_kind == VK_CONSTANT_INT:
                        m = re.search(r'i\d+\s+(-?\d+|0[xX][0-9a-fA-F]+)', str(op))
                        if m:
                            raw = m.group(1)
                            try:
                                const_val = int(raw, 0)
                            except ValueError:
                                pass
                    elif op.value_kind == VK_INSTRUCTION:
                        non_const_op = op
                # Reject: non-const side is a call result (error check, not input gate)
                if non_const_op is not None and non_const_op.value_kind == VK_INSTRUCTION:
                    try:
                        non_const_instr = next(
                            i for block in target_fn.blocks
                            for i in block.instructions
                            if _ptr_id(i) == _ptr_id(non_const_op)
                        )
                        if non_const_instr.opcode == "call":
                            continue
                    except StopIteration:
                        pass
                if const_val is not None and const_val not in seen_values:
                    seen_values.add(const_val)
                    gates.append({
                        "kind":       "icmp",
                        "pred":       pred_str,
                        "value":      const_val,
                        "hex":        hex(const_val & 0xFFFFFFFFFFFFFFFF),
                        "ir_snippet": ir_text[:120],
                    })

            elif instr.opcode == "switch":
                # switch i<N> %val, label %default [ i<N> <val>, label %bb ... ]
                for m in _SWITCH_LIT_RE.finditer(ir_text):
                    try:
                        const_val = int(m.group(2), 0)
                    except ValueError:
                        continue
                    if const_val not in seen_values:
                        seen_values.add(const_val)
                        gates.append({
                            "kind":       "switch",
                            "pred":       "eq",
                            "value":      const_val,
                            "hex":        hex(const_val & 0xFFFFFFFFFFFFFFFF),
                            "ir_snippet": ir_text[:120],
                        })

    return gates


# ---------------------------------------------------------------------------
# Format gate extractor — P2.2
# ---------------------------------------------------------------------------

def _extract_format_gates(target_fn, mock_names: dict) -> list[dict]:
    """Detect format-parsing calls anywhere in the function body.

    Scans all call instructions in target_fn. When a callee matches
    FORMAT_PARSERS, records the format family. The presence of a format
    parser indicates that the input must conform to a structured format
    before any dangerous sink is reachable — random bytes will be rejected
    at the parser boundary.

    Returns list of dicts:
      {"fn": str, "format": str}  — callee name and format family label
    """
    seen_formats: set[str] = set()
    gates: list[dict] = []

    for block in target_fn.blocks:
        for instr in block.instructions:
            if instr.opcode != "call":
                continue
            for op in instr.operands:
                if op.value_kind not in (VK_FUNCTION, VK_GLOBAL_VAR):
                    continue
                callee = op.name.lstrip("@")
                fmt = FORMAT_PARSERS.get(callee)
                if fmt and fmt not in seen_formats:
                    seen_formats.add(fmt)
                    gates.append({"fn": callee, "format": fmt})
                break  # callee found, move to next instruction

    return gates


# ---------------------------------------------------------------------------
# Shallow caller guard check (1-level-up, intra-module)
# ---------------------------------------------------------------------------

def _check_caller_guards(modules, fn_name: str) -> dict:
    """
    Check whether any direct caller of fn_name has an icmp guard — searched
    across all provided modules (cross-file aware).

    modules: single llvmlite module OR list of modules. Passing all loaded
             modules catches callers defined in different compilation units.

    Returns dict:
      caller_count     int  — number of distinct callers found
      caller_validated bool — at least one caller has an icmp
      caller_names     list — names of functions that call fn_name
    """
    if not isinstance(modules, (list, tuple)):
        modules = [modules]

    callers_with_guard: list[str] = []
    all_callers:        list[str] = []

    for mod in modules:
        for fn in mod.functions:
            if fn.is_declaration or fn.name == fn_name:
                continue

            fn_calls_target = False
            caller_has_icmp = False

            for block in fn.blocks:
                for instr in block.instructions:
                    if instr.opcode == "call":
                        for op in instr.operands:
                            if op.value_kind in (VK_FUNCTION, VK_GLOBAL_VAR) and op.name == fn_name:
                                fn_calls_target = True
                    elif instr.opcode == "icmp":
                        caller_has_icmp = True

            if fn_calls_target:
                all_callers.append(fn.name)
                if caller_has_icmp:
                    callers_with_guard.append(fn.name)

    return {
        "caller_count":     len(all_callers),
        "caller_validated": bool(callers_with_guard),
        "caller_names":     all_callers,
    }


# ---------------------------------------------------------------------------
# Double-free / use-after-free detector (intra-procedural, SSA names)
# ---------------------------------------------------------------------------

def _detect_double_free(fn) -> dict:
    """
    Detect double-free and use-after-free using llvmlite operand identity.

    Tracks freed pointers by their llvmlite value identity (_ptr_id), not by
    SSA name text — so bitcast wrappers and type-cast aliases are handled
    transparently. Also walks through bitcast/inttoptr chains to normalise the
    canonical pointer identity before comparing.

    State machine per pointer:
      LIVE  → free(p) → FREED
      FREED → free(p) again         → double_free
      FREED → load/store/call(p)    → use_after_free

    Returns dict:
      double_free    bool — same canonical ptr freed twice
      use_after_free bool — ptr used after first free
      freed_ptrs     list — SSA display names of freed pointers
    """
    # freed_ids: canonical ptr_id → SSA display name (from str(op))
    freed_ids:  dict[int, str] = {}
    double_free    = False
    use_after_free = False

    def _canonical_ptr_id(op):
        """Follow bitcast/inttoptr/load-from-alloca chains to the base value.

        At -O0 LLVM stores pointers to alloca slots and loads them before
        each use. Two loads from the same alloca have different SSA ids but
        the same underlying storage. We peel through load instructions back
        to their alloca source so the double-free detector sees the same
        canonical id regardless of which load produced the freed pointer.
        """
        seen = set()
        while True:
            pid = _ptr_id(op)
            if pid in seen:
                break
            seen.add(pid)
            if op.value_kind != VK_INSTRUCTION:
                break
            try:
                ops = list(op.operands)
            except Exception:
                break
            op_str = str(op)
            # load ptr from an alloca slot — peel through to the alloca
            if "load" in op_str and len(ops) >= 1:
                src = ops[0]
                if src.value_kind == VK_INSTRUCTION and "alloca" in str(src):
                    op = src
                    continue
            # single-operand cast (bitcast / inttoptr / addrspacecast)
            if len(ops) == 1 and ops[0].value_kind in (VK_INSTRUCTION, VK_ARGUMENT):
                op = ops[0]
            else:
                break
        return _ptr_id(op)

    for block in fn.blocks:
        for instr in block.instructions:
            opc = instr.opcode

            if opc == "call":
                ops = list(instr.operands)
                # Last operand of a call is the callee function reference
                callee_name = ""
                for op in ops:
                    if op.value_kind in (VK_FUNCTION, VK_GLOBAL_VAR):
                        callee_name = op.name
                        break

                norm = _normalize_sink_name(callee_name.lstrip("@"))
                is_free_call = (norm == "free" or
                                (norm.endswith("free") and _is_dangerous(callee_name)))

                if is_free_call:
                    # First non-callee operand is the pointer argument
                    ptr_op = None
                    for op in ops:
                        if op.value_kind not in (VK_FUNCTION, VK_GLOBAL_VAR):
                            ptr_op = op
                            break
                    if ptr_op is not None:
                        cid = _canonical_ptr_id(ptr_op)
                        if cid in freed_ids:
                            double_free = True
                        else:
                            freed_ids[cid] = str(ptr_op).split()[-1]
                else:
                    # Non-free call: check if any argument is a freed pointer
                    if not use_after_free and freed_ids:
                        for op in ops:
                            if op.value_kind in (VK_FUNCTION, VK_GLOBAL_VAR):
                                continue
                            if _canonical_ptr_id(op) in freed_ids:
                                use_after_free = True
                                break

            elif opc == "load" and freed_ids:
                # load's first operand is the pointer being read
                ops = list(instr.operands)
                if ops and _canonical_ptr_id(ops[0]) in freed_ids:
                    use_after_free = True

            elif opc == "store" and freed_ids:
                # store val, ptr — second operand is the pointer
                ops = list(instr.operands)
                if len(ops) >= 2 and _canonical_ptr_id(ops[1]) in freed_ids:
                    use_after_free = True

    return {
        "double_free":    double_free,
        "use_after_free": use_after_free,
        "freed_ptrs":     list(freed_ids.values()),
    }


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
    import sys as _sys
    _sys.path.insert(0, str(HERE))
    from preprocess import compile_to_ir, download_devign  # noqa: F401 — Devign batch only

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
