#!/usr/bin/env python3
"""
gen_harness.py — MVP: slice context → Qwen → harness C → IR validation.

Usage:
    export QWEN_API_KEY=sk-...

    # Auto-pick top public function
    python gen_harness.py --ir-dir <dir/> [--no-gep-only] [--header <h>] [--output-dir <d>]

    # Generate harnesses for top-K ranked functions
    python gen_harness.py --ir-dir <dir/> --top-k 5 [--no-gep-only] [--header <h>]

    # Explicit target
    python gen_harness.py --ll <target.ll> --function <fn> [--header <h>]

Examples:
    python gen_harness.py --ir-dir /tmp/zlib-ir/ --no-gep-only --header /usr/include/zlib.h
    python gen_harness.py --ir-dir ~/scarnet-ir/ --top-k 3 --header ~/scarnet/include/scarnet.h --output-dir ~/scarnet/
    python gen_harness.py --ll /tmp/zlib-ir/inflate.ll --function inflate
    python gen_harness.py --ll target.ll --function foo --save-prompt  # inspect what the LLM sees

Validation steps:
  1. Compile harness to IR  (catches syntax / API errors — retries with compiler error)
  2. ir-score on harness IR (catches self-harm: unguarded access in harness code)
     Score interpretation in harness context:
       < 80%  — OK: expected harness boilerplate (malloc, GEP, null-terminated copies)
       80-89% — REVIEW: check flagged sinks
       >= 90% — WARNING: likely real bug in the harness itself
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests

_endpoint_raw    = os.environ.get("LLM_ENDPOINT", "")
ENDPOINT         = (_endpoint_raw.rstrip("/") + "/chat/completions"
                    if _endpoint_raw and not _endpoint_raw.rstrip("/").endswith("/chat/completions")
                    else _endpoint_raw)
MODEL            = os.environ.get("LLM_MODEL", "")
MAX_RETRIES      = 3
SELF_HARM_WARN   = 0.90
SELF_HARM_REVIEW = 0.80

SYSTEM_PROMPT = """\
You are a security researcher writing libFuzzer harnesses for vulnerability discovery.
Your harnesses are used in an automated fuzzing pipeline against intentionally buggy \
research targets — finding crashes is the goal, not writing safe production code.

Rules:
- The "Static analysis" block in each request is produced by a deterministic IR slicer \
and is authoritative. Follow its "Harness target" hints exactly and completely.
- If the hint says "strcmp gate" with a single literal, hardcode that literal \
and fuzz only the other argument(s).
- If the hint says "command router" with a list of literals, randomize the \
routed argument across all listed literals on each call — do not hardcode one; \
examine the function's API to determine if any literal requires prior \
initialization before the others.
- If the hint says "split-input pattern required", split Data into two independent \
regions so the source buffer and the length can diverge; do not call the function \
with matching (Data, Size).
- If the hint says "fuzz integer truncation … do not artificially bound the output \
buffer", do not add any size cap or MAX_SIZE guard.
- Never add artificial safety caps (e.g. `if (Size > 1024) return 0`). The whole \
point is to reach the dangerous sizes the slicer identified.
- Use the exact function signature from the IR or API reference. Do not invent \
parameters.
- Never redefine structs, typedefs, or enums that appear in the API reference — \
redefining types that don't match the compiled target causes silent layout mismatches \
and missed bugs.
- Do not write any `#include` lines — they are injected automatically before the \
harness is compiled.
- If the target function returns a pointer, always `free()` it after the call \
(unless the API documents that ownership is not transferred). Leaked allocations \
hide crashes and produce misleading ASAN output.
- When reading multi-byte integers from fuzz input (e.g. `*(int*)(Data + N)`), \
guard with `Size >= N + sizeof(type)` — not `Size >= N + 1`. Reading 4 bytes at \
offset 4 requires `Size >= 8`, not `Size >= 5`.
- When seeding state variables (counts, indices, sizes) from fuzz input, clamp \
them to their valid range. If the real API enforces a maximum (e.g. nstore <= \
MAX_STORE), clamp to that maximum in the harness. Unclamped values cause OOB \
accesses that cannot occur in real usage and mask real bugs.
- Output C code only — no explanation, no markdown prose outside the code block.\
"""


# ---------------------------------------------------------------------------
# IR utilities
# ---------------------------------------------------------------------------

def get_context(ll_path: str, fn_name: str) -> str:
    r = subprocess.run(["ir-context", ll_path, "--function", fn_name],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        err = r.stderr.strip() or "(no output)"
        print(f"WARNING: ir-context returned no context (rc={r.returncode}):\n  {err}")
    return r.stdout.strip()


def get_context_json(ll_path: str, fn_name: str) -> dict:
    """Return the raw slice summary dict from ir-context --json, or {}."""
    r = subprocess.run(["ir-context", ll_path, "--function", fn_name, "--json"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return {}
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}


def resolve_public_caller(ll_path: str, fn_name: str,
                          header_text: str, ir_dir: str) -> "tuple[str, str] | None":
    """Find the best public caller of fn_name.

    Uses caller_names from the slice JSON. Searches all .ll files in ir_dir
    for a caller with external linkage (not `define internal`).
    Prefers callers declared in the header; falls back to any externally-linked
    caller (e.g. main()) when no header-declared caller exists.
    Returns (caller_ll_path, caller_fn_name) or None.
    """
    summary = get_context_json(ll_path, fn_name)
    caller_names = summary.get("caller_names", [])
    if not caller_names:
        return None

    search_dir = Path(ir_dir) if ir_dir else Path(ll_path).parent
    header_matches: list[tuple[str, str]] = []
    any_matches: list[tuple[str, str]] = []
    for ll in search_dir.glob("*.ll"):
        try:
            text = ll.read_text(errors="replace")
        except OSError:
            continue
        for caller in caller_names:
            if caller == "main":
                continue  # calling main() from a harness re-enters the server loop
            m = re.search(
                r"^(define\b[^@]*)@" + re.escape(caller) + r"\s*\(",
                text, re.MULTILINE,
            )
            if not m:
                continue
            if "internal" in m.group(1):
                continue
            entry = (str(ll), caller)
            if header_text and fn_in_header(caller, header_text):
                header_matches.append(entry)
            else:
                any_matches.append(entry)
    return (header_matches or any_matches or [None])[0]

try:
    from tree_sitter import Language, Parser as _TSParser
    import tree_sitter_c as _tsc
    _C_LANG   = Language(_tsc.language())
    _TS_PARSER = _TSParser(_C_LANG)
    _TS_AVAILABLE = True
except Exception:
    _TS_AVAILABLE = False


def _ts_declarator_name(node) -> str:
    """Return the function name from a function_declarator or pointer_declarator node."""
    for child in node.children:
        if child.type == 'identifier':
            return child.text.decode('utf-8', errors='replace')
        if child.type in ('function_declarator', 'pointer_declarator',
                          'parenthesized_declarator'):
            name = _ts_declarator_name(child)
            if name:
                return name
    return ''


def _ts_find_fn_def(node, fn_name: str):
    """Walk the tree-sitter AST and return the function_definition node for fn_name."""
    if node.type == 'function_definition':
        for child in node.children:
            if child.type in ('function_declarator', 'pointer_declarator'):
                if _ts_declarator_name(child) == fn_name:
                    return node
    for child in node.children:
        result = _ts_find_fn_def(child, fn_name)
        if result:
            return result
    return None


def extract_fn_source(src_text: str, fn_name: str) -> str:
    """Extract the body of fn_name from C source text.

    Uses tree-sitter-c when available for exact AST-based extraction.
    Falls back to regex + brace counting when tree-sitter is not installed.

    Returns empty string if no function_definition node is found — correctly
    handles macro-generated functions (e.g. OpenSSL's IMPLEMENT_PEM_rw) where
    no parseable definition exists in the source file.
    """
    if _TS_AVAILABLE:
        src_bytes = src_text.encode('utf-8', errors='replace')
        tree = _TS_PARSER.parse(src_bytes)
        node = _ts_find_fn_def(tree.root_node, fn_name)
        if node is None:
            return ''
        return src_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='replace')

    # --- Regex fallback (used only when tree-sitter is not installed) ---
    pat = re.compile(rf'\b{re.escape(fn_name)}\s*\(')
    fn_start = brace_start = None
    for m in pat.finditer(src_text):
        ls = src_text.rfind('\n', 0, m.start()) + 1
        line_head = src_text[ls:ls + 2]
        if src_text[ls:ls + 1] in (' ', '\t') or line_head in ('//', '/*'):
            continue
        rest = src_text[m.start():]
        semi, brace = rest.find(';'), rest.find('{')
        if brace == -1 or (semi != -1 and semi < brace) or '\n\n' in rest[:brace]:
            continue
        fn_start    = ls
        brace_start = m.start() + brace
        break
    if fn_start is None:
        return ''
    depth = 0
    for i in range(brace_start, len(src_text)):
        ch = src_text[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return src_text[fn_start:i + 1]
    return ''


def find_source_for_ll(ll_path: str, src_dir: str) -> str:
    """Guess the C source file path from the .ll filename and src_dir.

    IR stems encode the source path with underscores replacing separators,
    e.g. crypto_pem_pem_lib.ll → crypto/pem/pem_lib.c. We try progressively
    shorter suffix sequences so that pem_lib.c is found before pem_pem_lib.c.
    """
    stem = Path(ll_path).stem          # e.g. "crypto_pem_pem_lib"
    parts = stem.split("_")
    # Build candidates by progressively taking fewer leading parts as prefix:
    # full stem, then drop one leading part each time.
    # e.g. ["crypto_pem_pem_lib", "pem_pem_lib", "pem_lib", "lib"]
    candidates = []
    for start in range(len(parts)):
        candidates.append("_".join(parts[start:]))
    src_dir_path = Path(src_dir)
    search_dirs = [
        src_dir_path,
        src_dir_path / "src",
        src_dir_path.parent,   # e.g. main.c lives in repo root, not src/
    ]
    for cand in candidates:
        for ext in (".c", ".cpp", ".cc"):
            for d in search_dirs:
                p = d / (cand + ext)
                if p.exists():
                    return str(p)
    return ""


def get_ir_signature(ll_path: str, fn_name: str) -> str:
    try:
        text = Path(ll_path).read_text(errors="replace")
    except OSError:
        return ""
    m = re.search(
        rf'^define\b[^@]*@{re.escape(fn_name)}\s*\([^)]*\)',
        text, re.MULTILINE,
    )
    return m.group(0) if m else ""


def fn_in_header(fn_name: str, header_text: str) -> bool:
    return bool(re.search(rf'\b{re.escape(fn_name)}\s*\(', header_text))


# Maps DWARF language tags found in LLVM IR debug metadata to C standard strings.
_DWARF_LANG_MAP = {
    "DW_LANG_C89":      "C89",
    "DW_LANG_C":        "C89",
    "DW_LANG_C99":      "C99",
    "DW_LANG_C11":      "C11",
    "DW_LANG_C17":      "C17",
    "DW_LANG_C23":      "C23",
    "DW_LANG_C_plus_plus":    "C++",
    "DW_LANG_C_plus_plus_03": "C++03",
    "DW_LANG_C_plus_plus_11": "C++11",
    "DW_LANG_C_plus_plus_14": "C++14",
    "DW_LANG_C_plus_plus_17": "C++17",
    "DW_LANG_C_plus_plus_20": "C++20",
}


def _detect_c_standard(ll_path: str) -> str:
    """Detect the source language/standard from LLVM IR debug metadata.

    Reads !DICompileUnit entries for the 'language:' field. Returns a
    human-readable standard string (e.g. 'C11', 'C++17') or 'C11' as
    the default when no debug info is present.
    """
    try:
        text = Path(ll_path).read_text(errors="replace")
    except OSError:
        return "C11"
    # !DICompileUnit(language: DW_LANG_C11, ...)
    m = re.search(r'!DICompileUnit\([^)]*language:\s*(DW_LANG_\w+)', text)
    if m:
        tag = m.group(1)
        return _DWARF_LANG_MAP.get(tag, tag)
    return "C11"


def _clang_ast_info(header_text: str, fn_name: str,
                    include_dirs: list[str] | None = None,
                    clang_bin: str = "clang-20",
                    ) -> "tuple[set[str], list[tuple[int,int]]]":
    """Parse the header with clang and return (type_names, decl_line_ranges).

    type_names       — C type names used by fn_name (for typedef/struct filtering)
    decl_line_ranges — [(start_line, end_line), ...] 1-based, inclusive, one entry
                       per FunctionDecl matching fn_name in this file.

    Uses the text-mode AST dump (-ast-dump without =json) which is available on
    all clang versions and doesn't require JSON parsing of a potentially huge tree.

    The text format for a FunctionDecl looks like:
      |-FunctionDecl 0x... <file.h:42:1, col:52> col:5 PEM_read_bio_ex 'int (...)'
    The source range <start, end> gives line numbers directly.
    Child ParmVarDecl lines give additional type names and the end line of the decl.

    Returns (set(), []) on any failure.
    """
    import tempfile
    terms: set[str] = set()
    ranges: list[tuple[int, int]] = []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".h", mode="w",
                                         delete=False) as tmp:
            tmp.write(header_text)
            tmp_path = tmp.name

        cmd = [clang_bin, "-fsyntax-only", "-w",
               "-Xclang", "-ast-dump", "-x", "c", tmp_path]
        for d in (include_dirs or []):
            cmd += ["-I", d]

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True)

        # AST location pattern: <file:LINE:col, LINE:col> or <file:LINE:col, col:N>
        # We want the start and end line numbers.
        loc_re   = re.compile(
            r'<(?:[^:>]+):(\d+):\d+,\s*(?:[^:>]+:)?(\d+):\d+>'
        )
        type_re  = re.compile(r"'([A-Za-z_]\w*(?:\s*\*)*)'")
        fn_re    = re.compile(rf'\bFunctionDecl\b.*\b{re.escape(fn_name)}\b')

        in_fn        = False
        fn_start     = 0
        fn_end       = 0
        fn_indent    = 0
        lines_after  = 0

        for raw in proc.stdout:  # type: ignore[union-attr]
            line = raw.rstrip()

            if not in_fn:
                if "FunctionDecl" in line and fn_re.search(line):
                    lm = loc_re.search(line)
                    if lm:
                        fn_start = int(lm.group(1))
                        fn_end   = int(lm.group(2))
                    # Track indentation depth so we stop at the next sibling
                    fn_indent   = len(raw) - len(raw.lstrip('|-` '))
                    in_fn       = True
                    lines_after = 0
                    for m in type_re.finditer(line):
                        terms.add(m.group(1).rstrip(" *").strip())
                continue

            # Collect type names from child nodes
            for m in type_re.finditer(line):
                t = m.group(1).rstrip(" *").strip()
                if t:
                    terms.add(t)

            # Update end line from child ParmVarDecl locations
            lm = loc_re.search(line)
            if lm:
                fn_end = max(fn_end, int(lm.group(2)))

            lines_after += 1
            # Stop at next top-level sibling node (same or lower indent)
            node_indent = len(raw) - len(raw.lstrip('|-` '))
            if lines_after > 2 and node_indent <= fn_indent and re.search(
                r'\b(FunctionDecl|TypedefDecl|RecordDecl|VarDecl|EnumDecl)\b', line
            ):
                break
            if lines_after > 80:
                break

        proc.kill()
        proc.wait()

        if fn_start > 0:
            ranges.append((fn_start, max(fn_end, fn_start)))

    except Exception:
        pass
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass

    return terms, ranges


def _extract_header_for_fn(header_text: str, fn_name: str,
                            ir_signature: str = "",
                            include_dirs: list[str] | None = None,
                            char_limit: int = 6000) -> str:
    """Return a trimmed header view focused on fn_name using clang AST.

    Strategy (in order of preference):
    1. Use clang -ast-dump to find the exact source lines of every FunctionDecl
       for fn_name, plus the C type names it uses.
    2. Include typedef/struct definitions for those types (for opaque handles).
    3. Include integer/hex #define constants (flags, error codes).
    4. Fall back to IR-derived struct names when clang is unavailable.
    5. Hard-truncate at char_limit as a last resort.

    No custom line-by-line parsing of macro syntax — clang does that correctly.
    """
    header_lines = header_text.splitlines(keepends=True)

    # --- 1. Ask clang for the exact declaration lines and type names ----------
    clang_bin = shutil.which("clang-20") or shutil.which("clang-18") or \
                shutil.which("clang-17") or shutil.which("clang-16") or \
                shutil.which("clang")
    terms: set[str] = set()
    decl_lines: set[int] = set()   # 1-based line numbers to include

    if clang_bin:
        terms, ranges = _clang_ast_info(header_text, fn_name,
                                        include_dirs, clang_bin)
        for start, end in ranges:
            for ln in range(start, end + 1):
                decl_lines.add(ln)

    # --- 2. IR-derived struct names (free, no subprocess) --------------------
    for m in re.finditer(r'%struct\.(\w+)', ir_signature):
        sname = m.group(1)
        terms.add(sname)
        terms.add(re.sub(r'[_][st]$', '', sname))

    # Also always include fn_name itself for typedef/struct lookup
    terms.add(fn_name)
    terms.add(fn_name.rstrip("0123456789_"))

    # --- 3. Expand terms transitively through typedef chains -----------------
    _typedef_re = re.compile(r'\btypedef\b[^;]+;', re.DOTALL)
    snapshot = set(terms)
    for _m in _typedef_re.finditer(header_text):
        block = _m.group(0)
        if any(t in block for t in snapshot):
            for ident in re.findall(r'\b([A-Za-z_]\w+)\b', block):
                terms.add(ident)

    # --- 4. Build the output -------------------------------------------------
    keep: list[str] = []
    in_block      = False
    brace_depth   = 0
    in_comment    = False
    in_macro      = False   # inside a multi-line #define (continuation lines)
    in_open_paren = False   # inside a multi-line function declaration (unbalanced parens)
    paren_depth   = 0

    for i, line in enumerate(header_lines, start=1):
        stripped = line.strip()

        # Always keep exact declaration lines clang identified
        if i in decl_lines:
            keep.append(line)
            in_macro = False
            continue

        # Track multi-line #define continuation — skip until no trailing backslash
        if in_macro:
            if not stripped.endswith('\\'):
                in_macro = False
            continue

        # Integer/hex constant macros (flags, error codes) — always keep.
        # Match both "#define FOO 0x1" and "# define FOO 0x1" (OpenSSL style).
        if re.match(r'\s*#\s*define\s+\w+\s+\(?\s*[-+]?(0[xX][\da-fA-F]+|\d+)\s*\)?',
                    line):
            keep.append(line)
            continue

        # Multi-line #define (function-like or object-like with continuation):
        # skip the header line and set in_macro to skip continuation lines.
        # Match both "#define" and "# define" (OpenSSL-style spaced variant).
        if re.match(r'\s*#\s*define\b', stripped):
            if stripped.endswith('\\'):
                in_macro = True
            continue

        # Track multi-line block comments — keep only inside struct bodies
        if in_comment:
            if in_block:
                keep.append(line)
            if '*/' in line:
                in_comment = False
            continue
        if stripped.startswith('/*') and '*/' not in line:
            in_comment = True
            if in_block:
                keep.append(line)
            continue

        # Typedef/struct blocks that mention a relevant type name
        if re.match(r'\s*(typedef|struct)\b', line):
            if any(t in line for t in terms):
                keep.append(line)
                if '{' in line:
                    in_block   = True
                    brace_depth = line.count('{') - line.count('}')
            continue

        if in_block:
            keep.append(line)
            brace_depth += line.count('{') - line.count('}')
            if brace_depth <= 0:
                in_block = False
            continue

        # Fallback when clang was unavailable: term-match non-macro lines,
        # but skip orphaned continuation fragments (deeply indented, no ; or {).
        # Track open-paren depth so multi-line signatures are kept whole.
        if in_open_paren:
            keep.append(line)
            paren_depth += line.count('(') - line.count(')')
            if paren_depth <= 0:
                in_open_paren = False
            continue
        if not decl_lines and any(t in line for t in terms):
            indent = len(line) - len(line.lstrip())
            if not (indent > 8 and ';' not in stripped and '{' not in stripped):
                keep.append(line)
                paren_depth   = stripped.count('(') - stripped.count(')')
                in_open_paren = paren_depth > 0

    trimmed = "".join(keep)

    # If we got almost nothing (clang unavailable + opaque IR ptr + no terms),
    # fall back to the full header (then truncate).
    if len(trimmed) < 200:
        trimmed = header_text

    if len(trimmed) <= char_limit:
        return trimmed

    return trimmed[:char_limit] + "\n/* ... header truncated ... */\n"


# Known handle types for context-reader functions and their setup/teardown APIs.
# Keyed by handle type name (first param C type without pointer/const).
_HANDLE_API_SNIPPETS: dict[str, str] = {
    "BIO": """\
BIO *BIO_new(const BIO_METHOD *type);
int  BIO_free(BIO *a);
const BIO_METHOD *BIO_s_mem(void);
const BIO_METHOD *BIO_s_secmem(void);
int  BIO_write(BIO *b, const void *data, int dlen);
int  BIO_read(BIO *b, void *data, int dlen);
void OPENSSL_free(void *addr);
void OPENSSL_secure_free(void *ptr);
""",
    "FILE": """\
FILE *fmemopen(void *buf, size_t size, const char *mode);
""",
    "EVP_MD_CTX": """\
EVP_MD_CTX *EVP_MD_CTX_new(void);
void        EVP_MD_CTX_free(EVP_MD_CTX *ctx);
""",
    "EVP_CIPHER_CTX": """\
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void            EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
""",
}


def _context_reader_api_snippet(c_source_sig: str, ir_sig: str) -> str:
    """Return additional API signatures for the handle type used by a context-reader.

    Detects the handle type from the C source signature (first parameter type)
    or falls back to the IR signature for pointer-typed first params.
    Returns an empty string when the handle type is unknown.
    """
    # Extract first parameter type from C source (e.g. "BIO *bp" → "BIO")
    m = re.search(r'\(\s*(?:const\s+)?([A-Za-z_]\w*)\s*\*', c_source_sig or "")
    if m:
        handle_type = m.group(1)
        if handle_type in _HANDLE_API_SNIPPETS:
            return _HANDLE_API_SNIPPETS[handle_type]
    return ""


def ranked_functions(ir_dir: str, no_gep_only: bool) -> list[tuple[str, str]]:
    """Return [(ll_path, fn_name), ...] in score order."""
    cmd = ["ir-score", "--ir-dir", ir_dir]
    if no_gep_only:
        cmd.append("--no-gep-only")
    r = subprocess.run(cmd, capture_output=True, text=True)
    results = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s+(\d+)\s+(\S+)\s+[\d.]+%.*\((\S+\.ll)\)", line)
        if m:
            fn_name  = m.group(2)
            src_file = m.group(3)
            ll_path  = str(Path(ir_dir) / src_file)
            results.append((ll_path, fn_name))
    if not results:
        sys.exit("Could not parse any functions from ir-score output:\n" + r.stdout)
    return results


def pick_public_functions(ir_dir: str, no_gep_only: bool,
                          header_text: str, k: int) -> list[tuple[str, str]]:
    """Return up to k highest-ranked functions that appear in the header.

    When no header is provided, returns the top k ranked functions directly.
    Falls back to rank 1 if nothing matches the header.
    """
    ranked = ranked_functions(ir_dir, no_gep_only)
    if not header_text:
        return ranked[:k]

    public = [(ll, fn) for ll, fn in ranked if fn_in_header(fn, header_text)]
    if not public:
        print("  (no ranked function found in header — falling back to rank 1)")
        return ranked[:1]
    return public[:k]


# ---------------------------------------------------------------------------
# Qwen
# ---------------------------------------------------------------------------

def ask_qwen(messages: list[dict]) -> str:
    if not ENDPOINT:
        sys.exit("Set LLM_ENDPOINT env var (e.g. https://your-litellm-host/v1/chat/completions).")
    if not MODEL:
        sys.exit("Set LLM_MODEL env var (e.g. deepseek-r1-distill-qwen-14b).")
    key = os.environ.get("LLM_API_KEY") or os.environ.get("QWEN_API_KEY", "")
    if not key:
        sys.exit("Set LLM_API_KEY (or QWEN_API_KEY) env var first.")
    timeout = int(os.environ.get("LLM_TIMEOUT", "120"))
    for attempt in range(1, 4):
        try:
            r = requests.post(
                ENDPOINT,
                headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
                json={"model": MODEL, "messages": messages, "stream": True},
                timeout=timeout,
                stream=True,
            )
            if not r.ok:
                sys.exit(f"API error {r.status_code}: {r.text[:500]}")
            # Consume the SSE stream and reconstruct the full content.
            # Streaming keeps the connection alive during long reasoning phases
            # (deepseek-r1 chain-of-thought) that would otherwise hit the timeout.
            import json as _json
            chunks = []
            for raw in r.iter_lines():
                if not raw:
                    continue
                line = raw.decode("utf-8") if isinstance(raw, bytes) else raw
                if line.startswith("data: "):
                    line = line[6:]
                if line.strip() == "[DONE]":
                    break
                try:
                    delta = _json.loads(line)["choices"][0]["delta"].get("content", "")
                    if delta:
                        chunks.append(delta)
                except Exception:
                    pass
            return "".join(chunks)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as exc:
            if attempt == 3:
                sys.exit(f"LLM endpoint unreachable after 3 attempts: {exc}")
            wait = 5 * attempt
            print(f"  [network] connection/timeout error (attempt {attempt}/3), "
                  f"retrying in {wait}s…", file=sys.stderr)
            time.sleep(wait)



def _inject_sigpipe_ignore(c_text: str) -> str:
    """Ensure signal(SIGPIPE, SIG_IGN) and #include <signal.h> are present.
    Idempotent. Handles two cases independently:
    - Model forgot the include but wrote the call (compile error)
    - Model forgot both (inject both)
    Required for fd-reader harnesses — target may write back on fd after
    write-end is closed, triggering SIGPIPE which kills the fuzzer silently."""
    # Always ensure signal.h is included — model may write the call without the include
    if "<signal.h>" not in c_text:
        c_text = c_text.replace(
            "#include <unistd.h>",
            "#include <unistd.h>\n#include <signal.h>",
            1,
        )
        if "<signal.h>" not in c_text:
            c_text = "#include <signal.h>\n" + c_text
    # Inject the call only if not already present
    if "signal(SIGPIPE" not in c_text:
        c_text = re.sub(
            r'(LLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{)',
            r'\1\n    signal(SIGPIPE, SIG_IGN);',
            c_text,
            count=1,
        )
    return c_text

def _extract_global_decls(ll_text: str, names: set) -> list:
    """Extract global variable declarations from LLVM IR and convert to C.

    Returns a list of dicts: name, ir_type, c_extern, c_reset.
    Only returns globals whose names appear in `names`. Uses the original
    (pre-promotion) IR — promotion only changes linkage keywords, not types.
    """
    # names=None means "extract all module globals" (filter compiler-generated ones).
    # names=set() (empty) means "no filter specified" and we also extract all.
    # Only skip when names is an explicit non-empty set that doesn't match.
    extract_all = not names  # None or empty set → grab everything
    _scalar_map = {
        "i8": "char", "i16": "short", "i32": "int", "i64": "long long",
        "float": "float", "double": "double",
    }
    results = []
    for line in ll_text.splitlines():
        m = re.match(
            r'^(@(\w+))\s*=\s*(?:internal\s+)?global\s+(.+)',
            line.strip(),
        )
        if not m:
            continue
        gname = m.group(2)
        if extract_all:
            # Skip compiler-generated globals that aren't user-declared variables.
            # .str / .str.N — string literals; __func__ / __PRETTY_FUNCTION__ — debug strings;
            # anything starting with '.' — LLVM internal naming convention for constants.
            if gname.startswith('.') or gname.startswith('__') or gname.startswith('llvm.'):
                continue
        elif gname not in names:
            continue
        # Extract just the type token from "TYPE INITIALIZER [, align N]".
        # Arrays look like "[N x TYPE] zeroinitializer" — balance brackets first.
        rest = m.group(3).strip()
        if rest.startswith('['):
            close = rest.index(']')
            ir_type = rest[:close + 1].strip()
        elif rest.startswith('%'):
            ir_type = rest.split()[0]
        else:
            ir_type = rest.split()[0]

        arr = re.match(r'\[(\d+)\s+x\s+(.+)\]', ir_type)
        if arr:
            n, elem = arr.group(1), arr.group(2).strip()
            c_type = elem[len('%struct.'):] if elem.startswith('%struct.') else _scalar_map.get(elem, elem)
            results.append(dict(name=gname, ir_type=ir_type,
                                c_extern=f"extern {c_type} {gname}[{n}];",
                                c_reset=f"memset({gname}, 0, sizeof({gname}));"))
            continue

        if ir_type.startswith('%struct.'):
            c_type = ir_type[len('%struct.'):]
            results.append(dict(name=gname, ir_type=ir_type,
                                c_extern=f"extern {c_type} {gname};",
                                c_reset=f"memset(&{gname}, 0, sizeof({gname}));"))
            continue

        if ir_type in _scalar_map:
            c_type = _scalar_map[ir_type]
            results.append(dict(name=gname, ir_type=ir_type,
                                c_extern=f"extern {c_type} {gname};",
                                c_reset=f"{gname} = 0;"))
            continue

        print(f"WARN: unknown IR type '{ir_type}' for global {gname}, skipping extern injection")

    return results


def _inject_global_externs_and_reset(c_text: str, global_decls: list) -> str:
    """Strip model-written extern lines and inject correct ones from IR types.

    Idempotent: strips before re-injecting so retries don't double-inject.
    """
    if not global_decls:
        return c_text

    # Step 1: strip ALL model-written extern lines
    c_text = re.sub(r'^\s*extern\s+[^\n]+;\n', '', c_text, flags=re.MULTILINE)

    # Step 2: inject extern declarations after the last #include line
    extern_block = "\n".join(d["c_extern"] for d in global_decls)
    lines = c_text.splitlines()
    last_include_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith('#include'):
            last_include_idx = i
    if last_include_idx is not None:
        lines.insert(last_include_idx + 1, extern_block)
        c_text = "\n".join(lines)
    else:
        c_text = extern_block + "\n" + c_text

    # Step 3: inject reset calls at function entry
    reset_block = "\n    ".join(d["c_reset"] for d in global_decls)
    if "signal(SIGPIPE" in c_text:
        c_text = c_text.replace(
            "signal(SIGPIPE, SIG_IGN);",
            "signal(SIGPIPE, SIG_IGN);\n    " + reset_block,
            1,
        )
    else:
        c_text = re.sub(
            r'(LLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{)',
            r'\1\n    ' + reset_block.replace('\\', '\\\\'),
            c_text,
            count=1,
        )
    return c_text


def _assistant_content(reply: str) -> str:
    """Extract just the code block from a reply for use in multi-turn context.

    Appending the full chain-of-thought reply on retry quickly overflows the
    model's context window. Using only the extracted code keeps the conversation
    bounded and removes deepseek-r1 reasoning prose from the assistant turn.
    Falls back to the stripped full reply if no code fence is present.
    """
    return extract_c(reply)


def extract_c(text: str) -> str:
    # Strip deepseek-r1 chain-of-thought reasoning blocks before searching for code.
    # The model wraps internal reasoning in <think>...</think>; if that leaks into
    # the reply the prose would be treated as C code, causing a compile error.
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    m = re.search(r"```(?:c|cpp)?\n(.*?)```", cleaned, re.DOTALL)
    if m:
        return m.group(1).strip()
    # No code fence found — return a minimal stub that produces a short, bounded
    # compile error on the next retry rather than dumping prose into the compiler.
    # This keeps the retry context window from overflowing on reasoning models that
    # panic and emit their chain-of-thought as plain text instead of a code block.
    return "/* ERROR: model reply contained no code block — retry */\nvoid _no_code_block(void);"


# IR type → C type mapping for forward-declaration generation
_IR_TYPE_TO_C = {
    "i8": "char", "i16": "short", "i32": "int", "i64": "long long",
    "i8*": "char *", "i8**": "char **",
    "float": "float", "double": "double",
    "void": "void",
}

def _ir_sig_to_c_decl(ir_sig: str, fn_name: str) -> str:
    """Convert an IR function signature to a C forward declaration.

    e.g. "define internal void @handle_client(i32 noundef %0)"
      -> "static void handle_client(int);"
    Returns empty string if parsing fails.
    """
    m = re.match(r"define\s+\S+\s+(\S+)\s+@" + re.escape(fn_name) + r"\((.*)\)", ir_sig)
    if not m:
        return ""
    ret_ir, params_ir = m.group(1), m.group(2)
    ret_c = _IR_TYPE_TO_C.get(ret_ir, ret_ir)

    param_parts = []
    for param in params_ir.split(","):
        param = param.strip()
        if not param or param == "...":
            param_parts.append(param or "...")
            continue
        # e.g. "i32 noundef %0"  ->  take first token as type
        toks = param.split()
        c_type = _IR_TYPE_TO_C.get(toks[0], toks[0]) if toks else "int"
        param_parts.append(c_type)

    params_c = ", ".join(param_parts) if param_parts else "void"
    return f"static {ret_c} {fn_name}({params_c});"


def _build_include_preamble(summary: dict, header_path: str = "", is_fd_reader: bool = False, internal_fn_decl: str = "") -> str:
    """Return the canonical #include preamble for a harness.

    Deterministic — derived from slicer-detected sinks and the project header.
    Called at write time so the model's own include choices are discarded.
    header_path must be a filesystem path (not file content).
    """
    _SINK_HEADERS: dict[str, str] = {
        "memcpy": "<string.h>", "memmove": "<string.h>", "memset": "<string.h>",
        "memcmp": "<string.h>", "bcopy": "<string.h>",
        "strcpy": "<string.h>", "strncpy": "<string.h>",
        "strcat": "<string.h>", "strncat": "<string.h>",
        "strlen": "<string.h>", "strcmp": "<string.h>", "strncmp": "<string.h>",
        "malloc": "<stdlib.h>", "calloc": "<stdlib.h>",
        "realloc": "<stdlib.h>", "free": "<stdlib.h>",
        "xmalloc": "<stdlib.h>", "xrealloc": "<stdlib.h>",
        "atoi": "<stdlib.h>", "atol": "<stdlib.h>", "atoll": "<stdlib.h>",
        "strtol": "<stdlib.h>", "strtoul": "<stdlib.h>",
        "strtoll": "<stdlib.h>", "strtoull": "<stdlib.h>",
        "printf": "<stdio.h>", "fprintf": "<stdio.h>",
        "sprintf": "<stdio.h>", "snprintf": "<stdio.h>",
        "vsprintf": "<stdio.h>", "vsnprintf": "<stdio.h>",
        "scanf": "<stdio.h>", "sscanf": "<stdio.h>", "fscanf": "<stdio.h>",
        "gets": "<stdio.h>", "fgets": "<stdio.h>",
        "read": "<unistd.h>", "pread": "<unistd.h>",
        "recv": "<sys/socket.h>", "recvfrom": "<sys/socket.h>",
    }
    # M-03 always instructs malloc+memcpy for null-termination — always include
    system_headers: set[str] = {"<stdint.h>", "<stddef.h>", "<stdlib.h>", "<string.h>"}
    sink_fn_names = {s.get("fn", "") for s in summary.get("sinks", [])}
    for fn in sink_fn_names:
        hdr = _SINK_HEADERS.get(fn)
        if hdr:
            system_headers.add(hdr)

    # fd-reader functions (fgets, recv, read) signal that the harness needs
    # socketpair infrastructure — inject the required POSIX headers.
    _FD_READER_SINKS = frozenset({"fgets", "recv", "recvfrom", "read"})
    if is_fd_reader or (sink_fn_names & _FD_READER_SINKS):
        system_headers.update({"<sys/socket.h>", "<sys/un.h>", "<unistd.h>"})

    # Stable order: stdint/stddef first, then alphabetical, then project header
    ordered = ["<stdint.h>", "<stddef.h>"]
    for hdr in sorted(system_headers - {"<stdint.h>", "<stddef.h>"}):
        ordered.append(hdr)

    lines = [f"#include {h}" for h in ordered]
    if header_path:
        import os as _os
        lines.append(f'#include "{_os.path.basename(header_path)}"')
    if internal_fn_decl:
        lines.append(internal_fn_decl)
    return "\n".join(lines)


def _apply_preamble(code: str, preamble: str) -> str:
    """Strip all #include lines from model output and prepend the canonical preamble."""
    body_lines = [l for l in code.splitlines()
                  if not l.strip().startswith("#include")]
    body = "\n".join(body_lines).strip()
    return preamble + "\n\n" + body


# ---------------------------------------------------------------------------
# Compilation + validation
# ---------------------------------------------------------------------------

def compile_to_ir(src: Path, include_dirs: list[str] | None = None) -> tuple[Path | None, str]:
    out = src.with_suffix(".ll")
    cmd = ["clang-20", "-O0", "-Xclang", "-disable-O0-optnone",
           "-g", "-fno-inline", "-S", "-emit-llvm", "-w"]
    for d in (include_dirs or []):
        cmd += ["-I", d]
    cmd += [str(src), "-o", str(out)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return (out, "") if r.returncode == 0 else (None, r.stderr)


def _promote_linkage_in_ir(ll_path: Path, fn_name: str) -> Path:
    """Return a modified copy of ll_path with fn_name promoted to external
    linkage and @main renamed to avoid collision with libFuzzer's main."""
    text = ll_path.read_text(errors="replace")
    # Strip 'internal' from the target function definition
    text = re.sub(
        r'^(define\s+)internal(\s+[^@]*@' + re.escape(fn_name) + r'\s*\()',
        r'\1\2',
        text, flags=re.MULTILINE,
    )
    # Promote internal global variables to external linkage so the harness
    # can declare them extern and reset them each run for deterministic fuzzing.
    text = re.sub(
        r'^(@\w+\s*=\s*)internal(\s+global\b)',
        r'\1\2',
        text, flags=re.MULTILINE,
    )
    # Rename every reference to @main (definition + call sites) to avoid
    # collision with libFuzzer's main. Use \\b word boundary to avoid matching
    # @main_loop, @main_config, or other @main-prefixed symbols.
    text = re.sub(r'@main\b', '@__fuzzer_disabled_main', text)
    out = ll_path.with_name(ll_path.stem + "_promoted.ll")
    out.write_text(text)
    return out

def _llvm_link(harness_ll: Path, target_ll: Path, out: Path) -> "tuple[Path | None, str]":
    """Merge harness_ll and target_ll into a single IR module using llvm-link."""
    for linker in ("llvm-link-20", "llvm-link"):
        if shutil.which(linker):
            break
    else:
        return None, "llvm-link not found (install llvm-20)"
    r = subprocess.run(
        [linker, str(harness_ll), str(target_ll), "-S", "-o", str(out)],
        capture_output=True, text=True,
    )
    return (out, "") if r.returncode == 0 else (None, r.stderr)


def self_harm_verdict(score: float) -> str:
    if score >= SELF_HARM_WARN:
        return f"WARNING ({score:.0%}) — likely real bug in harness; review before fuzzing"
    if score >= SELF_HARM_REVIEW:
        return f"REVIEW ({score:.0%}) — elevated; check flagged sinks"
    return f"OK ({score:.0%}) — expected harness noise"



def _check_self_harm(harness_ll: Path) -> tuple[str, str | None]:
    """Run self-harm check on a compiled harness .ll file.

    Returns (verdict_line, retry_message).
    retry_message is None when the harness is clean; non-None when
    score >= SELF_HARM_WARN and the LLM should be asked to fix it.
    """
    from llvm_ir_context.api import get_vulnerability_context

    ir_text = harness_ll.read_text(errors="replace")
    result  = get_vulnerability_context(ir_text, "LLVMFuzzerTestOneInput")

    if "error" in result:
        return f"Self-harm check skipped: {result['error']}", None

    # Suppress double_free/use_after_free before scoring the harness.
    # The scorer escalates those to 0.92+ because they signal real bugs in
    # target functions — but in harness code, free() on multiple exit paths
    # is the correct cleanup pattern, not a defect. The linear IR walker
    # cannot distinguish mutually exclusive paths, so it always fires on
    # goto-cleanup harnesses. We score only the structural sink/guard signals.
    harness_summary = {**result,
                       "double_free": False, "use_after_free": False}
    from llvm_ir_context.score_deterministic import philosophy2_score
    score      = philosophy2_score(harness_summary)
    verdict    = self_harm_verdict(score)
    sink_types = result.get("sink_types") or []
    guard_type = result.get("guard_type", "none")

    if score < SELF_HARM_WARN:
        return verdict, None

    # Build a specific retry message naming the unguarded sinks
    unguarded = [s for s in sink_types if guard_type in ("none", "null_check")]
    sink_desc = ", ".join(f"`{s}`" for s in unguarded) if unguarded else "memory operations"
    retry_msg = (
        f"Your harness compiled, but the IR slicer detected a memory safety bug "
        f"inside the harness itself (self-harm score {score:.0%}).\n\n"
        f"The harness contains unguarded {sink_desc} in the test code — "
        f"this will cause ASAN crashes that mask real bugs in the target function.\n\n"
        f"Fix: ensure any buffer indexed or written using fuzz data is guarded "
        f"by an explicit `Size` check beforehand. Output corrected C code only."
    )
    return verdict, retry_msg


def _bs_retry_msg(bs_msg: str, fn_name: str, is_fd_reader: bool) -> str:
    """Override the blank-shooter retry message for fd-reader targets.

    The slicer cannot trace Data through the kernel socket buffer, so the
    generic 'pass Data directly' message causes the model to cast Data bytes
    as a file descriptor integer — which passes the check but breaks fdopen.
    """
    if not is_fd_reader:
        return bs_msg
    return (
        f"Validation failed: your harness is a blank shooter — "
        f"`Data` does not reach `{fn_name}`. "
        f"`{fn_name}` reads its input through a file descriptor, not a buffer "
        f"argument. You MUST use the socketpair pattern from the Task block: "
        f"call `socketpair(AF_UNIX, SOCK_STREAM, 0, sv)`, "
        f"write `Data` and `Size` to `sv[1]`, close `sv[1]`, "
        f"then pass `sv[0]` to `{fn_name}`. "
        f"Do NOT cast or derive the fd argument from `Data` bytes — "
        f"passing a random integer as a file descriptor will cause `fdopen` "
        f"to fail immediately and the function will return without executing."
    )


def _check_blank_shooter(harness_ll: Path, target_fn: str) -> str | None:
    """Check whether fuzz input (Data/Size) reaches the call to target_fn.

    Slices backward from the call to target_fn inside LLVMFuzzerTestOneInput,
    treating target_fn as a custom sink. Returns a retry message if the slice
    has no function_argument input channel (i.e. Data/Size never reach the
    call), or None when the harness passes.
    """
    from llvm_ir_context.preprocess_slice_pdg import ir_to_graph_slice_pdg
    from llvm_ir_context.slice_context import summarize_slice

    ir_text = harness_ll.read_text(errors="replace")
    g = ir_to_graph_slice_pdg(
        ir_text,
        fn_name="LLVMFuzzerTestOneInput",
        extra_sinks=frozenset({target_fn}),
    )
    if g is None:
        # No slice found at all — the call to target_fn may not exist in IR.
        return (
            f"Validation failed: the IR slicer found no call to `{target_fn}` "
            f"inside `LLVMFuzzerTestOneInput`. Ensure the harness actually calls "
            f"the target function with arguments derived from `Data` and `Size`."
        ), None

    summary = summarize_slice(g, fn_name="LLVMFuzzerTestOneInput")
    if "function_argument" in summary.get("input_channels", []):
        n = summary.get("n_sinks", 0)
        return None, (
            f"OK — Data/Size reach `{target_fn}` "
            f"({n} node(s) in slice, guard={summary.get('guard_type','?')})"
        )  # fuzz input reaches the target — harness passes

    channels = summary.get("input_channels", [])
    return (
        f"Validation failed: your harness is a blank shooter. "
        f"I traced the data flow backward from the call to `{target_fn}` and "
        f"neither `Data` nor `Size` from `LLVMFuzzerTestOneInput` reach its "
        f"arguments (input_channels={channels}) — you are passing constants or "
        f"locally-computed values that the fuzzer cannot influence. "
        f"Pass `Data` (or a slice of it) and/or a length derived from `Size` "
        f"directly into `{target_fn}`."
    ), None


# ---------------------------------------------------------------------------
# Prompt saving
# ---------------------------------------------------------------------------

def save_prompt_file(path: Path, messages: list[dict]) -> None:
    """Write the full message sequence to a markdown file for inspection."""
    lines = [f"# Prompt: {path.stem}\n"]
    for msg in messages:
        role = msg["role"].upper()
        lines.append(f"## {role}\n\n{msg['content']}\n")
    path.write_text("\n---\n\n".join(lines))
    print(f"  Prompt saved: {path}")


# ---------------------------------------------------------------------------
# Prompt module system
# ---------------------------------------------------------------------------
# Each module is a self-contained instruction block selected by a structural
# signal from the slicer summary. Modules are generic — no target-specific
# content. The slicer output is the condition; the module is the instruction.

def build_task_block(fn_name: str, summary: dict,
                     target_header: str = "",
                     is_internal: bool = False,
                     is_fd_reader: bool = False,
                     is_context_reader: bool = False,
                     c_standard: str = "C11") -> str:
    """Compose the Task requirements block from slicer-detected patterns.

    Modules are selected by structural signals in the summary dict.
    Each module is independent and testable in isolation.
    is_fd_reader must be computed by the caller (generate_one uses a robust
    fallback that catches fgets via source text when the slicer sink list misses it).
    is_context_reader: function reads through an opaque handle/context (BIO*, FILE*,
    EVP_MD_CTX*, etc.) rather than taking a raw fd or buffer argument directly.
    c_standard: detected from DWARF debug metadata in the IR (e.g. 'C11', 'C++17').
    """
    hint = summary.get("harness_hint", "")
    strcmp_guards = summary.get("strcmp_guards", [])

    # Classify strcmp_guards into routing vs credential
    from collections import defaultdict
    by_param: dict = defaultdict(list)
    for sg in strcmp_guards:
        idx = sg.get("fuzz_fn_arg_idx")
        if idx is not None:
            by_param[idx].append(sg)
    routing_params = {idx for idx, gs in by_param.items() if len(gs) >= 2}

    modules = []

    # --- M-00: Includes are injected programmatically at write time ---
    # _build_include_preamble() strips model-written includes and prepends the
    # canonical set derived from slicer-detected sinks + project header.
    modules.append("- Do not write any #include lines — they will be added automatically")

    # --- M-01: Base requirements (always present) ---
    _is_cpp = c_standard.startswith("C++")
    _lang_rule = (
        f"- The target is compiled as {c_standard} — output strictly {c_standard}, "
        f"not {'C' if _is_cpp else 'C++'}. "
        + ("Do not use C-style casts or extern \"C\" unless the API requires it."
           if _is_cpp else
           "Do not use range-based for loops, auto, references, or any other C++ syntax.")
    )
    modules.append(
        f"{_lang_rule}\n"
        f"- Use the exact function signature from the IR / API reference above\n"
        f"- Read the target function source carefully — understand what state must be "
        f"initialized before calling it and what the function does with its arguments\n"
        f"- Check the API reference for required initialization and teardown functions "
        f"and call them"
    )

    # Hoist df/uaf callee sets so M-02 can suppress itself when M-05 owns sequencing.
    _df_callees = sorted(summary.get("df_callees") or [])
    _uaf_callees = sorted(summary.get("uaf_callees") or [])
    _has_specific_vuln_callees = bool(_df_callees or _uaf_callees)

    # --- M-02: Input passing — mutually exclusive modules ---
    if "split-input" in hint:
        # P-03: (ptr, len) split-input pattern
        modules.append(
            "- Follow the split-input hint in the Static analysis block exactly — "
            "derive the source buffer and the length from different regions of Data "
            "so they can diverge; do not call the function with matching (Data, Size)"
        )
    elif routing_params and not _has_specific_vuln_callees:
        # P-02: stateful command router — multi-call sequence required.
        # Suppressed when M-05 fires with specific callees: M-05 fully owns the
        # call sequencing in that case and M-02's "randomize verb" instruction
        # would directly contradict M-05's hardcoded-verb-per-phase rule.
        modules.append(
            f"- The function is a command router: the same argument selects different "
            f"handlers on each call. Make multiple calls in sequence (2–4 calls) — "
            f"earlier calls establish state that later calls depend on. "
            f"Use a different byte from `Data` to select the routed argument on each "
            f"call (e.g. `Data[0]`, `Data[1]`, …) so each call can independently pick "
            f"any of the detected literals — do NOT derive the verb from `Size` or any "
            f"value that is constant across the call sequence"
        )
    elif is_fd_reader:
        pass  # M-09 provides the socketpair pattern — suppress contradictory "Pass Data" bullet
    elif is_context_reader:
        pass  # M-11 provides the handle-population pattern — suppress contradictory "Pass Data" bullet
    else:
        modules.append(
            f"- Pass `Data` and `Size` into `{fn_name}` — "
            f"do not add artificial caps on Size"
        )

    # --- M-03: String null-termination (always) ---
    modules.append(
        "- If `Data` is used as a string (passed to a function expecting `const char *`), "
        "null-terminate it first: copy into a heap buffer of `Size + 1` bytes and set "
        "the last byte to `\\0`"
    )

    # --- M-04: State setup and teardown (always) ---
    # Streaming detection: use the slicer hint, not hardcoded library names.
    _has_streaming = "streaming" in hint or "call in a loop" in hint
    teardown_note = (
        " Do NOT use a reset function as a substitute for a full teardown — "
        "reset keeps internal state alive and leaks memory."
        if _has_streaming else ""
    )
    modules.append(
        "- Initialize any required state before the call; clean it up after. "
        "Teardown functions (freeing heap buffers, closing contexts or handles) "
        "MUST be called on every exit path including early returns — use "
        "`goto cleanup` or ensure every `return 0` is preceded by the teardown calls."
        + teardown_note
    )

    # --- M-05: Double-free / UAF — stateful precondition ---
    # Suppressed for context-readers: the vulnerability is reached by feeding
    # data through the handle (BIO_write, fmemopen), not by a two-phase call
    # sequence. M-11 owns the input-routing instruction in that case.
    if not is_context_reader and (summary.get("double_free") or summary.get("use_after_free")):
        bug = "double-free" if summary.get("double_free") else "use-after-free"
        df_callees = _df_callees or _uaf_callees  # already sorted above
        callee_list = ", ".join(f"`{c}`" for c in df_callees) if df_callees else ""
        callee_any  = (df_callees[0] if len(df_callees) == 1
                       else (f"one of {callee_list}" if df_callees else "the vulnerable callee"))
        if is_fd_reader:
            # Stream processor with internal read loop: the function reads ALL commands
            # until EOF in a single call. Use one socketpair, prepend a fixed SETUP
            # command before Data, call the function once.
            callee_ctx = f" in {callee_list}" if callee_list else ""
            modules.append(
                f"- A {bug} is detected{callee_ctx}, reached via `{fn_name}`. "
                f"`{fn_name}` reads commands in a loop from a file descriptor until EOF — "
                f"a single call processes ALL commands in the stream. "
                f"Use ONE socketpair and ONE call. Pack the SETUP and TRIGGER into a single stream:\n"
                f"  1. Write a fixed SETUP command that creates/acquires a resource with a "
                f"known identifier. Derive the exact command syntax from the injected source "
                f"code — do NOT guess the format. Use a short fixed key. "
                f"The command string MUST end with '\\n' so the target's fgets/readline returns. "
                f"Use strlen(setup) not sizeof(setup) when calling write().\n"
                f"  2. Call `write(sv[1], Data, Size)` immediately after the setup write — "
                f"two separate write() calls work fine, no malloc/memcpy needed.\n"
                f"  3. Close the write end, call `{fn_name}(sv[0])` ONCE — the read loop "
                f"processes both the setup command and the fuzz bytes before returning at EOF.\n"
                f"  Do NOT call `{fn_name}` twice — the {bug} is triggered within a single "
                f"connection by the command sequence, not across connections."
            )
        elif df_callees:
            modules.append(
                f"- A {bug} is detected in {callee_list}, which `{fn_name}` calls. "
                f"To trigger it, route `{fn_name}` into {callee_any} twice with the "
                f"same resource identifier. Structure the harness as two fixed phases:\n"
                f"  1. SETUP: craft input so `{fn_name}` invokes {callee_any} to "
                f"create or acquire a resource. This must always succeed before continuing.\n"
                f"  2. TRIGGER: craft input so `{fn_name}` invokes {callee_any} again "
                f"with the same resource identifier to trigger the {bug}. Randomize other "
                f"arguments from fuzz input to vary the execution path.\n"
                f"  Do NOT randomize the resource identifier — the {bug} only fires when "
                f"both calls operate on the same resource.\n"
                f"  The routing argument that selects which handler runs (e.g. the verb "
                f"or command field) must also be hardcoded for each phase — do NOT derive "
                f"it from fuzz data. If you copy fuzz bytes into the command struct with "
                f"memcpy, set the routing field AFTER the memcpy so it is not overwritten."
            )
        else:
            modules.append(
                f"- A {bug} is detected in a callee. This bug requires a specific "
                f"call sequence: one call creates or acquires a resource, and a later "
                f"call frees or mishandles it. Structure the harness as two fixed phases:\n"
                f"  1. SETUP: make a call that creates the resource using a fixed identifier. "
                f"This call must always succeed before continuing.\n"
                f"  2. TRIGGER: make a second call that targets the same identifier/resource "
                f"to trigger the {bug}. Randomize the second call's other arguments from fuzz "
                f"input to vary the execution path.\n"
                f"  Do NOT randomize the resource identifier across calls — the {bug} only "
                f"fires when both calls operate on the same resource."
            )

    # --- M-06: Streaming / incremental call pattern ---
    if "streaming" in hint or "call in a loop" in hint:
        modules.append(
            "- This function uses a streaming call model: call it in a loop until "
            "the return value indicates completion or error; refill any output buffer "
            "each iteration"
        )

    # --- M-09: fd-reader — pipe fuzz input via socketpair ---
    # Fires when the target reads data through a file descriptor (fgets/recv/read)
    # rather than accepting a buffer argument directly.
    if is_fd_reader:
        modules.append(
            f"- This function reads data through a file descriptor, not from a buffer "
            f"argument. The fuzzer cannot feed `Data` into it directly.\n"
            f"  Use a UNIX socket pair to pipe fuzz input in:\n"
            f"  ```c\n"
            f"  #include <signal.h>\n"
            f"  signal(SIGPIPE, SIG_IGN);  /* must be first — target may write back on fd */\n"
            f"  int sv[2];\n"
            f"  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 0;\n"
            f"  write(sv[1], Data, Size);\n"
            f"  close(sv[1]);   /* EOF: fgets/recv returns when write end is closed */\n"
            f"  {fn_name}(sv[0]);\n"
            f"  close(sv[0]);\n"
            f"  ```\n"
            f"  CRITICAL: call `signal(SIGPIPE, SIG_IGN)` as the very first statement. "
            f"If the target writes a banner or response back on the same fd, closing "
            f"the write end before calling it will cause a SIGPIPE that silently kills "
            f"the fuzzer process — libFuzzer does not catch SIGPIPE as a crash.\n"
            f"  Pass `sv[0]` (read end) to the target. Close `sv[1]` (write end) "
            f"BEFORE calling the target so that `fgets`/`recv` returns NULL/0 at EOF "
            f"and the target's read loop terminates naturally.\n"
            f"  Use `socketpair` (bidirectional) rather than `pipe` when the target "
            f"opens the fd twice (e.g. `fdopen(fd, \"r\")` + `fdopen(dup(fd), \"w\")`)."
        )

    # --- M-11: Context/handle reader — populate handle with fuzz data before calling ---
    # Fires when the function reads through an opaque handle (BIO*, FILE*, EVP_MD_CTX*,
    # etc.) rather than taking a raw fd or buffer argument. The model must create the
    # handle and write fuzz data into it before calling the target.
    if is_context_reader:
        modules.append(
            f"- `{fn_name}` reads its input through an opaque context or handle object "
            f"(e.g. BIO*, FILE*, or similar), not a raw buffer or file descriptor argument. "
            f"You MUST populate that handle with fuzz data BEFORE calling `{fn_name}`. "
            f"For a BIO*: call `BIO_new(BIO_s_mem())` then `BIO_write(bio, Data, Size)` "
            f"before passing the BIO to `{fn_name}`. "
            f"`BIO_write` accepts raw bytes — pass `Data` directly, no null-termination "
            f"or intermediate copy needed. "
            f"For a FILE*: use `fmemopen(Data, Size, \"r\")`. "
            f"Do NOT pass `Data` or `Size` directly as arguments to `{fn_name}` — "
            f"check the function signature and API reference to identify which parameter "
            f"is the handle and which are output/flag parameters."
        )

    # --- M-10: Global init state warning for internal-linkage functions ---
    # Fires when the target is define internal: main() is suppressed in the
    # merged IR so globals it normally initializes start at zero/null.
    # Uses global_vars_read from the slicer so the model gets concrete names.
    if is_internal:
        modules.append(
            f"- `{fn_name}` is a static function. Its file-scope globals have been "
            f"promoted to external linkage in the merged IR, and `@main` has been "
            f"renamed so it does not collide with libFuzzer's `main`. "
            f"The build pipeline automatically injects the correct `extern` declarations "
            f"and per-run zero resets for all globals — do NOT write any `extern` "
            f"declarations or global reset calls in your harness. "
            f"Do NOT use `static` local variables to shadow file-scope globals."
        )

    # --- M-08: Output buffer sizing ---
    # Fires only when a buffer-write or streaming sink is present.
    # Not for printf/format-string sinks or division/GEP-only functions.
    # Two failure modes observed in the wild:
    #   1. malloc(Size) — output of a transform can be larger than input
    #   2. avail_out = *(uint32_t*)(Data) — reads output size from fuzz bytes
    _OUTPUT_WRITE_SINKS = frozenset({
        "memcpy", "memmove", "memset", "bcopy",
        "strcpy", "strncpy", "strcat", "strncat",
    })
    _FORMAT_ONLY_SINKS = frozenset({
        "printf", "fprintf", "sprintf", "snprintf",
        "vsprintf", "vsnprintf", "scanf", "sscanf", "fscanf",
        "syslog", "err", "warn",
    })
    sink_fns = {s.get("fn") for s in summary.get("sinks", [])}
    # GEP-only sinks (no fn name) count as buffer-write potential for streaming APIs.
    # But if every named sink is a format-string function, skip M-08.
    has_buffer_write_sink = bool(sink_fns & _OUTPUT_WRITE_SINKS)
    has_unnamed_sink = any(s.get("fn") is None for s in summary.get("sinks", []))
    only_format_sinks = bool(sink_fns) and not (sink_fns - _FORMAT_ONLY_SINKS)
    if (has_buffer_write_sink or has_unnamed_sink) and not only_format_sinks:
        modules.append(
            "- The function writes into an output buffer. "
            "Size that buffer from a compile-time constant, NEVER from fuzz bytes — "
            "`malloc(Size)` is wrong because output can exceed input. "
            "Apply a hard cap (e.g. 4 MB) so libFuzzer cannot grow inputs until OOM. "
            "Never derive a buffer length, capacity field, or size argument from `Data`."
        )

    # --- M-07: Return 0 (always last) ---
    modules.append("- Return 0")

    requirements = "\n".join(modules)
    return (
        f"## Task\n"
        f"Write `int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)` "
        f"targeting `{fn_name}`.\n\n"
        f"Requirements:\n{requirements}\n\n"
        f"Output C code only, no explanation."
    )


# ---------------------------------------------------------------------------
# Source extraction helper (shared by 1:1 and interprocedural paths)
# ---------------------------------------------------------------------------

def _extract_direct_callees(ll_path: str, fn_name: str) -> list:
    """Return names of functions directly called by fn_name in LLVM IR.

    Parses the IR function body for call instructions. Filters out LLVM
    intrinsics (llvm.*), compiler builtins (__*), and the target itself.
    Order is first-occurrence in the IR body.
    """
    try:
        text = Path(ll_path).read_text(errors="replace")
    except OSError:
        return []
    m = re.search(rf'^define\b[^@]*@{re.escape(fn_name)}\s*\(', text, re.MULTILINE)
    if not m:
        return []
    start = text.find('{', m.start())
    if start == -1:
        return []
    depth, i = 0, start
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                body = text[start:i + 1]
                break
        i += 1
    else:
        return []
    # Collect all functions defined across all IR files in the same directory.
    # Callees that are only `declare`d everywhere are external (libc, OS) and
    # contain no application protocol logic worth injecting.
    ir_dir_path = Path(ll_path).parent
    defined_anywhere = set(
        m2.group(1)
        for ll_file in ir_dir_path.glob("*.ll")
        for m2 in re.finditer(
            r'^define\b[^@]*@(\w+)\s*\(', ll_file.read_text(errors="replace"), re.MULTILINE
        )
    )
    seen, callees = set(), []
    for cm in re.finditer(r'\bcall\b[^@\n]*@(\w+)\s*\(', body):
        name = cm.group(1)
        if name in seen:
            continue
        seen.add(name)
        if (name.startswith('llvm.') or name.startswith('__')
                or name == fn_name or name not in defined_anywhere):
            continue
        callees.append(name)
    return callees


def _callee_source_block(ll_path: str, fn_name: str, src_dir: str,
                          priority_callees: set = None,
                          max_callees: int = 3, max_chars: int = 3000) -> str:
    """Return source bodies of direct callees of fn_name found in src_dir.

    When priority_callees is provided (df_callees/uaf_callees from the slicer),
    only those callees are injected and the same-file guard is bypassed — they
    are on the vulnerability path so their source is always relevant regardless
    of which file they live in. Fallback (priority_callees=None): all cross-file
    callees, same-file guard active.
    """
    if not src_dir:
        return ""
    if priority_callees:
        callees = [c for c in _extract_direct_callees(ll_path, fn_name)
                   if c in priority_callees]
    else:
        callees = _extract_direct_callees(ll_path, fn_name)
    if not callees:
        return ""
    all_src_files = list(Path(src_dir).glob("*.c"))
    def _contains_fn(f):
        try:
            return bool(extract_fn_source(f.read_text(errors="replace"), fn_name))
        except OSError:
            return False
    src_files = sorted(all_src_files, key=lambda f: (_contains_fn(f), f.name))
    snippets, total_chars, found = [], 0, 0
    for callee in callees:
        if found >= max_callees or total_chars >= max_chars:
            break
        for src_file in src_files:
            try:
                src_text = src_file.read_text(errors="replace")
            except OSError:
                continue
            # Skip fuzzer scaffold files — they contain harness code, not
            # application logic, and should never be injected as callee source.
            if "LLVMFuzzerTestOneInput" in src_text:
                continue
            if not priority_callees:
                # Fallback mode: skip the file defining fn_name — its content
                # is already injected as the target source block.
                if extract_fn_source(src_text, fn_name):
                    continue
            body = extract_fn_source(src_text, callee)
            if not body:
                continue
            if total_chars + len(body) > max_chars:
                remaining = max_chars - total_chars
                if remaining < 80:
                    break
                body = body[:remaining] + "\n/* ... truncated ... */"
            snippets.append(f"// {callee}()\n{body}")
            total_chars += len(body)
            found += 1
            print(f"  Callee source: {callee} ({src_file.name}, {len(body)} chars)")
            break
    if not snippets:
        return ""
    return "\n## Direct callee source\n```c\n" + "\n\n".join(snippets) + "\n```"


def _source_block(ll_path: str, fn_name: str, src_dir: str,
                  label: str = "Target function") -> str:
    """Return a markdown source block for fn_name, or empty string."""
    if not src_dir:
        return ""
    src_file = find_source_for_ll(ll_path, src_dir)
    if not src_file:
        print(f"  WARNING: no C source found for {Path(ll_path).name} in {src_dir}")
        return ""
    try:
        src_text = Path(src_file).read_text(errors="replace")
    except OSError as e:
        print(f"  WARNING: could not read {src_file}: {e}")
        return ""
    fn_src = extract_fn_source(src_text, fn_name)
    if not fn_src:
        print(f"  WARNING: could not extract {fn_name} from {src_file}")
        return ""
    print(f"  Source ({label}): {src_file} ({len(fn_src)} chars)")
    return f"\n## {label} (C source)\n```c\n{fn_src}\n```"


# ---------------------------------------------------------------------------
# Interprocedural harness generation (P-05)
# ---------------------------------------------------------------------------

def _generate_interprocedural(vuln_ll: str, vuln_fn: str,
                               caller_ll: str, caller_fn: str,
                               header: str, include_dirs: list[str],
                               output_dir: Path, src_dir: str,
                               save_prompt: bool = False,
                               header_path: str = "") -> bool:
    """Build a two-section prompt: vulnerable callee context + caller entry point.

    The model sees where the bug is (vuln_fn) and where the harness must
    enter (caller_fn), and must reason about how to drive caller_fn into
    the path that reaches vuln_fn.
    """
    # Vulnerability context from the callee
    vuln_ctx    = get_context(vuln_ll, vuln_fn)
    vuln_sig    = get_ir_signature(vuln_ll, vuln_fn)
    vuln_src    = _source_block(vuln_ll, vuln_fn, src_dir,
                                label=f"Vulnerable function: {vuln_fn}")

    # Caller context (for routing gates etc.)
    caller_ctx  = get_context(caller_ll, caller_fn)
    caller_sig  = get_ir_signature(caller_ll, caller_fn)
    caller_src  = _source_block(caller_ll, caller_fn, src_dir,
                                label=f"Harness entry point: {caller_fn}")

    header_trimmed = _extract_header_for_fn(header, vuln_fn, vuln_sig, include_dirs) if header else ""
    header_block = f"\n## API reference\n```c\n{header_trimmed}\n```" if header_trimmed else ""
    vuln_sig_block   = (f"\n## Vulnerable function signature (from IR)\n```\n{vuln_sig}\n```"
                        if vuln_sig else "")
    caller_sig_block = (f"\n## Entry point signature (from IR)\n```\n{caller_sig}\n```"
                        if caller_sig else "")

    print(f"\n── Vulnerability context ({vuln_fn}) ──")
    print(vuln_ctx)
    print(f"\n── Caller context ({caller_fn}) ──")
    print(caller_ctx)

    caller_summary = get_context_json(caller_ll, caller_fn)
    # Interprocedural: always include the double-free/UAF module from the callee
    # so the model knows to establish the precondition via the caller path.
    merged_summary = {**caller_summary,
                      "double_free":   caller_summary.get("double_free")
                                       or get_context_json(vuln_ll, vuln_fn).get("double_free"),
                      "use_after_free": caller_summary.get("use_after_free")
                                        or get_context_json(vuln_ll, vuln_fn).get("use_after_free")}
    _ifd_sinks = frozenset({"fgets", "recv", "recvfrom", "read"})
    caller_is_fd_reader = bool(
        {s.get("fn") for s in caller_summary.get("sinks", [])} & _ifd_sinks
    )
    task_block = build_task_block(caller_fn, merged_summary, target_header=header,
                                  is_fd_reader=caller_is_fd_reader,
                                  c_standard=_detect_c_standard(caller_ll))
    # Prepend the interprocedural-specific constraint
    interp_note = (
        f"- The harness entry point is `{caller_fn}` — do NOT call `{vuln_fn}` directly\n"
        f"- Read both function sources carefully: understand the path through "
        f"`{caller_fn}` that reaches `{vuln_fn}` and set up any required preconditions"
    )
    task_block = task_block.replace("Requirements:\n", f"Requirements:\n{interp_note}\n")

    initial_prompt = f"""Write a libFuzzer harness in C for security testing.

The vulnerability is in `{vuln_fn}` but it is an internal function not \
directly accessible. The harness must enter via `{caller_fn}`, which is \
the public API function that calls `{vuln_fn}`.

## Static analysis — vulnerable function: {vuln_fn}
{vuln_ctx}
{vuln_sig_block}
{vuln_src}
## Static analysis — harness entry point: {caller_fn}
{caller_ctx}
{caller_sig_block}
{caller_src}
{header_block}
{task_block}"""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": initial_prompt},
    ]
    out_c = output_dir / f"harness_{vuln_fn}_via_{caller_fn}.c"
    output_dir.mkdir(parents=True, exist_ok=True)

    if save_prompt:
        save_prompt_file(output_dir / f"harness_{vuln_fn}_via_{caller_fn}_prompt.md", messages)

    harness_ll = None
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n── calling {MODEL} (attempt {attempt}/{MAX_RETRIES}) ──────")
        reply = ask_qwen(messages)
        preamble = _build_include_preamble(merged_summary, header_path=header_path)
        code  = _apply_preamble(extract_c(reply), preamble)
        if is_fd_reader:
            code = _inject_sigpipe_ignore(code)
        if _global_decls:
            code = _inject_global_externs_and_reset(code, _global_decls)
        out_c.write_text(code)
        print(code)
        print(f"\n→ saved: {out_c}")

        print("\n── compiling harness to IR ──────────────────────────")
        harness_ll, stderr = compile_to_ir(out_c, include_dirs)
        if not harness_ll:
            print("COMPILE ERROR:\n" + stderr)
            if attempt == MAX_RETRIES:
                print(f"VALIDATION: FAIL — {vuln_fn} via {caller_fn} skipped "
                      f"after {MAX_RETRIES} compile errors")
                return False
            messages.append({"role": "assistant", "content": _assistant_content(reply)})
            messages.append({
                "role": "user",
                "content": (
                    "The harness failed to compile. Fix the C code and output "
                    "corrected C only (no explanation).\n\n"
                    f"Compiler error:\n```\n{stderr.strip()}\n```"
                ),
            })
            continue

        print(f"OK → {harness_ll}")

        print("\n── self-harm check ──────────────────────────────────")
        verdict, retry_msg = _check_self_harm(harness_ll)
        print(f"Self-harm verdict: {verdict}")
        if retry_msg is not None:
            print(f"Self-harm retry message:\n{retry_msg}")
            if attempt == MAX_RETRIES:
                print(f"VALIDATION: WARN — {vuln_fn} via {caller_fn} has self-harm; generated anyway")
            else:
                messages.append({"role": "assistant", "content": _assistant_content(reply)})
                messages.append({"role": "user", "content": retry_msg})
                continue

        print("\n── blank-shooter check ──────────────────────────────")
        bs_msg, bs_ok = _check_blank_shooter(harness_ll, caller_fn)
        if bs_ok is not None:
            print(bs_ok)
            break
        print(f"BLANK SHOOTER: {bs_msg}")
        if attempt == MAX_RETRIES:
            print(f"VALIDATION: WARN — {vuln_fn} via {caller_fn} is a blank shooter; generated anyway")
            break
        messages.append({"role": "assistant", "content": _assistant_content(reply)})
        messages.append({"role": "user", "content": bs_msg})

    inc = "".join(f" -I {d}" for d in include_dirs)
    print(f"\nTo fuzz:")
    print(f"  clang-20 -fsanitize=fuzzer,address -g{inc} {out_c} <target_lib> "
          f"-o fuzzer_{vuln_fn}_via_{caller_fn}")
    print(f"  ./fuzzer_{vuln_fn}_via_{caller_fn}")
    return True


# ---------------------------------------------------------------------------
# Single harness generation
# ---------------------------------------------------------------------------

def generate_one(ll_path: str, fn_name: str, header: str,
                 include_dirs: list[str], output_dir: Path,
                 src_dir: str = "", ir_dir: str = "",
                 save_prompt: bool = False,
                 header_path: str = "") -> bool:
    """Generate, compile, and validate one harness. Returns True on success."""

    print(f"\n{'='*60}")
    print(f"Target: {fn_name}  ({ll_path})")
    print('='*60)

    # Detect interprocedural case: fn_name not in header but has a public caller.
    # When detected, delegate to the interprocedural prompt builder.
    # Note: also handles internal-linkage functions — P-05 finds a public caller
    # that reaches the target so the harness calls the caller instead.
    ir_sig_early = get_ir_signature(ll_path, fn_name)
    is_internal = ir_sig_early and "define internal" in ir_sig_early
    if header and (not fn_in_header(fn_name, header) or is_internal):
        search_dir = ir_dir or str(Path(ll_path).parent)
        caller = resolve_public_caller(ll_path, fn_name, header, search_dir)
        if caller:
            caller_ll, caller_fn = caller
            print(f"  P-05: {fn_name} not in header — "
                  f"fuzz via caller `{caller_fn}` ({caller_ll})")
            return _generate_interprocedural(
                vuln_ll=ll_path, vuln_fn=fn_name,
                caller_ll=caller_ll, caller_fn=caller_fn,
                header=header, include_dirs=include_dirs,
                output_dir=output_dir, src_dir=src_dir,
                save_prompt=save_prompt,
                header_path=header_path,
            )

    # If function has internal linkage and no public caller was found, fall
    # through to direct harness generation. The harness is compiled together
    # with the source file that defines the static function, so the symbol
    # resolves at link time. Emit a warning so the user knows.
    if is_internal:
        print(f"  NOTE: {fn_name} has internal linkage — harness must be compiled "
              f"together with its defining source file so the symbol resolves.")

    # Standard 1:1 path
    ctx    = get_context(ll_path, fn_name)
    ir_sig = get_ir_signature(ll_path, fn_name)
    print(ctx)
    if ir_sig:
        print(f"\nIR signature: {ir_sig}")

    src_block    = _source_block(ll_path, fn_name, src_dir)
    summary_json = get_context_json(ll_path, fn_name)
    if ir_dir:
        summary_json = _enrich_with_callee_flags(
            summary_json, fn_name, ll_path, ir_dir,
            src_text=src_block,
        )
    _priority = (summary_json.get("df_callees") or set()) | (summary_json.get("uaf_callees") or set())
    callee_src_block = _callee_source_block(ll_path, fn_name, src_dir,
                                             priority_callees=_priority or None)
    sig_block    = (f"\n## Function signature (from IR)\n```\n{ir_sig}\n```"
                    if ir_sig else "")
    _FD_READER_SINKS_GEN = frozenset({"fgets", "recv", "recvfrom", "read"})
    _gen_sink_fns = {s.get("fn") for s in summary_json.get("sinks", [])}
    _has_read_sink = bool(_gen_sink_fns & _FD_READER_SINKS_GEN) or (
        is_internal and "fgets" in ctx
    )
    # Distinguish true fd-readers (first param is integer: i32/i64 fd) from
    # context/handle readers (first param is ptr: BIO*, FILE*, EVP_MD_CTX*, ...).
    # IR signature: "define ... @fn(i32 noundef %0, ...)" → fd-reader
    #               "define ... @fn(ptr noundef %0, ...)" → context-reader
    _first_param_is_int = bool(ir_sig and re.search(
        r'@' + re.escape(fn_name) + r'\s*\(\s*i(?:8|16|32|64)\b', ir_sig
    ))
    is_fd_reader      = _has_read_sink and _first_param_is_int
    is_context_reader = _has_read_sink and not _first_param_is_int
    header_trimmed = _extract_header_for_fn(header, fn_name, ir_sig, include_dirs) if header else ""
    if is_context_reader:
        snippet = _context_reader_api_snippet(src_block, ir_sig)
        if snippet and snippet not in header_trimmed:
            header_trimmed = (header_trimmed.rstrip() + "\n" + snippet) if header_trimmed else snippet
    header_block = f"\n## API reference\n```c\n{header_trimmed}\n```" if header_trimmed else ""
    # For internal-linkage functions build a forward decl so the harness IR
    # compiles without the defining TU present. The harness is linked with
    # the full src/ tree so the symbol resolves at final link time.
    internal_fn_decl = ""
    if is_internal and ir_sig:
        # ir_sig is e.g. "define internal void @handle_client(i32 noundef %0)"
        # Produce: "static void handle_client(int fd);"  using the C source sig
        # if available, otherwise a best-effort cast from IR types.
        c_decl = _ir_sig_to_c_decl(ir_sig, fn_name)
        if c_decl:
            internal_fn_decl = c_decl
    c_std        = _detect_c_standard(ll_path)
    task_block   = build_task_block(fn_name, summary_json, target_header=header,
                                    is_internal=is_internal, is_fd_reader=is_fd_reader,
                                    is_context_reader=is_context_reader,
                                    c_standard=c_std)

    # Extract global declarations from the original IR so the pipeline can
    # inject correct extern decls and resets without relying on the model.
    if is_internal:
        _ll_text = Path(ll_path).read_text(errors="replace")
        _gvr = summary_json.get("global_vars_read")
        # When the slicer field is absent or None, globals are accessed via callees
        # (intra-procedural slicer can't see them). Fall back to all module globals,
        # filtering out compiler-generated names (.str, __func__, llvm.*).
        _slice_globals = set(_gvr) if _gvr else None
        _global_decls = _extract_global_decls(_ll_text, _slice_globals)
        if _global_decls:
            src_label = "slicer" if _gvr else "all module globals (slicer field absent)"
            print(f"  globals extracted from IR ({src_label}): " +
                  ", ".join(d['name'] for d in _global_decls))
    else:
        _global_decls = []

    initial_prompt = f"""Write a libFuzzer harness in C for security testing.

## Static analysis (IR slicer output)
{ctx}
{sig_block}
{src_block}
{callee_src_block}
{header_block}
{task_block}"""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": initial_prompt},
    ]
    out_c    = output_dir / f"harness_{fn_name}.c"
    output_dir.mkdir(parents=True, exist_ok=True)

    if save_prompt:
        save_prompt_file(output_dir / f"harness_{fn_name}_prompt.md", messages)

    # Qwen with compile-error retry
    harness_ll = None
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"\n── calling {MODEL} (attempt {attempt}/{MAX_RETRIES}) ──────")
        reply = ask_qwen(messages)
        extracted = extract_c(reply)
        # Sentinel stub means model returned no fenced code block — retry directly.
        if "/* ERROR: model reply contained no code block" in extracted:
            print("NO CODE BLOCK — model reply had no fenced code; retrying")
            if attempt == MAX_RETRIES:
                print(f"VALIDATION: FAIL — {fn_name} skipped after {MAX_RETRIES} empty replies")
                return False
            messages.append({"role": "assistant", "content": reply[:500]})
            messages.append({
                "role": "user",
                "content": (
                    "Your reply contained no C code block. "
                    "Output ONLY a fenced C code block (```c ... ```) with the complete harness."
                ),
            })
            continue
        preamble = _build_include_preamble(summary_json, header_path=header_path, is_fd_reader=is_fd_reader, internal_fn_decl=internal_fn_decl)
        code  = _apply_preamble(extracted, preamble)
        if is_fd_reader:
            code = _inject_sigpipe_ignore(code)
        if _global_decls:
            code = _inject_global_externs_and_reset(code, _global_decls)
        out_c.write_text(code)
        print(code)
        print(f"\n→ saved: {out_c}")

        print("\n── compiling harness to IR ──────────────────────────")
        harness_ll, stderr = compile_to_ir(out_c, include_dirs)
        if not harness_ll:
            print("COMPILE ERROR:\n" + stderr)
            if attempt == MAX_RETRIES:
                print(f"VALIDATION: FAIL — {fn_name} skipped after {MAX_RETRIES} compile errors")
                return False
            messages.append({"role": "assistant", "content": _assistant_content(reply)})
            messages.append({
                "role": "user",
                "content": (
                    "The harness failed to compile. Fix the C code and output "
                    "corrected C only (no explanation).\n\n"
                    f"Compiler error:\n```\n{stderr.strip()}\n```"
                ),
            })
            continue

        print(f"OK → {harness_ll}")

        print("\n── self-harm check ──────────────────────────────────")
        verdict, retry_msg = _check_self_harm(harness_ll)
        print(f"Self-harm verdict: {verdict}")
        if retry_msg is not None:
            print(f"Self-harm retry message:\n{retry_msg}")
            if attempt == MAX_RETRIES:
                print(f"VALIDATION: WARN — {fn_name} has self-harm; generated anyway")
            else:
                messages.append({"role": "assistant", "content": _assistant_content(reply)})
                messages.append({"role": "user", "content": retry_msg})
                continue

        print("\n── blank-shooter check ──────────────────────────────")
        if is_fd_reader:
            # Data flows via socket buffer — slicer cannot trace through kernel,
            # so the check always false-positives for correct socketpair harnesses.
            print("SKIP — fd-reader: Data flows via socket buffer, slicer cannot trace through kernel")
            break
        else:
            bs_msg, bs_ok = _check_blank_shooter(harness_ll, fn_name)
            if bs_ok is not None:
                print(bs_ok)
                break
            bs_msg = _bs_retry_msg(bs_msg, fn_name, is_fd_reader)
            print(f"BLANK SHOOTER: {bs_msg}")
            if attempt == MAX_RETRIES:
                print(f"VALIDATION: WARN — {fn_name} is a blank shooter; generated anyway")
                break
            messages.append({"role": "assistant", "content": _assistant_content(reply)})
            messages.append({"role": "user", "content": bs_msg})

    # For internal-linkage functions: promote linkage in target IR and
    # merge with harness IR via llvm-link so the static symbol resolves.
    if is_internal and harness_ll:
        print("\n── IR link (internal linkage promotion) ─────────────")
        promoted_ll = _promote_linkage_in_ir(Path(ll_path), fn_name)
        merged_ll   = output_dir / f"harness_{fn_name}_merged.ll"
        merged, link_err = _llvm_link(harness_ll, promoted_ll, merged_ll)
        if merged:
            print(f"OK → {merged}")
            print(f"\nTo fuzz (IR-linked — add remaining source files, exclude the file containing {fn_name}):")
            print(f"  clang-20 -fsanitize=fuzzer,address -g {merged} <other_src/*.c> -o fuzzer_{fn_name}")
            print(f"  (e.g., src/*.c minus the file that defines {fn_name})")
            print(f"  ./fuzzer_{fn_name}")
        else:
            print(f"WARNING: llvm-link failed — {link_err.strip()[:200]}")
            inc = "".join(f" -I {d}" for d in include_dirs)
            print(f"\nTo fuzz (fallback — compile with source):")
            print(f"  clang-20 -fsanitize=fuzzer,address -g{inc} {out_c} <target_lib> -o fuzzer_{fn_name}")
            print(f"  ./fuzzer_{fn_name}")
    else:
        inc = "".join(f" -I {d}" for d in include_dirs)
        print(f"\nTo fuzz:")
        print(f"  clang-20 -fsanitize=fuzzer,address -g{inc} {out_c} <target_lib> -o fuzzer_{fn_name}")
        print(f"  ./fuzzer_{fn_name}")
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_ll_for_function(ir_dir: str, fn_name: str) -> str | None:
    """Return the .ll file path that defines fn_name, or None."""
    import glob as _glob
    pattern = re.compile(rf"^define\b.*@{re.escape(fn_name)}\s*\(", re.MULTILINE)
    for ll_path in sorted(_glob.glob(str(Path(ir_dir) / "*.ll"))):
        try:
            if pattern.search(Path(ll_path).read_text(errors="replace")):
                return ll_path
        except OSError:
            pass
    return None


def _enrich_with_callee_flags(summary: dict, fn_name: str,
                               ll_path: str, ir_dir: str,
                               src_text: str = "") -> dict:
    """Merge double_free/use_after_free from direct callees into summary.

    Scans all .ll files in ir_dir. For each direct callee of fn_name, merges
    its slicer double_free/use_after_free flags into the caller summary so
    that M-05 fires in the prompt when a callee has the vulnerable pattern.
    """
    import glob as _glob
    ll_text = ""
    try:
        ll_text = Path(ll_path).read_text(errors="replace")
    except OSError:
        pass

    enriched = dict(summary)
    define_re = re.compile(r"^define\b.*@(\w+)\s*\(", re.MULTILINE)
    for sibling_ll in sorted(_glob.glob(str(Path(ir_dir) / "*.ll"))):
        try:
            sibling_text = (Path(sibling_ll).read_text(errors="replace")
                            if sibling_ll != ll_path else ll_text)
        except OSError:
            continue
        for m in define_re.finditer(sibling_text):
            callee = m.group(1)
            if callee == fn_name:
                continue
            in_ir  = bool(re.search(rf"\bcall\b.*@{re.escape(callee)}\b", ll_text))
            in_src = bool(src_text and re.search(rf"\b{re.escape(callee)}\s*\(", src_text))
            if not (in_ir or in_src):
                continue
            callee_summary = get_context_json(sibling_ll, callee)
            if callee_summary.get("double_free"):
                enriched["double_free"] = True
                enriched.setdefault("df_callees", set()).add(callee)
            if callee_summary.get("use_after_free"):
                enriched["use_after_free"] = True
                enriched.setdefault("uaf_callees", set()).add(callee)
    return enriched


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ll",          metavar="FILE")
    src.add_argument("--ir-dir",      metavar="DIR")
    ap.add_argument("--function",     metavar="FN",
                    help="Target function. Required with --ll. "
                         "With --ir-dir: skip ranking, generate exactly this function.")
    ap.add_argument("--no-gep-only",  action="store_true")
    ap.add_argument("--header",       metavar="FILE")
    ap.add_argument("--top-k",        metavar="N", type=int, default=1,
                    help="Generate harnesses for top-K ranked public functions (default: 1)")
    ap.add_argument("--output-dir",   metavar="DIR", default=".",
                    help="Directory to write harness_<fn>.c (default: cwd)")
    ap.add_argument("--skip-existing", action="store_true",
                    help="Skip functions that already have a harness_<fn>.c calling the target")
    ap.add_argument("--src-dir",      metavar="DIR", default="",
                    help="Directory containing C source files; the target function body "
                         "is extracted and included in the prompt so the model can reason "
                         "about required state and call sequences")
    ap.add_argument("--save-prompt",  action="store_true",
                    help="Write harness_<fn>_prompt.md alongside each harness showing "
                         "the full message sequence sent to the model (system + user turns)")
    args = ap.parse_args()

    if args.ll and not args.function:
        ap.error("--function is required with --ll")
    if args.ll and args.top_k != 1:
        ap.error("--top-k only applies to --ir-dir mode")

    header       = Path(args.header).read_text(errors="replace") if args.header else ""
    if args.header:
        _hdr = Path(args.header).resolve()
        # Include both the header's parent dir AND its grandparent so that both
        # `#include "pem.h"` and `#include <openssl/pem.h>` resolve correctly.
        _dirs = [str(_hdr.parent)]
        if _hdr.parent.parent != _hdr.parent:
            _dirs.append(str(_hdr.parent.parent))
        include_dirs = _dirs
    else:
        include_dirs = []
    output_dir   = Path(args.output_dir)
    src_dir      = args.src_dir

    header_path  = args.header or ""

    if args.ll:
        generate_one(args.ll, args.function, header, include_dirs, output_dir,
                     src_dir=src_dir,
                     ir_dir=str(Path(args.ll).parent),
                     save_prompt=args.save_prompt,
                     header_path=header_path)
        return

    # ir-dir mode
    if args.function:
        # --function with --ir-dir: locate the .ll that defines this function, skip ranking
        ll_path = _find_ll_for_function(args.ir_dir, args.function)
        if not ll_path:
            ap.error(f"--function {args.function!r} not found in any .ll file under {args.ir_dir}")
        generate_one(ll_path, args.function, header, include_dirs, output_dir,
                     src_dir=src_dir, ir_dir=args.ir_dir, save_prompt=args.save_prompt,
                     header_path=header_path)
        return

    print(f"── ranking functions in {args.ir_dir} ──────────────")
    targets = pick_public_functions(args.ir_dir, args.no_gep_only, header, args.top_k)
    print(f"   Selected {len(targets)} target(s): {', '.join(fn for _, fn in targets)}")

    results = {"ok": [], "fail": [], "skipped": []}
    for ll_path, fn_name in targets:
        if args.skip_existing:
            existing = output_dir / f"harness_{fn_name}.c"
            if existing.exists() and fn_name in existing.read_text(errors="replace"):
                print(f"\n── skipping {fn_name} — harness already exists ({existing})")
                results["skipped"].append(fn_name)
                continue
        ok = generate_one(ll_path, fn_name, header, include_dirs, output_dir,
                          src_dir=src_dir, ir_dir=args.ir_dir,
                          header_path=header_path,
                          save_prompt=args.save_prompt)
        (results["ok"] if ok else results["fail"]).append(fn_name)

    # Summary when running multiple
    if args.top_k > 1:
        print(f"\n{'='*60}")
        print(f"Summary: {len(results['ok'])} generated, "
              f"{len(results['skipped'])} skipped, {len(results['fail'])} failed")
        if results["ok"]:
            print(f"  OK:      {', '.join(results['ok'])}")
        if results["skipped"]:
            print(f"  SKIPPED: {', '.join(results['skipped'])}")
        if results["fail"]:
            print(f"  FAIL:    {', '.join(results['fail'])}")


if __name__ == "__main__":
    main()
