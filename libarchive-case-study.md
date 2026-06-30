# Case Study: Finding a DoS in libarchive with llvm-ir-context

**Target:** libarchive 3.7.4 — LHA format parser  
**Bug:** Unchecked 32-bit size field from archive header passed to `__archive_read_ahead`, triggering a ~4GB allocation  
**Impact:** Reliable denial-of-service; any process parsing a malformed `.lha` archive crashes with OOM  
**Discovery method:** IR scoring → manual triage → automated harness generation → coverage-guided fuzzing  
**Time to crash:** ~91 million executions (~30 minutes with instrumented build)

---

## 1. Scoring 2203 functions in 30 seconds

libarchive 3.7.4 was built from the release tarball with `bear` to capture a
compilation database, then compiled to LLVM IR with `-emit-llvm`. The result:
2203 translation-unit IR files covering the full library.

```
python3 -m llvm_ir_context.score_deterministic \
  --ir-dir ~/libarchive-ir \
  --no-gep-only \
  --top-k 20
```

```
Scoring 2203/2203 functions...
Functions found: 2065
Wrappers deduplicated: 108 thin wrapper(s) grouped beneath their implementation
```

The scorer applies backward PDG slices from dangerous sinks (memory operations,
filesystem calls, format-string functions), scores each function on guard density,
input channel reachability, and interprocedural propagation from callees, then ranks
all 2065 functions.

---

## 2. The ranking

```
 Rank  Function                                 Score   Details
    1  zisofs_rewind_boot_file                 100.0%  sinks=49 guard=yes(mixed) [free,malloc,read]
    2  entry_to_archive                        100.0%  sinks=27 guard=yes(mixed) [fprintf,free,link,open,read]
   ...
   33  archive_read_format_lha_read_header      92.0%  sinks=195 guard=yes(mixed) +df+uaf
                                                        [+prop:lha_read_file_header_1(45%)]
```

**Ranks 1–32 are explainable noise.** The top band is dominated by functions
whose documented purpose is to accept a user-supplied path (`open`, `openat`,
`fopen`) — they score 100% because `function_argument → fopen, no guard` is
structurally identical to a path traversal bug, but semantically these are
intentional API boundaries. The same false-positive category was observed in the
OpenSSL benchmark (e.g. `BIO_new_file`, `openssl_fopen`).

**Rank 33 was selected for investigation** not by name but because of a
structural anomaly in the scorer details: 195 sinks — the highest of any function
in the 90–93% score band by a factor of 4×, with guard status `mixed` and
`5.1 sinks/guard (sparse)`. A high sink count combined with sparse guard coverage
means a large fraction of paths to dangerous operations are unprotected.

---

## 3. What the slicer said

```
ir-context ~/libarchive-ir/archive_read_support_format_lha.ll \
  --function archive_read_format_lha_read_header
```

```
Sinks       : array/ptr-subscript ×185 — pointer arithmetic with non-constant index
              free ×8 — double-free or use-after-free
              link ×2 — path traversal if either path user-controlled
Guard status: 38 guard(s) (eq, ne, slt, ugt) / 195 sink(s) = 5.1 sinks/guard (sparse)
Distance    : 1 hop(s) source→sink
Double-free : YES  ptr(s): 8, 8
Strcmp gate : memcmp("lhd"); memcmp("lh0"); memcmp("lz4")
Propagation : lha_read_file_header_1(45%), lha_read_file_header_0(45%)
```

The propagation annotation `lha_read_file_header_1(45%)` named the guilty
subfunction before any source code was read.

---

## 4. Harness generation

The function `archive_read_format_lha_read_header` is internal — not exposed in
`archive.h`. The tool automatically applied **P-05 interprocedural routing**: it
identified `archive_read_support_format_lha` as the public entry point that
registers the LHA format handler and dispatches to the target.

```
python3 gen_harness.py \
  --ll ~/libarchive-ir/archive_read_support_format_lha.ll \
  --function archive_read_format_lha_read_header \
  --header ~/libarchive-3.7.4/libarchive/archive.h \
  --src-dir ~/libarchive-3.7.4/libarchive \
  --lib ~/libarchive-3.7.4/libarchive/.libs/libarchive.a \
  --output-dir ~/libarchive-harness
```

The model generated a harness on attempt 2 (attempt 1 produced valid C without
fenced code block delimiters; the retry loop recovered automatically):

```c
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    struct archive *a = archive_read_new();
    if (a == NULL) return 0;

    if (archive_read_support_format_lha(a) != 0) {
        archive_read_free(a);
        return 0;
    }
    if (archive_read_open_memory(a, Data, Size) != 0) {
        archive_read_free(a);
        return 0;
    }

    struct archive_entry *entry = NULL;
    archive_read_next_header(a, &entry);

    archive_read_free(a);
    return 0;
}
```

Compiled clean. Blank-shooter check passed (Data/Size reach `archive_read_support_format_lha`).

---

## 5. Fuzzing

libarchive was rebuilt with fuzzer instrumentation:

```
CC=clang-20 CFLAGS="-fsanitize=fuzzer-no-link,address -g -O1" \
  ./configure --enable-static --disable-shared && make -j$(nproc)
```

A minimal seed and a dictionary of LHA format method strings (extracted from the
slicer's strcmp-gate output) were added to guide the mutator:

```
# lha.dict — from slicer strcmp gates: memcmp("lhd"), memcmp("lh0"), memcmp("lz4")
"-lhd-"
"-lh0-"
"-lz4-"
"-lh5-"
"-lh6-"
"-lh7-"
```

Coverage progression:

| Executions | Coverage | Lever applied |
|---|---|---|
| 2M | cov: 2 | (no seed — fuzzer blind) |
| after seed | cov: 3 | minimal LHA seed added |
| after dict | cov: 531→706 | strcmp gate dict added |
| after max_len | cov: 742 | `-max_len=65536` |
| 91M | **OOM crash** | |

---

## 6. The crash

```
==114425== ERROR: libFuzzer: out-of-memory (malloc(4278517759))
artifact_prefix='./'; Test unit written to ./oom-f7d4e6c9080e0a6248b95278e66f469f1a966f65
```

The crashing input (50 bytes):

```
\x04\x00-lh0-lh0\x00\x00\xf8\x00\x04e1\x00t \x03h
\xd3\xff\xff\xff\xff\xff\xff\xff\x04\xff\x94\x02\x00\x00
\x0a\x00\x00\x00sssssssss\x00
```

The bytes `\xff\xff\xff\xff\xff\xff\xff\x04` were placed by the fuzzer into the
compressed-size field of a level-1 LHA header.

---

## 7. Root cause

In `archive_read_support_format_lha.c`, `lha_read_file_header_1()` at line 820:

```c
lha->compsize = archive_le32dec(p + H0_COMP_SIZE_OFFSET);  // raw 32-bit field, no validation
```

Then at line 947:

```c
err2 = lha_read_file_extended_header(a, lha, NULL, 2,
    (size_t)(lha->compsize + 2),   // ← attacker controls this
    &extdsize);
```

`lha_read_file_extended_header` passes the limit directly to `__archive_read_ahead`,
which attempts to allocate a buffer of that size. With `compsize = 0xFFFFFFFF`,
`compsize + 2` overflows to `0x100000001` on a 64-bit system — ~4GB. No check
against available input bytes, no upper bound.

The same pattern appears at lines 1027 and 1106 for level-2 and level-3 headers.

**Fix:** Cap `compsize` after reading, before the `lha_read_file_extended_header` call:

```c
if (lha->compsize < 0 || lha->compsize > (int64_t)archive_read_bytes_available(a))
    goto invalid;
```

---

## 8. What the tool got right

- **Scoring:** Ranked the buggy function 33/2065. Ranks 1–32 were explainable
  false positives (API-boundary path traversal). The sparse guard ratio (5.1
  sinks/guard) was the structural signal that distinguished it from noise.
- **Propagation:** The `[+prop:lha_read_file_header_1(45%)]` annotation named the
  guilty subfunction before source code was read.
- **Interprocedural routing (P-05):** Automatically found the public entry point
  for an internal function and generated a valid dispatch harness.
- **Strcmp gate dict:** Slicer emitted `memcmp("lhd")`, `memcmp("lh0")`,
  `memcmp("lz4")` — these became the fuzzer dictionary that unlocked decompression
  paths and drove coverage from 3 to 742.
- **Harness correctness:** Generated harness compiled clean, passed blank-shooter
  check, and reached the vulnerable code on the first run.

## 9. What could be improved

- **Ranking:** Rank 33 required human triage. A sparse guard ratio multiplier
  (already added to the roadmap as P1.11) would push this function into the top 15
  automatically.
- **Callee-sink propagation:** The actual allocation happens 2 hops deep
  (`lha_read_file_header_1 → __archive_read_ahead → malloc`). Deeper propagation
  would surface the `malloc` sink and raise the score further.
- **Adaptive fuzzing:** Coverage levers (seed, dict, max_len) were applied manually.
  A `fuzz_loop.py` wrapper using slicer-emitted signals to drive lever selection
  automatically is on the roadmap (P2.4).
