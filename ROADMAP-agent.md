# Agent Workflow Roadmap

This file tracks the work needed to turn `llvm-ir-context` from a CLI tool
into a self-driving agent that can take an arbitrary Git repository and produce
confirmed, patched vulnerability findings with minimal human involvement.

The analysis engine (scoring, sinking, harness generation) is tracked separately
in `ROADMAP.md`. This file covers orchestration, execution infrastructure, and
integration.

---

## Vision

The target workflow, fully automated:

```
clone repo
    │
    ▼
ir-prep  (compile_commands → clang IR extraction)
    │
    ▼
ir-score  (rank all functions, identify top-k targets)
    │
    ▼
ir-context + gen_harness  (per-target: context analysis → harness)
    │
    ▼
fuzz  (libFuzzer + ASAN, time- or coverage-budgeted)
    │
    ▼
crash_to_findings  (symbolize, deduplicate, classify)
    │
    ▼
patch generation  (LLM-assisted fix proposal)
    │
    ▼
apply_patch + re-fuzz  (confirm fix, no regression)
    │
    ▼
loop  (next target, or re-rank after patch)
```

The manual version of this loop was validated end-to-end on scarnet (4/4 bugs
found, patched, verified). The gap is automation of steps 1–2 and the
orchestration layer that drives the rest.

---

## Layer 0: IR Prep  *(current blocker)*

**Status: Not started — highest priority**

The single biggest adoption barrier. Users cannot run the pipeline without `.ll`
files, and almost no project produces them by default.

### `ir-prep` CLI

A standalone command:

```bash
ir-prep --src-dir /path/to/repo --output-dir ./ir/
```

**Implementation:**

1. **Detect build system** — check for `compile_commands.json`, `CMakeLists.txt`,
   `Makefile`, `configure`. For CMake, run `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`.
   For Makefiles, run `bear -- make`. Fail fast with actionable error if neither works.

2. **Mutate compile commands** — for each entry in `compile_commands.json`:
   - Swap compiler to `clang-20`
   - Strip `-O0`–`-O3`, `-march=*`, `-mtune=*`; inject `-O0 -Xclang -disable-O0-optnone -fno-inline`
   - Swap `-c -o file.o` → `-S -emit-llvm -o <output_dir>/file.ll`
   - Skip `.S` assembly files, precompiled headers, generated protobuf/flex sources

3. **Parallel execution** — run all mutated commands concurrently (worker pool,
   default: nproc). Per-file errors are logged but do not abort the run.

4. **Coverage summary** — report `N/M files compiled to IR (K errors)`. 80% IR
   coverage on a real project is useful; 100% is not required.

**Known failure modes to handle:**
- GCC-specific builtins (`__builtin_ia32_*`, `__attribute__((optimize(...)))`) —
  log and skip
- Unity builds / generated source — detect by path pattern, skip or warn
- Missing system headers in the container — surface clearly, not as a clang error

**Files:** new `ir_prep.py` + `ir_prep/` package; new `ir-prep` entry point in
`pyproject.toml`

---

## Layer 1: Execution Abstraction

**Status: Not started**

Every pipeline step reduces to:

```python
result = executor.run(
    image="llvm-ir-context/clang20",
    command=["ir-prep", "--src-dir", "/src", "--output-dir", "/ir"],
    mounts={"/src": repo_path, "/ir": ir_output_path},
    env={"CC": "clang-20"},
)
# result: (stdout, stderr, exit_code, output_files)
```

The pipeline steps are backend-agnostic. Backends are pluggable via config:

```yaml
executor:
  backend: podman        # podman | docker | subprocess | k8s | ssh
  image_registry: ghcr.io/johwes/llvm-ir-context
```

### Backends

| Backend | Use case | Notes |
|---|---|---|
| `subprocess` | Dev / user with clang installed locally | No containers, runs directly |
| `podman` | Single machine, rootless | Default for local agent runs |
| `docker` | Single machine, CI systems | Same interface as podman |
| `k8s` | Enterprise scale, parallel fuzzing | Spawns a Job per step, polls completion |
| `ssh` | Existing build server | User already has the environment |

Start with `subprocess` and `podman`. k8s is v2.

**Files:** `llvm_ir_context/executor/base.py`, `executor/subprocess.py`,
`executor/podman.py`; config schema in `llvm_ir_context/config.py`

---

## Layer 2: Container Images

**Status: Not started**

Two images cover the full pipeline:

### `llvm-ir-context/build`
Used by `ir-prep` (IR extraction):
- Base: `ubuntu:22.04`
- `clang-20`, `llvm-20`, `bear`
- `python3`, `pip`, `llvm-ir-context` package
- No fuzzing runtime

### `llvm-ir-context/fuzz`
Used by harness compilation and fuzzing:
- Base: `llvm-ir-context/build` (inherits clang-20)
- `libFuzzer`, `AddressSanitizer`, `UndefinedBehaviorSanitizer`
- `llvm-symbolizer-20` on `PATH`
- Entrypoint: runs fuzzer binary, captures crashes to mounted output dir

**Published to:** GitHub Container Registry (`ghcr.io/johwes/llvm-ir-context/*`)
via GitHub Actions on each release tag.

**Files:** `docker/Dockerfile.build`, `docker/Dockerfile.fuzz`,
`.github/workflows/publish-images.yml`

---

## Layer 3: Orchestration

**Status: Not started — depends on Layer 0 + Layer 1**

The agent loop that drives the full pipeline. Implemented as a Python class
(not a shell script) so state can be tracked, resumed, and inspected.

### Loop structure

```python
class Agent:
    def run(self, repo_url: str, budget: Budget):
        repo = self.clone(repo_url)
        ir_dir = self.ir_prep(repo)
        targets = self.score(ir_dir, top_k=budget.top_k)
        for target in targets:
            harness = self.gen_harness(target, ir_dir)
            crashes = self.fuzz(harness, budget=budget.per_target)
            if crashes:
                findings = self.symbolize(crashes)
                patches = self.gen_patch(findings, repo)
                self.apply_and_verify(patches, harness)
            self.record(target, harness, crashes)
```

### Termination conditions
- Per-target fuzz budget exhausted (time or exec count)
- Coverage plateau: no new edges for N consecutive seconds
- Top-k targets exhausted
- Global budget (total wall clock) exceeded

### State tracking
- JSON state file: current target, fuzz progress, findings so far
- Resumable: agent can restart from last checkpoint after a crash or timeout
- Human-in-the-loop hook: optional pause after each finding for review before
  patching

### Patch generation
Currently missing from the pipeline. LLM-assisted: feed the crash report,
the source context (from `--src-dir`), and the slice summary to the model with
a patch-generation prompt. Output: unified diff. Apply via `apply_patch.py`.

**Files:** `llvm_ir_context/agent.py`; `ir-agent` entry point in `pyproject.toml`

---

## Layer 4: Output and Integration

**Status: Not started — can be done independently of Layers 1–3**

### SARIF output
GitHub code scanning and most CI systems consume SARIF. Each finding maps to a
SARIF result with:
- `ruleId`: sink type (buffer_overflow, cmd_injection, path_traversal, ...)
- `location`: source file + line (from symbolizer output)
- `message`: slice summary + harness hint
- `level`: error / warning based on score tier

`ir-score --sarif output.sarif` — does not require the agent, works standalone.

### CI integration
A GitHub Actions action:
```yaml
- uses: johwes/llvm-ir-context@v1
  with:
    src-dir: .
    top-k: 5
    upload-sarif: true
```

Runs `ir-prep` + `ir-score` + `gen_harness` in the published Docker image.
Uploads findings as code scanning alerts. No fuzzing in CI (too slow) — harness
generation only.

### JSON findings format
Stable schema for downstream consumers (dashboards, ticketing systems):
```json
{
  "target": "fn_name",
  "score": 0.945,
  "signals": ["trunc", "caller_guarded_args"],
  "sinks": ["memcpy"],
  "harness_path": "harnesses/fn_name_fuzz.c",
  "crash": null
}
```

**Files:** `llvm_ir_context/sarif.py`; `.github/actions/llvm-ir-context/action.yml`

---

## Deferred

| Item | Why deferred |
|---|---|
| k8s executor backend | Complexity cost not justified until scale need is confirmed |
| Distributed fuzzing (multiple fuzz workers per target) | Depends on executor abstraction being stable first |
| Automatic CVE correlation | Requires NVD API integration + function name matching heuristic |
| Incremental IR re-prep on diff (only re-compile changed TUs) | Useful for CI but complex; `bear` re-run is fast enough for now |
| wllvm backend for ir-prep | Fallback for projects where compile_commands replay fails; lower priority than getting replay right |

---

## Build Order

Dependencies flow top-to-bottom. Items at the same level can be parallelized.

```
ir-prep (Layer 0)
    ├── subprocess executor (Layer 1)          ← unblocks local testing immediately
    └── container images (Layer 2)
            └── podman/docker executor (Layer 1)
                    └── agent orchestration (Layer 3)

SARIF output (Layer 4)                         ← independent, start any time
GitHub Actions action (Layer 4)                ← depends on container images
```
