# Mirrorscope — Claude working notes

A cross-platform, eBPF-assisted **time-travel debugger** for C / Rust / Go with first-class async-Rust + goroutine semantics, over **DAP**. Standalone tool AND the debug engine of the sibling Workbench. Read `README.md` for the full architecture before non-trivial work.

## Sibling repo (contract = DAP only, keep independent)
[`lifeos-workbench`](https://github.com/chayan-bit/lifeos-workbench) (local `../lifeos-workbench`) is Mirrorscope's **primary DAP client + host UI** and exposes Mirrorscope's ops to its AI agent (agentic time-travel debugging). **Mirrorscope must stay fully usable without it** (VS Code, nvim-dap, any DAP client). Never build Workbench-specific coupling into the engine; the only contract is DAP (`reverseContinue`/`stepBack` + custom `listCheckpoints`/`taskTimeline`/`jumpToEvent`).

## The thesis — don't lose it (OPINIONS: find the novel angle)
The recording mechanism is NOT the contribution (rr/Undo own that). The novelty is the **class**: *reconstruct the logical concurrency structure the compiler/runtime flattened away, and make it time-travelable.* Two new pillars:
1. **Logical-task-tree reconstruction + time-travel** (async Rust, goroutines) — nobody does this correctly.
2. **Retroactive watchpoints via replay** ("every write to X across history") — only exists with replay; useful even in plain C.
If a design decision doesn't serve one of these two (or the plumbing under them), question it.

## Mental model (don't violate)
- **Not instruction-exact.** Record enough to replay externally-observable behavior between periodic checkpoints. No perf counters → works on ARM (the whole point vs rr).
- **Determinism is a conscious trade, not hand-waving.** MVP = rr's **single-core serialization** adapted to ARM-without-perf-counters: preempt only at instrumented points (syscalls + uprobe'd sync primitives + periodic timer), treat spans between as atomic. Layer **checksum divergence detection** on top as the honesty backstop (surface "replay diverged", never show wrong state silently). Data races are only sound under single-core; say so.
- **One `SemanticDecoder` trait, languages are plugins.** `decode_tasks`/`logical_stack`/`wake_cause`/`locals_at`. Recording/replay/DAP layers never know the language. This is how the class (not the instance) gets solved.
- **`select!`/`join!` → a tree, not a stack.** Model the logical structure as a tree; the DAP stack trace is a flattened projection.
- **State-machine layout is unstable across rustc versions.** Maintain a per-rustc-version layout DB (like Delve's per-Go offset tables), pinned via the DWARF producer string. Highest-risk item — treat as a living compatibility DB, not a one-time reverse-engineer.

## Reuse, don't re-derive (OPINIONS: research before code)
- Unwinding: **framehop** (x86-64 + aarch64) — do NOT hand-roll CFI on ARM.
- eBPF: **aya** (pure-Rust, CO-RE/BTF) — not libbpf/BCC.
- Async introspection: consume/extend **tokio-console**'s `tracing` instrumentation for Tokio (≈80% of users); uprobes only for uninstrumented executors.
- Go: vendor **Delve's** runtime offset tables; handle stack-growth relocation as a first-class event.
- Determinism edge cases (time/rdtsc/randomness/scheduling): port from **Hermit** / **DetTrace**.
- Checkpoint: **CRIU** default (note: no GPU/some-namespace state); `userfaultfd`+soft-dirty for incremental (O(working set), not O(RSS)); fork-snapshot for trivial targets.
- DWARF: gimli + addr2line + object.

## Language extension policy (only along the novelty axis)
v1 = native/compiled family sharing one plumbing stack: C, sync Rust, async Rust, Go. Then **C++20 coroutines** (identical mechanism to Rust async — proves the SemanticDecoder generalizes) then **Swift**. JVM/Python/JS = a SEPARATE later track (different recording stack: VM hooks, not eBPF/DWARF/CRIU). Don't promise them in v1. Erlang/BEAM: skip (already introspectable).

## Build order (README §8)
1. Single-threaded C/Rust, ptrace capture, fork checkpoint, basic DAP. 2. Multi-threaded (single-core serialization + divergence detection) **+ retroactive watchpoints pulled early** (second-most-novel, needs only replay). 3. Capture ptrace → eBPF/aya. 4. **Async-Rust semantic layer** (flagship; compiler internals). 5. Go goroutines. 6. C++20 coroutines + Swift + Workbench panes. Phases 1-3 alone = a shippable ARM checkpoint/replay debugger with watchpoints.

## The spine (why 2 repos, one system)
Time-travel/replay is the universal primitive: Mirrorscope = replay over **execution**, `lifeos-vcs` = history over **files**, Life OS memory = event-sourced **knowledge**. Mirrorscope owns the execution axis.

## Conventions (inherited house style)
Rust-native. Conventional commits, no co-author trailers. Many small files (200-400 lines, 800 max), functions <50 lines, immutable patterns, explicit error handling, validate at boundaries. Tests ≥80%, TDD. Run `cargo clean` after a build session (target/ is gitignored but regrows into tens of GB).
