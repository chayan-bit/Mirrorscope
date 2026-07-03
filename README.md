# Mirrorscope

A cross-platform, eBPF-assisted **time-travel debugger** for C, Rust, and Go - with first-class **async-Rust** and **goroutine** semantics - exposed over the Debug Adapter Protocol (DAP).

Mirrorscope is a standalone tool (usable from any DAP client, including VS Code). It is also the **debug engine** of the [Life OS Workbench](https://github.com/chayan-bit/lifeos-workbench) (local `../lifeos-workbench`), which is its primary DAP client and native host UI - see [§10](#10-workbench-integration).

> Status: design-complete specification, pre-implementation. This README is the canonical architecture doc; `CLAUDE.md` is the working-rules companion.

---

## 0. Relationship to the sibling repo

| Repo | Role | Contract |
|---|---|---|
| [`lifeos-workbench`](https://github.com/chayan-bit/lifeos-workbench) (local `../lifeos-workbench`) | Terminal-weight, agent-native IDE (terminal + editor + AI agent + Life OS front-end in one Rust binary). | The Workbench is Mirrorscope's **primary DAP client + host UI**, and exposes Mirrorscope's operations to its AI agent for **agentic time-travel debugging**. Mirrorscope stays independent of it: the contract is DAP, nothing more. See [§10](#10-workbench-integration). |

Shared spine across both repos: **time-travel / replay as a universal primitive** - Mirrorscope replays *execution*, `lifeos-vcs` versions *files*, Life OS memory event-sources *knowledge*.

---

## 1. Why this is a real gap (not reinventing rr)

`rr` is the gold standard for record-replay, but it has three hard limits:

- **x86-only** — it depends on Intel performance counters for precise instruction counting during replay.
- **No async-awareness** — it replays raw instructions/syscalls with no concept of a Rust `Future` state machine or a Go goroutine, so you read the executor's poll loop, not the logical task that is paused.
- **Linux-only, single-machine** — no distributed or cross-thread-interleaving story beyond ptrace/perf.

Undo's commercial tool solves ARM via a software JIT (dynamic binary translation) instead of hardware counters - a proven alternative worth borrowing conceptually. But the actual novel contribution of Mirrorscope is **not** the recording mechanism.

### The thesis (the class, not the instance)

> **Reconstruct the logical concurrency structure that the compiler or runtime flattened away at the machine level - and make it time-travelable.**

Async Rust flattens tasks into state-machine structs. Go hides goroutines in runtime structs. C++20 coroutines flatten into heap frames. In every case a native debugger shows you the executor's poll loop, not the logical task. **That gap is the product**, and framing it as a *class* forces a language-pluggable **semantic decoder** ([§4](#4-the-semanticdecoder-abstraction)) instead of hardcoded per-language paths.

Two genuinely-new pillars; everything else is plumbing to be reused:

1. **Logical-task-tree reconstruction + time-travel** (the semantic layer) — no open or commercial tool does this correctly for async Rust.
2. **Retroactive watchpoints via replay** ("every write to X across all of history") — only possible with replay, and useful even for boring synchronous C.

---

## 2. System layers

```
┌─────────────────────────────────────────────┐
│  DAP server (VS Code / Workbench / any client)│  Layer 4
├─────────────────────────────────────────────┤
│  Query & introspection engine                 │  Layer 5
│  (unwinding, variable eval, watchpoints)      │
├─────────────────────────────────────────────┤
│  Language semantic layer (SemanticDecoder)    │  Layer 3  ← the novel work
│  (async-task / goroutine / coroutine decoders)│
├─────────────────────────────────────────────┤
│  Replay execution engine                      │  Layer 2
│  (checkpoint restore + deterministic re-run)  │
├─────────────────────────────────────────────┤
│  Recording layer (eBPF + ptrace + snapshot)   │  Layer 1
└─────────────────────────────────────────────┘
```

---

## 3. Layer 1 — recording

Core decision: **don't be instruction-exact like rr.** Record enough to make externally-observable behavior replayable between periodic full-process checkpoints. Trades some precision for portability (no perf counters → works on ARM).

### 3.1 What gets captured

| Source of non-determinism | Capture mechanism |
|---|---|
| Syscall return values (`read`/`recv`/`getrandom`/`clock_gettime`/…) | eBPF tracepoints (`sys_enter`/`sys_exit`) → ring buffer; ptrace `PTRACE_SYSCALL` fallback on non-BTF kernels |
| Signal delivery timing | eBPF kprobe on the signal path; or ptrace signal-stop |
| Thread scheduling order | eBPF tracepoint `sched:sched_switch` |
| Shared-memory / lock ordering | uprobes on `pthread_mutex_lock/unlock`, `cond_wait`, and runtime primitives (Rust `parking_lot`, Go runtime lock) |
| Process/thread creation | eBPF on `sched_process_fork`/`clone` |

Events stream into a `BPF_MAP_TYPE_RINGBUF`, consumed by a userspace collector, written to an append-only log with a monotonic global sequence number. Use **`aya`** (pure-Rust eBPF, CO-RE via BTF) rather than libbpf/BCC to stay in one language and one build.

### 3.2 Checkpointing

Full snapshots on a time/event-count interval (tunable, e.g. every 50 ms or 10k syscalls) and on demand at "record checkpoint here" breakpoints.

- **CRIU** — default backend; handles open fds/sockets/mmaps. Note its real limits up front: it does **not** handle GPU state or some namespaces (matters for CUDA/Vulkan targets).
- **Fork-snapshot** — for trivial short-lived single-process targets where CRIU overhead isn't worth it.
- **Incremental snapshots** — don't full-dump every 50 ms. Use `userfaultfd` + soft-dirty page tracking (`/proc/pid/pagemap`) to copy only pages changed since the last checkpoint: turns checkpoint cost from O(RSS) to O(working set). This is the difference between usable-on-real-workloads and not.

### 3.3 The hard problem — deterministic thread interleaving, stated properly

The crux the naive framing hides is the **data-race problem**: syscall-boundary recording is only sound if the program is race-free at the granularity recorded. Three honest design points - choose consciously:

| Approach | Soundness | Cost | Record-time parallelism |
|---|---|---|---|
| **Single-core serialization (rr's trick)** | Sound even with data races (no true concurrency → shared memory has a total order for free) | Cheap: log preemption points + syscall results | None (threads time-slice on one core) |
| **Sync-primitive ordering** | Sound only for race-free programs (a lock-free/atomic race is invisible) | Proportional to lock frequency | Full |
| **Full memory-access instrumentation** | Always sound | 10-100× slowdown | Full |

The MVP is **rr's single-core model** - but rr drives preemption with perf counters, which we can't use (that's the whole ARM thesis). So the real research problem is **deterministic preemption on ARM without hardware instruction counters**:

- **Preempt only at instrumented points** (syscalls + uprobe'd sync primitives + a periodic timer signal), treating spans between them as atomic regions. Defensible for a debugger: you inspect state at synchronization/syscall boundaries; nothing externally observable happens between them. This is Undo's software-JIT territory, reachable in a coarse form without a full JIT.
- **Divergence detection as a safety net** (not the mechanism): checksum key memory at each checkpoint; on replay mismatch, surface *"replay diverged, non-deterministic execution outside recorded synchronization"* rather than silently showing wrong state. Honest and shippable.

Prior art to port (don't re-derive the edge cases — time, `rdtsc`, randomness, scheduling): **Meta's Hermit** (deterministic Linux execution sandbox) and **DetTrace**.

---

## 4. The SemanticDecoder abstraction

One trait; every language is a plugin behind it. The recording/replay/DAP layers never know which language they serve.

```rust
trait SemanticDecoder {
    /// Given a restored/paused process image + DWARF + runtime metadata,
    /// produce the logical concurrency tree, not the physical stack.
    fn decode_tasks(&self, mem: &ProcessImage, dwarf: &Dwarf) -> TaskTree;
    fn logical_stack(&self, task: TaskId) -> Vec<LogicalFrame>;
    fn wake_cause(&self, task: TaskId) -> Option<WakeEvent>;
    fn locals_at(&self, task: TaskId) -> Vec<Local>;
}
```

Rust-async, Go, and (next) C++-coroutine each implement it. This is the "solve the class, not the instance" move.

---

## 5. Layer 3 — the semantic layer (the actual novel work)

### 5.1 C and synchronous Rust — mostly solved
Standard DWARF (**gimli** + **addr2line** + **object**), CFI unwinding. Rust wrinkles: niche-optimized enums, monomorphized generics, trait-object vtable resolution. Use **framehop** (the unwinder behind the Firefox profiler / `samply`) - fast, correct, and **aarch64**-capable - instead of hand-rolling CFI on ARM. Study probe-rs and Delve as references.

### 5.2 Async Rust — the genuinely hard, genuinely needed part

An `async fn` lowers to a compiler-generated coroutine → an enum-like state machine: variants are the suspend points (`Suspended(0)`, `Suspended(1)`, …) plus `Unresumed`/`Returned`/`Panicked`; locals live across an `.await` are fields of the active variant; the discriminant says which await you're parked at.

- **Lean on existing instrumentation.** **`tokio-console`** already exposes task IDs, poll counts/timing, waker events, and task↔resource relationships via the `tracing` crate's instrumentation points. Consume/extend that offline for Tokio (≈80% of the audience) rather than re-deriving executor uprobes. Uprobes are the **fallback** for uninstrumented executors (embassy, custom).
- **State-machine layout is a rustc implementation detail with no stability guarantee** - it has changed across editions and coroutine-layout optimizations (field overlap for non-overlapping-lifetime locals makes naive field reads wrong). Maintain a **per-rustc-version layout model** (like Delve's per-Go-version offset tables), pinned via the DWARF producer string. **This is the single highest-risk item; budget for it as a living compatibility DB.**
- **`select!`/`join!` fan out → the logical structure is a tree, not a stack.** Model it as a tree internally; the DAP "stack trace" is a flattened projection.
- **Waker causality** ("why did this task wake") is what native debuggers structurally cannot provide, and it falls out nearly free from the `tracing`/uprobe waker events. Prioritize it.

### 5.3 Go goroutines — easier, still real
Read `runtime.allgs`, walk `gobuf.sp/pc` per goroutine, DWARF-unwind from there. Vendor **Delve's** per-Go-version runtime offset tables rather than re-deriving. Extra care: Go grows/moves goroutine stacks, so pointers into stacks are invalidated across a growth - treat stack-relocation as a first-class event or you'll read stale frames after a growth between checkpoints. The novel part is combining this with replay so you can *scrub goroutine history*, not just inspect live.

---

## 6. Should Mirrorscope extend to other languages? Yes — only along the novelty axis

Extend only where the same gap exists (concurrency the machine level hides). Random languages dilute the thesis.

| Language | Mechanism | Same gap? | Shares the plumbing? | Verdict |
|---|---|---|---|---|
| **C++20 coroutines** | Compiler-generated heap coroutine frame + promise object | **Identical to Rust async** | Full (native, DWARF, eBPF, CRIU) | **First after Rust.** Huge audience, worse existing tooling, and it *proves* the SemanticDecoder generalizes. |
| **Swift async/await** | Continuation-based async task runtime, heap async frames | Yes | Full (native/LLVM/DWARF); ARM-native | Strong second (matches the ARM thesis). |
| **Go** | Runtime goroutine structs | Yes (in-plan) | Full | Keep as planned. |
| **Kotlin coroutines** | CPS `Continuation` objects on JVM | Yes but **JVM** | Different (JVMTI, not eBPF/DWARF/CRIU) | Separate later track. |
| **Python asyncio / Node V8** | Interpreter/VM-managed tasks | Yes | Different (interpreter hooks) | Separate later track. |
| Erlang/BEAM | Already introspectable | Small gap | — | Skip. |

**Recommendation:** keep v1 to the **native/compiled family** (C, sync Rust, async Rust, Go) sharing one plumbing stack (eBPF + DWARF + framehop + CRIU). Add **C++20 coroutines** then **Swift** as the proof the abstraction holds - nearly free because they reuse everything below Layer 3. Treat **JVM/Python/JS** as a deliberately separate future track with its own recording stack; promising them in v1 is how the project drowns.

---

## 7. Layer 4 — DAP server + replay engine

DAP already specs `reverseContinue` and `stepBack` (added for exactly this; GDB and rr implement them), so you implement protocol, not invent it.

- **Replay-to-timestamp:** find the nearest preceding checkpoint, restore (CRIU/fork), replay forward using the recorded syscall/scheduling log until the target sequence number.
- **Custom DAP requests** (vendor extensions): `listCheckpoints`, `taskTimeline` (async task lifecycle), `jumpToEvent`.
- **Retroactive watchpoints** ("show every write to this location across history") - re-run a replay pass with a hardware watchpoint (or eBPF uprobe if software-only) active, collecting all hits *without* having logged every memory write at record time. The killer feature that justifies the whole engineering cost.

Raw DAP clients can't render a task tree or a scrub timeline, so the reference plan calls for a thin companion UI (Pernosco-over-rr style). In the **Workbench** that companion UI is native and free ([§10](#10-workbench-integration)).

---

## 8. Build order

| Phase | Scope | Why here |
|---|---|---|
| 1 | Single-threaded C/Rust; ptrace syscall capture; fork checkpointing; basic DAP (`reverseContinue`/`stepBack`) | Prove the core loop. Cross-platform (ARM+x86) replay without perf counters is already differentiated from rr. |
| 2 | Multi-threaded; single-core serialization + divergence detection; **retroactive watchpoints** | Real programs are concurrent. **Watchpoints pulled early** — the second-most-novel feature, works on plain C, needs only replay. Ship something exciting before Phase 4. |
| 3 | Move capture ptrace → eBPF (`aya`) tracepoints/uprobes | Big overhead win before real workloads. |
| 4 | **Async-Rust semantic layer** (tokio-console instrumentation → state-machine decoding → logical stack + waker causality) | The flagship differentiator. Compiler-internals knowledge stops being optional here. |
| 5 | Go goroutine layer (Delve offset tables) | Extends reach with less novel risk. |
| 6 | C++20 coroutines + Swift decoders; task-timeline polish; Workbench panes | Prove the SemanticDecoder generalizes; make it pleasant. |

Phases 1-3 alone are a shippable, differentiated project: a portable checkpoint/replay debugger with DAP + retroactive watchpoints that works on ARM. Phase 4 is where it becomes a novel contribution to async-Rust tooling.

---

## 9. Concrete stack (Rust-native, all reusable)

- Unwinding: **framehop** (x86-64 + aarch64). DWARF: **gimli** + **addr2line** + **object**.
- eBPF: **aya** (CO-RE, BTF).
- Checkpoint: **CRIU** default; `userfaultfd` + soft-dirty incremental; fork-snapshot for trivial targets.
- Async introspection: consume/extend **tokio-console**'s `tracing` instrumentation; uprobes for uninstrumented executors.
- Go: vendor **Delve's** runtime offset tables.
- Determinism references: **Hermit**, **DetTrace**, **rr** (single-core model), **Undo** (software-JIT-on-ARM).
- DAP: implement `reverseContinue`/`stepBack` + `listCheckpoints`/`taskTimeline`/`jumpToEvent`.

---

## 10. Workbench integration

The [Life OS Workbench](https://github.com/chayan-bit/lifeos-workbench) is Mirrorscope's primary client. Contract: **DAP only** - Mirrorscope stays a standalone tool; do not build Workbench-specific coupling into it.

- **Native panes for free.** The Workbench owns its DAP client, so Mirrorscope's task tree, replay scrubber, checkpoint list, watchpoint results, and waker-causality render as native TUI panes there - the "companion UI" this spec wanted, without a separate extension.
- **Agentic time-travel debugging (flagship).** The Workbench is also an ACP agent host, so it exposes Mirrorscope's DAP ops (`reverseContinue`, `setWatchpoint`, `jumpToEvent`, `readLogicalStack`) to the agent as tools. The agent can replay-to-fault → set a retroactive watchpoint → scrub to the causing write → read logical async task state → propose a fix, autonomously. No existing tool has this; it only works because editor + agent + debugger are one process.
- **Artifacts feed Life OS.** Debug sessions/checkpoints/root-causes are written back as `events`/`entities` in the Workbench's Coding module - searchable and versioned.

Mirrorscope must remain fully usable **without** the Workbench (VS Code, `nvim-dap`, any DAP client). The Workbench is the best client, not a dependency.

---

## 11. Prior art (study, don't blindly copy)

- **rr** — recording/replay split, DWARF introspection, single-core serialization.
- **Undo** (commercial) — software-JIT-based non-perf-counter recording (ARM).
- **Delve** — Go runtime struct-layout tracking, goroutine stack walking.
- **Pernosco** — how to layer a useful UI over a replay engine.
- **FireDBG** — closest existing async-Rust visual debugging (WIP on async); read their sync/async-boundary writeups before re-deriving.
- **tokio-console** — live async task/waker introspection via `tracing`.
- **framehop / samply** — fast async-friendly unwinding on x86-64 + aarch64.
- **Hermit / DetTrace** — deterministic Linux execution.
- **CRIU docs** — checkpoint/restore semantics and limits (namespaces, GPU state).

---

## 12. Status

Design-complete specification, pre-implementation. See `CLAUDE.md` for working rules and the sibling [`lifeos-workbench`](https://github.com/chayan-bit/lifeos-workbench) for the host UI + agentic-debugging integration.
