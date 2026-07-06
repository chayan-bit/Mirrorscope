//! Linux-only integration test for issue #7: unwind and symbolize the current
//! thread's own stack.
//!
//! A `#[inline(never)]` call chain three deep, plus the capture site, records
//! its own registers at the bottom and unwinds via [`SelfMemory`] using modules
//! from `/proc/self/maps`. The recovered, symbolized frame names must contain
//! the chain in caller order. This exercises the real framehop + addr2line path
//! on whichever architecture the test runs (x86-64 and aarch64).

#![cfg(target_os = "linux")]

use std::hint::black_box;
use std::path::Path;

use unwind::maps::read_self_modules;
use unwind::{
    unwind_symbolized, InitialRegs, SelfMemory, StackUnwinder, SymbolizedFrame, Symbolizer,
};

/// Build an unwinder and symbolizer covering every file-backed module.
fn build() -> (StackUnwinder, Symbolizer) {
    let mut unwinder = StackUnwinder::new();
    let mut symbolizer = Symbolizer::new();
    for module in read_self_modules().expect("read /proc/self/maps") {
        // Best effort: skip modules that fail to parse (e.g. deleted files).
        let _ = unwinder.add_module(Path::new(&module.path), module.base);
        let _ = symbolizer.add_module(Path::new(&module.path), module.base);
    }
    (unwinder, symbolizer)
}

/// Capture the current registers and unwind, all within this one live frame so
/// the captured `sp`/`fp` and the caller chain above it stay valid.
#[inline(never)]
#[allow(unsafe_code)]
fn capture_and_unwind(
    unwinder: &mut StackUnwinder,
    symbolizer: &Symbolizer,
) -> Vec<SymbolizedFrame> {
    #[cfg(target_arch = "x86_64")]
    let regs = {
        let (pc, sp, fp): (u64, u64, u64);
        // SAFETY: reads rip/rsp/rbp into locals; the block accesses no memory.
        unsafe {
            std::arch::asm!(
                "lea {pc}, [rip]",
                "mov {sp}, rsp",
                "mov {fp}, rbp",
                pc = out(reg) pc,
                sp = out(reg) sp,
                fp = out(reg) fp,
                options(nomem, nostack, preserves_flags),
            );
        }
        InitialRegs { pc, sp, fp, lr: 0 }
    };
    #[cfg(target_arch = "aarch64")]
    let regs = {
        let (pc, sp, fp, lr): (u64, u64, u64, u64);
        // SAFETY: reads pc/sp/x29/x30 into locals; the block accesses no memory.
        unsafe {
            std::arch::asm!(
                "adr {pc}, .",
                "mov {sp}, sp",
                "mov {fp}, x29",
                "mov {lr}, x30",
                pc = out(reg) pc,
                sp = out(reg) sp,
                fp = out(reg) fp,
                lr = out(reg) lr,
                options(nomem, nostack, preserves_flags),
            );
        }
        InitialRegs { pc, sp, fp, lr }
    };

    let mut mem = SelfMemory::new().expect("open /proc/self/mem");
    unwind_symbolized(unwinder, symbolizer, &regs, &mut mem).expect("unwind self stack")
}

#[inline(never)]
fn depth_three(unwinder: &mut StackUnwinder, symbolizer: &Symbolizer) -> Vec<SymbolizedFrame> {
    let frames = capture_and_unwind(unwinder, symbolizer);
    black_box(&frames);
    frames
}

#[inline(never)]
fn depth_two(unwinder: &mut StackUnwinder, symbolizer: &Symbolizer) -> Vec<SymbolizedFrame> {
    let frames = depth_three(unwinder, symbolizer);
    black_box(&frames);
    frames
}

#[inline(never)]
fn depth_one(unwinder: &mut StackUnwinder, symbolizer: &Symbolizer) -> Vec<SymbolizedFrame> {
    let frames = depth_two(unwinder, symbolizer);
    black_box(&frames);
    frames
}

/// Index of the first frame whose function name contains `needle`.
fn find(names: &[String], needle: &str) -> Option<usize> {
    names.iter().position(|name| name.contains(needle))
}

#[test]
fn unwinds_and_symbolizes_the_call_chain_in_order() {
    let (mut unwinder, symbolizer) = build();
    let frames = depth_one(&mut unwinder, &symbolizer);

    let names: Vec<String> = frames
        .iter()
        .filter_map(|frame| frame.function.clone())
        .collect();
    let joined = names.join("\n");

    let i3 = find(&names, "depth_three");
    let i2 = find(&names, "depth_two");
    let i1 = find(&names, "depth_one");
    assert!(
        matches!((i3, i2, i1), (Some(a), Some(b), Some(c)) if a < b && b < c),
        "expected depth_three < depth_two < depth_one in frame order; got:\n{joined}"
    );
}
