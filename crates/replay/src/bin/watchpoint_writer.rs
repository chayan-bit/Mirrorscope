//! Test fixture for the retroactive-watchpoint integration test (issue #12).
//!
//! Prints the address of a global, then writes that global a fixed number of
//! times with distinct values. The `tests/watchpoint.rs` harness records this
//! fixture, learns the address from a probe replay, and scans for writes to it.
//! It is a test fixture, not part of the shipped `mirrorscope` tool; it lives
//! as a `[[bin]]` so integration tests can find it via `CARGO_BIN_EXE_*`.
//!
//! Because both the recorder and the replay engine pin the layout with
//! `ADDR_NO_RANDOMIZE`, the printed address is identical at record and replay
//! time, so a watchpoint armed on it during replay lands on the same global.

use std::io::Write;

/// The watched global. `static mut` so writes are plain stores to a fixed BSS
/// address rather than going through a cell's API.
static mut TARGET: u64 = 0;

/// How many times the fixture writes the global — the exact hit count the test
/// asserts.
const WRITES: u64 = 5;

/// Write the global `WRITES` times with distinct, increasing values. `inline`
/// is suppressed so the writes symbolize to this named frame in a backtrace.
#[inline(never)]
fn hammer() {
    for value in 1..=WRITES {
        // SAFETY: single-threaded fixture writing its own `static mut` through a
        // volatile store so the compiler neither elides nor coalesces the
        // writes; each iteration is a distinct store the watchpoint must catch.
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::write_volatile(std::ptr::addr_of_mut!(TARGET), value);
        }
    }
}

fn main() {
    let addr = std::ptr::addr_of!(TARGET) as u64;
    println!("{addr}");
    // Flush so the address reaches the recorded stdout before the writes run.
    std::io::stdout().flush().ok();
    hammer();
}
