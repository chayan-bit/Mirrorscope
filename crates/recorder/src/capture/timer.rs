//! Periodic preemption timer for the single-core scheduler.
//!
//! The scheduler runs one tracee at a time and blocks in `waitpid` for its
//! next instrumented stop. A thread spinning in a *syscall-free* loop never
//! produces such a stop, so without an external nudge it would run forever and
//! starve every other thread — and the recorded schedule would never show the
//! other threads making progress.
//!
//! This timer is that nudge. It arms a `CLOCK_MONOTONIC` POSIX timer
//! ([`timer_create`]/[`timer_settime`]) before the scheduler resumes a tracee;
//! when the quantum expires, `SIGALRM` is delivered to *the exact tracer
//! thread that armed it* (`SIGEV_THREAD_ID`, not a process-wide `setitimer`)
//! with a no-op handler installed **without** `SA_RESTART`, so that thread's
//! blocking `waitpid` returns `EINTR`. The scheduler treats that as a
//! preemption point, stops the running tracee, records a
//! [`SchedSwitch`](crate::capture::payload::SchedSwitch), and rotates.
//!
//! # Why not `setitimer`
//! `setitimer(ITIMER_REAL, ..)` is process-directed: the kernel may deliver
//! the resulting `SIGALRM` to *any* thread in the process that doesn't have it
//! blocked, not necessarily the one blocked in the scheduler's `waitpid`. The
//! scheduler's own thread is exactly that — a single thread among however
//! many the host process happens to have (`cargo test` alone runs each test
//! on its own worker thread) — so a process-wide timer can silently starve
//! the scheduler: the alarm fires, but on a thread that isn't waiting on it,
//! and the loop never sees `EINTR`. A syscall-free spinning tracee then runs
//! forever and every other thread starves behind it. `SIGEV_THREAD_ID` pins
//! the signal to the tracer thread's `tid`, captured at [`install`], so the
//! preemption is delivered where it is actually observed regardless of how
//! many other threads exist in the process.
//!
//! # Determinism caveat (honest)
//! The *instruction* at which a spinning tracee is preempted is timing
//! dependent and **not** reproducible without hardware instruction counting
//! (the very thing the ARM thesis forgoes). What is reproducible is the
//! **order** of instrumented points across threads, which is exactly what the
//! recorded [`SchedSwitch`] stream captures. Spans between instrumented points
//! are treated as atomic; data races within such a span are only sound under
//! single-core serialization. Replay re-derives the interleaving from the log
//! and leans on checksum divergence detection (issue #11) to surface — never
//! silently show — any execution that drifts outside the recorded schedule.

use std::time::Duration;

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

use crate::capture::error::CaptureError;

/// Default scheduling quantum: how long a single tracee may run before the
/// timer forces a preemption point. Coarse on purpose — fine enough to keep
/// spin loops from starving peers, coarse enough not to drown the trace.
pub const DEFAULT_QUANTUM: Duration = Duration::from_millis(10);

/// A `SIGALRM`-based preemption source for the scheduler, pinned to the
/// thread that installs it via `SIGEV_THREAD_ID` (see module docs for why a
/// process-wide `setitimer` is not safe to use here).
#[derive(Debug)]
pub struct PreemptionTimer {
    quantum: Duration,
    timer: libc::timer_t,
}

/// No-op `SIGALRM` handler: its only job is to interrupt `waitpid`.
extern "C" fn on_alarm(_sig: libc::c_int) {}

impl PreemptionTimer {
    /// Install the `SIGALRM` handler (idempotent across timers) and create a
    /// disarmed `CLOCK_MONOTONIC` timer bound to the *calling thread*, using
    /// `quantum` as its one-shot duration.
    pub fn install(quantum: Duration) -> Result<Self, CaptureError> {
        let action = SigAction::new(
            SigHandler::Handler(on_alarm),
            SaFlags::empty(), // deliberately NOT SA_RESTART: we want EINTR.
            SigSet::empty(),
        );
        // SAFETY: `on_alarm` is async-signal-safe (it does nothing), and we
        // install a handler for SIGALRM only; no other thread races this setup.
        #[allow(unsafe_code)]
        unsafe {
            sigaction(Signal::SIGALRM, &action)?;
        }

        // SAFETY: an all-zero `sigevent` is a valid bit pattern (plain-old-data
        // C struct of integers); every field we care about is set explicitly
        // below before the struct is used.
        #[allow(unsafe_code)]
        let mut sev: libc::sigevent = unsafe { std::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_THREAD_ID;
        sev.sigev_signo = libc::SIGALRM;
        // SAFETY: `gettid()` takes no arguments and cannot fail; it returns
        // the calling thread's tid, which is exactly the thread this timer's
        // signal must land on (the one about to block in `waitpid`).
        #[allow(unsafe_code)]
        {
            sev.sigev_notify_thread_id = unsafe { libc::gettid() };
        }

        let mut timer: libc::timer_t = std::ptr::null_mut();
        // SAFETY: `sev` is fully initialized above; `timer` is a valid
        // out-pointer for the kernel to write the new timer id into.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut timer) };
        if rc == -1 {
            return Err(CaptureError::Ptrace(nix::Error::last()));
        }

        Ok(Self { quantum, timer })
    }

    /// Arm a one-shot alarm `quantum` from now, delivered to this timer's
    /// owning thread.
    pub fn arm(&self) -> Result<(), CaptureError> {
        self.set_interval(self.quantum)
    }

    /// Cancel any pending alarm.
    pub fn disarm(&self) -> Result<(), CaptureError> {
        self.set_interval(Duration::ZERO)
    }

    fn set_interval(&self, dur: Duration) -> Result<(), CaptureError> {
        let value = libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: libc::c_long::from(dur.subsec_nanos()),
        };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let it = libc::itimerspec {
            it_interval: zero,
            it_value: value,
        };
        // SAFETY: `it` is a fully-initialized itimerspec that outlives the
        // call; the old-value pointer is null (we don't need it); `self.timer`
        // was created by `timer_create` above and is not shared.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::timer_settime(self.timer, 0, &it, std::ptr::null_mut()) };
        if rc == -1 {
            return Err(CaptureError::Ptrace(nix::Error::last()));
        }
        Ok(())
    }
}

impl Drop for PreemptionTimer {
    fn drop(&mut self) {
        // SAFETY: `self.timer` was created by `timer_create` in `install` and
        // is deleted at most once, here.
        #[allow(unsafe_code)]
        unsafe {
            libc::timer_delete(self.timer);
        }
    }
}
