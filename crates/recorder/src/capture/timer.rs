//! Periodic preemption timer for the single-core scheduler.
//!
//! The scheduler runs one tracee at a time and blocks in `waitpid` for its
//! next instrumented stop. A thread spinning in a *syscall-free* loop never
//! produces such a stop, so without an external nudge it would run forever and
//! starve every other thread — and the recorded schedule would never show the
//! other threads making progress.
//!
//! This timer is that nudge. It arms `ITIMER_REAL` before the scheduler resumes
//! a tracee; when the quantum expires, `SIGALRM` is delivered to the *tracer*
//! (not the tracee) with a no-op handler installed **without** `SA_RESTART`, so
//! the tracer's blocking `waitpid` returns `EINTR`. The scheduler treats that
//! as a preemption point, stops the running tracee, records a
//! [`SchedSwitch`](crate::capture::payload::SchedSwitch), and rotates.
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

/// A `SIGALRM`-based preemption source for the scheduler.
#[derive(Debug)]
pub struct PreemptionTimer {
    quantum: Duration,
}

/// No-op `SIGALRM` handler: its only job is to interrupt `waitpid`.
extern "C" fn on_alarm(_sig: libc::c_int) {}

impl PreemptionTimer {
    /// Install the `SIGALRM` handler (idempotent across timers) and return a
    /// disarmed timer using `quantum`.
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
        Ok(Self { quantum })
    }

    /// Arm a one-shot alarm `quantum` from now.
    pub fn arm(&self) -> Result<(), CaptureError> {
        self.set_interval(self.quantum)
    }

    /// Cancel any pending alarm.
    pub fn disarm(&self) -> Result<(), CaptureError> {
        self.set_interval(Duration::ZERO)
    }

    fn set_interval(&self, dur: Duration) -> Result<(), CaptureError> {
        let value = libc::timeval {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_usec: dur.subsec_micros() as libc::suseconds_t,
        };
        let zero = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let it = libc::itimerval {
            it_interval: zero,
            it_value: value,
        };
        // SAFETY: `it` is a fully-initialized itimerval that outlives the call;
        // the old-value pointer is null (we don't need it).
        #[allow(unsafe_code)]
        let rc = unsafe { libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut()) };
        if rc == -1 {
            return Err(CaptureError::Ptrace(nix::Error::last()));
        }
        Ok(())
    }
}
