//! Portable checkpoint bookkeeping — interval decisions and nearest-checkpoint
//! selection.
//!
//! Deliberately free of any ptrace/`nix`/`libc` reference so it compiles and
//! unit-tests on every platform, including macOS. The Linux-only fork-snapshot
//! machinery that these decisions drive lives in the [`crate::checkpoint`]
//! module; keeping the arithmetic here means the load-bearing "which checkpoint
//! do I restore to" logic is covered by tests that run in ordinary `cargo test`.
//!
//! All sequence numbers are trace-global `seq` values (see `recorder::trace`),
//! and every helper treats intervals in those same units.

/// Whether a fresh checkpoint is due at trace position `current`, given the seq
/// of the most recent checkpoint (`last`, `None` if none taken yet) and the
/// configured `interval`. An `interval` of `0` disables checkpointing entirely.
///
/// The gap test (`current >= last + interval`) — rather than an absolute grid —
/// keeps checkpoints from bunching up after a restore rewinds `current`, and
/// naturally suppresses duplicates when replay re-runs an already-covered span.
pub(crate) fn is_checkpoint_due(last: Option<u64>, current: u64, interval: u64) -> bool {
    if interval == 0 {
        return false;
    }
    match last {
        None => current >= interval,
        Some(last) => current >= last.saturating_add(interval),
    }
}

/// Index of the nearest checkpoint whose seq is at-or-before `target`, given
/// `seqs` in ascending order. `None` when every checkpoint lies after `target`
/// (the caller then falls back to re-running from process entry).
pub(crate) fn nearest_at_or_before(seqs: &[u64], target: u64) -> Option<usize> {
    seqs.iter()
        .enumerate()
        .rev()
        .find(|(_, &seq)| seq <= target)
        .map(|(index, _)| index)
}

/// Whether `run_to(target)` must restart execution — restore a checkpoint or
/// respawn from entry — rather than simply drive forward from where the tracee
/// currently sits.
///
/// `current` is the last consumed seq (`None` when the session is fresh at
/// entry) and `start_seq` is the seq of the chosen restart point (`0` for
/// entry). A restart is required when the target is *behind* the current
/// position (only replay can go backward) or when the chosen checkpoint is
/// *ahead* of the current position (restoring it skips needless re-execution).
pub(crate) fn should_restart(current: Option<u64>, start_seq: u64, target: u64) -> bool {
    match current {
        None => start_seq > 0,
        Some(current) => current > target || start_seq > current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_checkpoint_is_ever_due_when_interval_is_zero() {
        assert!(!is_checkpoint_due(None, 1_000, 0));
        assert!(!is_checkpoint_due(Some(10), 1_000, 0));
    }

    #[test]
    fn first_checkpoint_is_due_once_current_reaches_the_interval() {
        assert!(!is_checkpoint_due(None, 3, 4));
        assert!(is_checkpoint_due(None, 4, 4));
        assert!(is_checkpoint_due(None, 9, 4));
    }

    #[test]
    fn subsequent_checkpoints_wait_a_full_interval_past_the_last() {
        assert!(!is_checkpoint_due(Some(8), 11, 4));
        assert!(is_checkpoint_due(Some(8), 12, 4));
        assert!(is_checkpoint_due(Some(8), 20, 4));
    }

    #[test]
    fn interval_arithmetic_saturates_instead_of_overflowing() {
        // `last + interval` would overflow; saturating to u64::MAX must leave a
        // modest `current` below the threshold (and never panic).
        assert!(!is_checkpoint_due(Some(u64::MAX - 2), 10, u64::MAX));
    }

    #[test]
    fn nearest_picks_the_greatest_seq_at_or_before_the_target() {
        let seqs = [2u64, 6, 10, 14];
        assert_eq!(nearest_at_or_before(&seqs, 11), Some(2)); // seq 10
        assert_eq!(nearest_at_or_before(&seqs, 10), Some(2)); // exact hit
        assert_eq!(nearest_at_or_before(&seqs, 6), Some(1));
        assert_eq!(nearest_at_or_before(&seqs, 100), Some(3));
    }

    #[test]
    fn nearest_is_none_when_all_checkpoints_are_after_the_target() {
        let seqs = [6u64, 10, 14];
        assert_eq!(nearest_at_or_before(&seqs, 5), None);
        assert_eq!(nearest_at_or_before(&[], 5), None);
    }

    #[test]
    fn fresh_session_only_restarts_when_the_start_is_past_entry() {
        assert!(!should_restart(None, 0, 100)); // already at entry, drive forward
        assert!(should_restart(None, 20, 100)); // a checkpoint exists ahead
    }

    #[test]
    fn running_session_restarts_to_go_backward_or_to_skip_ahead() {
        // Target behind the current position → must restore/respawn.
        assert!(should_restart(Some(50), 20, 30));
        // Chosen checkpoint ahead of current position → restore to skip re-run.
        assert!(should_restart(Some(10), 40, 60));
        // Target ahead and no better checkpoint than where we are → drive on.
        assert!(!should_restart(Some(10), 10, 60));
        assert!(!should_restart(Some(10), 0, 60));
    }
}
