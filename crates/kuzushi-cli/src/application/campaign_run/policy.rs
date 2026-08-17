//! Pure dispatch decisions: exit-code classification, retry ladder,
//! rate-limit sniffing, quota-wall counting, and the budget gate. No I/O —
//! everything here is unit-testable without processes or files.

/// How one child `kuzushi run` attempt ended, classified from the batch
/// exit-code contract (0/2/3/4, 1 = operational) plus dispatcher-observed
/// terminations (timeout kill, shutdown kill).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum JobOutcome {
    Completed,
    Blocked,
    ToolFailed,
    Partial,
    Canceled,
    OperationalError,
    TimedOut,
    Interrupted,
    /// The dispatcher killed the child because its live traced spend
    /// crossed the per-job budget ceiling.
    OverBudget,
    /// The dispatcher killed the child because its canonical live accounting
    /// stream could no longer authorize continued spend.
    BudgetEvidenceUnavailable,
}

impl JobOutcome {
    pub(super) fn from_exit_code(code: Option<i32>) -> Self {
        match code {
            Some(0) => Self::Completed,
            Some(2) => Self::Blocked,
            Some(3) => Self::ToolFailed,
            Some(4) => Self::Partial,
            Some(130) => Self::Canceled,
            _ => Self::OperationalError,
        }
    }

    pub(super) fn from_persisted_status(status: &str) -> Option<Self> {
        match status {
            "completed" | "skipped" => Some(Self::Completed),
            "blocked" => Some(Self::Blocked),
            "failed" => Some(Self::ToolFailed),
            "partial" => Some(Self::Partial),
            "canceled" => Some(Self::Canceled),
            "interrupted" => Some(Self::Interrupted),
            _ => None,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Blocked => "blocked",
            Self::ToolFailed => "tool-failed",
            Self::Partial => "partial",
            Self::Canceled => "canceled",
            Self::OperationalError => "operational-error",
            Self::TimedOut => "timed-out",
            Self::Interrupted => "interrupted",
            Self::OverBudget => "over-budget",
            Self::BudgetEvidenceUnavailable => "budget-evidence-unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Transition {
    Complete,
    Park {
        reason: String,
    },
    Requeue {
        backoff_secs: u64,
        consume_attempt: bool,
    },
    Fail,
}

/// The retry ladder. `attempts_used` counts consumed attempts INCLUDING the
/// one that just finished. Prepare failures park immediately (same input →
/// same rejection). Rate-limited failures requeue without consuming an
/// attempt — a quota wall is the provider's state, not the job's fault —
/// matching the forever-retry queue that survives overnight 429 walls.
pub(super) fn transition_for(
    outcome: JobOutcome,
    rate_limited: bool,
    attempts_used: u32,
    max_attempts: u32,
    base_backoff_secs: u64,
) -> Transition {
    match outcome {
        JobOutcome::Completed => Transition::Complete,
        JobOutcome::Blocked => park(outcome),
        JobOutcome::Canceled => park(outcome),
        JobOutcome::Interrupted => park(outcome),
        // Retrying a job with no trustworthy spend evidence can spend again
        // under the same broken guard, even when its output resembles a 429.
        JobOutcome::BudgetEvidenceUnavailable => park(outcome),
        // Retrying an over-budget job would just spend the same money
        // again; it parks with its partial run state kept for resume.
        JobOutcome::OverBudget => park(outcome),
        _ if rate_limited => Transition::Requeue {
            backoff_secs: base_backoff_secs,
            consume_attempt: false,
        },
        _ if attempts_used < max_attempts => Transition::Requeue {
            backoff_secs: retry_backoff_secs(base_backoff_secs, attempts_used),
            consume_attempt: true,
        },
        _ => Transition::Fail,
    }
}

fn park(outcome: JobOutcome) -> Transition {
    Transition::Park {
        reason: outcome.label().to_string(),
    }
}

/// Exponential backoff per consumed attempt, capped so a fat-fingered
/// max-attempts value cannot schedule a job into next week.
fn retry_backoff_secs(base: u64, attempts_used: u32) -> u64 {
    let shift = attempts_used.saturating_sub(1).min(6);
    (base.max(1)) << shift
}

const RATE_LIMIT_MARKERS: &[&str] = &[
    "429",
    "rate limit",
    "rate_limited",
    "rate-limited",
    "resource_exhausted",
    "resource exhausted",
    "too many requests",
    "quota exceeded",
    "overloaded",
];

/// Conservative substring sniff over the child's stderr tail and recorded
/// run error. False negatives cost one retry attempt; false positives only
/// delay a retry — so matching stays broad and case-insensitive.
pub(super) fn looks_rate_limited(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    RATE_LIMIT_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

/// Consecutive rate-limited failures across the whole campaign. Any
/// non-rate-limited terminal resets the streak; crossing the threshold
/// signals a provider-wide quota wall and the dispatcher pauses globally.
#[derive(Debug)]
pub(super) struct QuotaWall {
    consecutive: usize,
    threshold: usize,
}

impl QuotaWall {
    pub(super) fn new(threshold: usize) -> Self {
        Self {
            consecutive: 0,
            threshold: threshold.max(1),
        }
    }

    pub(super) fn observe(&mut self, rate_limited: bool) -> bool {
        if !rate_limited {
            self.consecutive = 0;
            return false;
        }
        self.consecutive += 1;
        if self.consecutive >= self.threshold {
            self.consecutive = 0;
            return true;
        }
        false
    }
}

/// True once spent cost reaches the cap. `None` = unlimited.
pub(super) fn budget_exhausted(spent_usd: f64, budget_usd: Option<f64>) -> bool {
    budget_usd.is_some_and(|cap| spent_usd >= cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_map_to_the_batch_contract() {
        assert_eq!(JobOutcome::from_exit_code(Some(0)), JobOutcome::Completed);
        assert_eq!(JobOutcome::from_exit_code(Some(2)), JobOutcome::Blocked);
        assert_eq!(JobOutcome::from_exit_code(Some(3)), JobOutcome::ToolFailed);
        assert_eq!(JobOutcome::from_exit_code(Some(4)), JobOutcome::Partial);
        assert_eq!(JobOutcome::from_exit_code(Some(130)), JobOutcome::Canceled);
        assert_eq!(
            JobOutcome::from_exit_code(None),
            JobOutcome::OperationalError
        );
        assert_eq!(
            JobOutcome::from_exit_code(Some(1)),
            JobOutcome::OperationalError
        );
    }

    #[test]
    fn persisted_host_statuses_preserve_cancellation_identity() {
        assert_eq!(
            JobOutcome::from_persisted_status("canceled"),
            Some(JobOutcome::Canceled)
        );
        assert_eq!(
            JobOutcome::from_persisted_status("interrupted"),
            Some(JobOutcome::Interrupted)
        );
        assert_eq!(
            transition_for(JobOutcome::Canceled, false, 1, 3, 5),
            Transition::Park {
                reason: "canceled".to_string()
            }
        );
    }

    #[test]
    fn prepare_failures_park_and_never_retry() {
        let transition = transition_for(JobOutcome::Blocked, false, 1, 3, 5);
        assert_eq!(
            transition,
            Transition::Park {
                reason: "blocked".to_string()
            }
        );
    }

    #[test]
    fn tool_failures_requeue_with_doubling_backoff_until_attempts_run_out() {
        assert_eq!(
            transition_for(JobOutcome::ToolFailed, false, 1, 3, 5),
            Transition::Requeue {
                backoff_secs: 5,
                consume_attempt: true
            }
        );
        assert_eq!(
            transition_for(JobOutcome::ToolFailed, false, 2, 3, 5),
            Transition::Requeue {
                backoff_secs: 10,
                consume_attempt: true
            }
        );
        assert_eq!(
            transition_for(JobOutcome::ToolFailed, false, 3, 3, 5),
            Transition::Fail
        );
    }

    #[test]
    fn timeouts_and_partials_ride_the_same_retry_ladder() {
        assert!(matches!(
            transition_for(JobOutcome::TimedOut, false, 1, 2, 5),
            Transition::Requeue { .. }
        ));
        assert!(matches!(
            transition_for(JobOutcome::Partial, false, 2, 2, 5),
            Transition::Fail
        ));
    }

    #[test]
    fn over_budget_parks_and_never_retries_even_with_attempts_left() {
        let transition = transition_for(JobOutcome::OverBudget, false, 1, 5, 5);
        assert_eq!(
            transition,
            Transition::Park {
                reason: "over-budget".to_string()
            }
        );
        assert_eq!(
            transition_for(JobOutcome::OverBudget, true, 1, 5, 5),
            Transition::Park {
                reason: "over-budget".to_string()
            }
        );
    }

    #[test]
    fn unavailable_budget_evidence_parks_before_rate_limit_retry_logic() {
        let expected = Transition::Park {
            reason: "budget-evidence-unavailable".to_string(),
        };
        assert_eq!(
            transition_for(JobOutcome::BudgetEvidenceUnavailable, false, 1, 5, 5),
            expected
        );
        assert_eq!(
            transition_for(JobOutcome::BudgetEvidenceUnavailable, true, 1, 5, 5),
            Transition::Park {
                reason: "budget-evidence-unavailable".to_string()
            }
        );
    }

    #[test]
    fn rate_limited_failures_never_consume_an_attempt() {
        let transition = transition_for(JobOutcome::ToolFailed, true, 3, 3, 7);
        assert_eq!(
            transition,
            Transition::Requeue {
                backoff_secs: 7,
                consume_attempt: false
            }
        );
    }

    #[test]
    fn rate_limit_sniffing_matches_provider_phrasings() {
        assert!(looks_rate_limited("HTTP 429 Too Many Requests"));
        assert!(looks_rate_limited("Vertex says RESOURCE_EXHAUSTED"));
        assert!(looks_rate_limited("provider overloaded, retry later"));
        assert!(!looks_rate_limited("assertion failed: index out of range"));
    }

    #[test]
    fn quota_wall_trips_on_consecutive_rate_limits_only() {
        let mut wall = QuotaWall::new(3);
        assert!(!wall.observe(true));
        assert!(!wall.observe(true));
        assert!(!wall.observe(false));
        assert!(!wall.observe(true));
        assert!(!wall.observe(true));
        assert!(wall.observe(true));
        assert!(!wall.observe(true));
    }

    #[test]
    fn budget_gate_is_inclusive_and_ignores_unlimited() {
        assert!(!budget_exhausted(10.0, None));
        assert!(!budget_exhausted(9.99, Some(10.0)));
        assert!(budget_exhausted(10.0, Some(10.0)));
    }

    #[test]
    fn backoff_shift_is_capped() {
        assert_eq!(retry_backoff_secs(5, 40), 5 << 6);
        assert_eq!(retry_backoff_secs(0, 1), 1);
    }
}
