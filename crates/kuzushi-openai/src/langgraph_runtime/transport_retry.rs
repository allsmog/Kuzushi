//! Same-model transport retry policy shared by the query and next-step
//! bridge paths (explicitly allowed by the no-silent-fallback policy: the
//! model object is reused, only the transport attempt repeats).
//!
//! Rate limits get a schedule that can actually outlast a provider window —
//! the run keeps its built-up state and waits in place instead of dying and
//! forcing a from-scratch re-run. Other transients keep the fast schedule.

use std::time::{Duration, Instant};

use anyhow::Result;

use super::runtime_config::BridgeRetryPolicy;

/// A bridge failure worth retrying, with what we know about why.
pub(super) struct TransientFailure {
    pub(super) rate_limited: bool,
    /// Provider-declared wait (HTTP `Retry-After`), forwarded by the bridge.
    pub(super) retry_after: Option<Duration>,
}

const RETRY_AFTER_CAP: Duration = Duration::from_secs(300);

pub(super) fn max_attempts(failure: &TransientFailure, retry_policy: &BridgeRetryPolicy) -> usize {
    if failure.rate_limited {
        retry_policy.rate_limit_attempts()
    } else {
        retry_policy.attempts()
    }
}

/// Delay before the next attempt. The provider's `Retry-After` raises (never
/// lowers below) the schedule so we don't hammer inside a declared window.
pub(super) fn backoff_delay(
    attempt: usize,
    failure: &TransientFailure,
    retry_policy: &BridgeRetryPolicy,
) -> Duration {
    let configured = Duration::from_millis(retry_policy.delay_ms(attempt));
    let scheduled = if failure.rate_limited {
        rate_limit_delay(attempt).max(configured)
    } else {
        configured
    };
    match failure.retry_after {
        Some(after) => scheduled.max(after.min(RETRY_AFTER_CAP)),
        None => scheduled,
    }
}

fn rate_limit_delay(attempt: usize) -> Duration {
    Duration::from_secs(match attempt {
        0 | 1 => 2,
        2 => 5,
        3 => 10,
        _ => 20,
    })
}

/// Sleep out a backoff without ignoring cancellation: long rate-limit waits
/// must still abort promptly when the operator cancels the run.
pub(super) fn sleep_before_retry(
    delay: Duration,
    mut ensure_not_cancelled: impl FnMut() -> Result<()>,
) -> Result<()> {
    let deadline = Instant::now() + delay;
    loop {
        ensure_not_cancelled()?;
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Ok(());
        };
        std::thread::sleep(remaining.min(Duration::from_millis(200)));
    }
}

/// Classify a failed bridge response (`ok: false`) from its structured
/// fields. `None` means permanent — do not retry.
pub(super) fn response_transient_failure(
    status: Option<u16>,
    error_class: Option<&str>,
    error: Option<&str>,
    retry_after_seconds: Option<u64>,
) -> Option<TransientFailure> {
    let transient = matches!(status, Some(408 | 425 | 429 | 500..=599))
        || matches!(
            error_class,
            Some("rate_limited" | "timeout" | "provider_unavailable" | "transport")
        )
        || error.is_some_and(is_transient_bridge_error);
    transient.then(|| TransientFailure {
        rate_limited: matches!(status, Some(425 | 429)) || error_class == Some("rate_limited"),
        retry_after: retry_after_seconds.map(Duration::from_secs),
    })
}

/// Classify a transport-level failure (the bridge process itself failed)
/// from its message. `None` means permanent — do not retry.
pub(super) fn message_transient_failure(message: &str) -> Option<TransientFailure> {
    is_transient_bridge_error(message).then(|| TransientFailure {
        rate_limited: is_rate_limited_message(message),
        retry_after: None,
    })
}

fn is_rate_limited_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("429") || lower.contains("rate limit")
}

pub(super) fn is_transient_bridge_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "websocket closed 1006",
        "websocket closed",
        "socket hang up",
        "econnreset",
        "etimedout",
        "network error",
        "fetch failed",
        "429",
        "rate limit",
        "temporarily unavailable",
        "internal server error",
        "bad gateway",
        "service unavailable",
        "gateway timeout",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limits_get_more_attempts_and_a_window_sized_schedule() {
        let rate_limited = TransientFailure {
            rate_limited: true,
            retry_after: None,
        };
        let transport = TransientFailure {
            rate_limited: false,
            retry_after: None,
        };

        let policy = BridgeRetryPolicy::default();
        assert_eq!(max_attempts(&rate_limited, &policy), 5);
        assert_eq!(max_attempts(&transport, &policy), 3);
        assert_eq!(
            backoff_delay(1, &rate_limited, &policy),
            Duration::from_secs(2)
        );
        assert_eq!(
            backoff_delay(4, &rate_limited, &policy),
            Duration::from_secs(20)
        );
        assert_eq!(
            backoff_delay(1, &transport, &policy),
            Duration::from_millis(250)
        );
        let configured = BridgeRetryPolicy {
            attempts: Some(1),
            backoff_ms: 20_000,
        };
        assert_eq!(max_attempts(&rate_limited, &configured), 1);
        assert_eq!(max_attempts(&transport, &configured), 1);
        assert_eq!(
            backoff_delay(1, &rate_limited, &configured),
            Duration::from_secs(20)
        );
    }

    #[test]
    fn unavailable_mcp_sidecars_are_permanent_failures() {
        assert!(response_transient_failure(
            None,
            Some("mcp_unavailable"),
            Some("Restore the missing code-analysis component."),
            None,
        )
        .is_none());
    }

    #[test]
    fn provider_retry_after_raises_but_never_lowers_the_delay() {
        let declared = TransientFailure {
            rate_limited: true,
            retry_after: Some(Duration::from_secs(45)),
        };
        let policy = BridgeRetryPolicy::default();
        assert_eq!(
            backoff_delay(1, &declared, &policy),
            Duration::from_secs(45)
        );

        let shorter_than_schedule = TransientFailure {
            rate_limited: true,
            retry_after: Some(Duration::from_secs(1)),
        };
        assert_eq!(
            backoff_delay(4, &shorter_than_schedule, &policy),
            Duration::from_secs(20)
        );

        let absurd = TransientFailure {
            rate_limited: true,
            retry_after: Some(Duration::from_secs(86_400)),
        };
        assert_eq!(backoff_delay(1, &absurd, &policy), RETRY_AFTER_CAP);
    }

    #[test]
    fn classification_separates_rate_limits_permanent_and_transport_errors() {
        let limited = response_transient_failure(Some(429), Some("rate_limited"), None, Some(30))
            .expect("429 is transient");
        assert!(limited.rate_limited);
        assert_eq!(limited.retry_after, Some(Duration::from_secs(30)));

        assert!(
            response_transient_failure(Some(401), Some("authentication"), None, None).is_none()
        );

        let flaky = message_transient_failure("socket hang up").expect("transport is transient");
        assert!(!flaky.rate_limited);
        assert!(message_transient_failure("Provider rejected the request.").is_none());
        assert!(
            message_transient_failure("Provider rate limited the request (HTTP 429).")
                .expect("429 text is transient")
                .rate_limited
        );
    }

    #[test]
    fn backoff_sleep_aborts_on_cancellation() {
        let error = sleep_before_retry(Duration::from_secs(60), || anyhow::bail!("cancelled"))
            .expect_err("cancellation must interrupt the wait");
        assert!(error.to_string().contains("cancelled"));

        sleep_before_retry(Duration::from_millis(1), || Ok(())).expect("short sleep completes");
    }
}
