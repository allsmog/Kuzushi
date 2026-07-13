use super::KwpError;
use std::time::{Duration, Instant};

const MINIMUM_TIMEOUT: Duration = Duration::from_millis(1);

pub(super) fn effective_broker_timeout(
    remaining: Duration,
    fallback: Duration,
    constraints: &[Option<Duration>],
) -> Result<Duration, KwpError> {
    if remaining.is_zero() {
        return Err(KwpError::Deadline);
    }
    let constrained = constraints
        .iter()
        .flatten()
        .copied()
        .map(nonzero_timeout)
        .fold(nonzero_timeout(fallback), Duration::min);
    Ok(remaining.min(constrained))
}

pub(super) fn broker_timeout_before(
    deadline: Instant,
    fallback: Duration,
    constraints: &[Option<Duration>],
) -> Result<Duration, KwpError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(KwpError::Deadline)?;
    effective_broker_timeout(remaining, fallback, constraints)
}

pub(super) fn milliseconds(value: Option<u64>) -> Option<Duration> {
    value.map(Duration::from_millis)
}

pub(super) fn seconds(value: Option<u64>) -> Option<Duration> {
    value.map(Duration::from_secs)
}

fn nonzero_timeout(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        MINIMUM_TIMEOUT
    } else {
        timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_timeout_clamps_every_constraint_and_remaining_time() {
        let timeout = effective_broker_timeout(
            Duration::from_millis(80),
            Duration::from_secs(30),
            &[
                Some(Duration::from_millis(40)),
                Some(Duration::from_millis(20)),
            ],
        )
        .unwrap();
        assert_eq!(timeout, Duration::from_millis(20));

        let remaining = effective_broker_timeout(
            Duration::from_millis(5),
            Duration::from_secs(30),
            &[Some(Duration::from_millis(20))],
        )
        .unwrap();
        assert_eq!(remaining, Duration::from_millis(5));
    }

    #[test]
    fn effective_timeout_rejects_an_expired_session() {
        assert_eq!(
            effective_broker_timeout(Duration::ZERO, Duration::from_secs(1), &[]),
            Err(KwpError::Deadline)
        );
    }

    #[test]
    fn zero_request_timeout_keeps_the_existing_one_millisecond_floor() {
        assert_eq!(
            effective_broker_timeout(
                Duration::from_secs(1),
                Duration::from_secs(30),
                &[Some(Duration::ZERO)]
            )
            .unwrap(),
            MINIMUM_TIMEOUT
        );
    }
}
