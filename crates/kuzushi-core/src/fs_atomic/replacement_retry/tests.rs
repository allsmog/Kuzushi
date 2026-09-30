use super::*;

#[test]
fn successful_replacement_never_waits() {
    replace_with_retry(|| Ok(())).unwrap();
    retry_replacement(
        || Ok(()),
        |_| panic!("successful replacement must not wait"),
    )
    .unwrap();
}

#[test]
fn transient_windows_contention_retries_the_same_atomic_operation() {
    for code in [5, 32] {
        let mut attempts = 0;
        let mut waits = Vec::new();
        retry_replacement(
            || {
                attempts += 1;
                if attempts < 4 {
                    Err(io::Error::from_raw_os_error(code))
                } else {
                    Ok(())
                }
            },
            |delay| waits.push(delay),
        )
        .unwrap();
        assert_eq!(attempts, 4);
        assert_eq!(waits, [1, 2, 4].map(Duration::from_millis));
    }
}

#[test]
fn unrelated_errors_return_without_retry() {
    let mut attempts = 0;
    let error = retry_replacement(
        || {
            attempts += 1;
            Err(io::Error::from_raw_os_error(112))
        },
        |_| panic!("disk full must not be retried"),
    )
    .unwrap_err();
    assert_eq!(attempts, 1);
    assert_eq!(error.raw_os_error(), Some(112));
}

#[test]
fn persistent_contention_preserves_error_and_has_a_bounded_wait_budget() {
    let mut attempts = 0;
    let mut waited = Duration::ZERO;
    let error = retry_replacement(
        || {
            attempts += 1;
            Err(io::Error::from_raw_os_error(5))
        },
        |delay| waited += delay,
    )
    .unwrap_err();
    assert_eq!(attempts, MAX_RETRIES + 1);
    assert_eq!(waited, Duration::from_millis(511));
    assert_eq!(error.raw_os_error(), Some(5));
}
