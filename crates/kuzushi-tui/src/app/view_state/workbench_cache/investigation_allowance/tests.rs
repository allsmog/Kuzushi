use super::*;

fn key(run: &str) -> ViewHydrationKey {
    ViewHydrationKey::InvestigationAllowance {
        run_refs: vec![run.into()],
    }
}

#[test]
fn allowance_cache_is_scoped_to_exact_target_and_displayed_runs() {
    let mut cache = WorkbenchCache::default();
    let target = Path::new("/owned/one");
    cache.apply_view_hydration(ViewHydrationResult {
        target: target.into(),
        key: key("one"),
        value: ViewHydrationValue::InvestigationAllowance(Ok(None)),
    });
    assert!(matches!(
        cache.cached_investigation_allowance(target, &key("one")),
        ViewDataState::Ready(Ok(None))
    ));
    assert!(cache
        .cached_investigation_allowance(Path::new("/owned/two"), &key("one"))
        .is_not_requested());
    assert!(cache
        .cached_investigation_allowance(target, &key("two"))
        .is_not_requested());
}

#[test]
fn allowance_refresh_is_bounded_and_keeps_previous_read_until_new_result() {
    let mut cache = WorkbenchCache::default();
    let target = Path::new("/owned");
    cache.apply_view_hydration(ViewHydrationResult {
        target: target.into(),
        key: key("run"),
        value: ViewHydrationValue::InvestigationAllowance(Ok(None)),
    });
    assert!(!cache.view_hydration_needed(target, &key("run")));
    cache.investigation_allowance.as_mut().unwrap().read_at -= REFRESH_INTERVAL;
    assert!(cache.view_hydration_needed(target, &key("run")));
    cache.mark_view_hydration_loading(target, &[key("run")]);
    assert!(matches!(
        cache.cached_investigation_allowance(target, &key("run")),
        ViewDataState::Ready(Ok(None))
    ));
    cache.clear_failed_view_hydrations(&[ViewHydrationFailure::unexplained(
        target.into(),
        key("run"),
    )]);
    assert!(matches!(
        cache.cached_investigation_allowance(target, &key("run")),
        ViewDataState::Ready(Err(_))
    ));
    assert!(!cache.view_hydration_needed(target, &key("run")));
}
