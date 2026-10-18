use super::*;

fn key(id: &str) -> ViewHydrationKey {
    ViewHydrationKey::ScanStudyProgress {
        campaign_id: id.into(),
    }
}

#[test]
fn study_cache_is_target_and_plan_scoped_with_bounded_refresh() {
    let mut cache = WorkbenchCache::default();
    let target = Path::new("/owned/first");
    cache.apply_view_hydration(ViewHydrationResult {
        target: target.into(),
        key: key("one"),
        value: ViewHydrationValue::ScanStudyProgress(Err("Owned diagnostic".into())),
    });
    assert!(matches!(
        cache.cached_scan_study_progress(target, &key("one")),
        ViewDataState::Ready(Err(_))
    ));
    assert!(cache
        .cached_scan_study_progress(Path::new("/owned/second"), &key("one"))
        .is_not_requested());
    assert!(cache
        .cached_scan_study_progress(target, &key("two"))
        .is_not_requested());
    assert!(!cache.view_hydration_needed(target, &key("one")));
    cache.scan_study_progress.as_mut().unwrap().read_at -= Duration::from_secs(2);
    assert!(cache.view_hydration_needed(target, &key("one")));
    cache.mark_view_hydration_loading(target, &[key("one")]);
    assert!(matches!(
        cache.cached_scan_study_progress(target, &key("one")),
        ViewDataState::Ready(Err(_))
    ));
}

#[test]
fn failed_worker_replaces_the_read_with_an_explicit_retryable_error() {
    let target = Path::new("/owned/first");
    let mut cache = WorkbenchCache::default();
    cache.mark_view_hydration_loading(target, &[key("one")]);
    cache.clear_failed_view_hydrations(&[ViewHydrationFailure {
        target: target.into(),
        key: key("one"),
    }]);
    let ViewDataState::Ready(Err(error)) = cache.cached_scan_study_progress(target, &key("one"))
    else {
        panic!("Failed read cannot remain a loading or ready queue");
    };
    assert!(error.contains("unavailable") && error.contains("retrying"));
}
