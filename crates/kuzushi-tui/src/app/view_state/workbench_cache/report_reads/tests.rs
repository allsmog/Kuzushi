use super::*;

fn study(id: &str, digest: &str, watermark: Option<u64>) -> ViewHydrationKey {
    ViewHydrationKey::InvestigationStudyReport {
        campaign_id: id.into(),
        plan_sha256: digest.into(),
        findings_watermark: watermark,
    }
}

fn runs(names: &[&str], watermark: Option<u64>) -> ViewHydrationKey {
    ViewHydrationKey::InvestigationReport {
        run_refs: names.iter().map(|name| (*name).into()).collect(),
        findings_watermark: watermark,
    }
}

#[test]
fn refresh_retains_shared_bytes_but_invalidates_current_readiness() {
    let target = Path::new("/owned-a");
    let key = study("owned-study", "digest", Some(8));
    let document = Arc::new(vec![7_u8; 1024 * 1024]);
    let mut cache = ReportReadCache::default();
    cache.store(target.into(), key.clone(), Ok(document.clone()));
    cache.invalidate_target(target);
    assert!(cache.current(target, &key).is_none());
    assert!(Arc::ptr_eq(
        cache.previous(target, &key).unwrap(),
        &document
    ));
    assert_eq!(Arc::strong_count(&document), 2);
    cache.invalidate_target(target);
    assert!(
        cache.previous(target, &key).is_some(),
        "repeated refresh retains the same read"
    );
}

#[test]
fn previous_reads_cannot_cross_target_campaign_plan_or_run_membership() {
    let target = Path::new("/owned-a");
    let mut cache = ReportReadCache::default();
    cache.store(target.into(), study("a", "first", Some(1)), Ok(42));
    for key in [
        study("b", "first", Some(1)),
        study("a", "changed", Some(1)),
        runs(&["run-a"], Some(1)),
    ] {
        assert!(cache.previous(target, &key).is_none());
    }
    assert!(cache
        .previous(Path::new("/owned-b"), &study("a", "first", Some(1)))
        .is_none());
    cache.store(target.into(), runs(&["a", "b"], Some(1)), Ok(43));
    assert!(cache.previous(target, &runs(&["a"], Some(2))).is_none());
    assert_eq!(
        cache.previous(target, &runs(&["a", "b"], Some(2))),
        Some(&43)
    );
    assert!(cache
        .previous(target, &ViewHydrationKey::GitMetadata)
        .is_none());
}

#[test]
fn regressed_or_missing_watermarks_do_not_reuse_previous_review_counts() {
    let target = Path::new("/owned");
    let mut cache = ReportReadCache::default();
    cache.store(target.into(), study("a", "first", Some(8)), Ok(42));
    assert!(cache
        .previous(target, &study("a", "first", Some(7)))
        .is_none());
    assert!(cache.previous(target, &study("a", "first", None)).is_none());
    assert_eq!(
        cache.previous(target, &study("a", "first", Some(9))),
        Some(&42)
    );
    assert!(cache
        .current(target, &study("a", "first", Some(9)))
        .is_none());
}

#[test]
fn read_failure_replaces_old_content_and_explicit_retry_cannot_resurrect_it() {
    let target = Path::new("/owned");
    let key = study("a", "first", None);
    let mut cache = ReportReadCache::default();
    cache.store(target.into(), key.clone(), Ok(42));
    cache.invalidate();
    cache.store(
        target.into(),
        key.clone(),
        Err("Owned unavailable ledger".into()),
    );
    assert!(cache.current(target, &key).unwrap().is_err());
    assert!(cache.previous(target, &key).is_none());
    cache.invalidate();
    assert!(cache.previous(target, &key).is_none());
}

#[test]
fn workspace_history_keeps_its_own_previous_read_and_drops_superseded_payloads() {
    let target = Path::new("/owned");
    let key = ViewHydrationKey::WorkspaceReportReview {
        findings_watermark: Some(2),
    };
    let mut cache = ReportReadCache::default();
    let first = Arc::new(42);
    let weak = Arc::downgrade(&first);
    cache.store(target.into(), key.clone(), Ok(first));
    cache.invalidate();
    assert!(cache.previous(target, &key).is_some());
    assert!(cache
        .previous(target, &study("a", "first", Some(2)))
        .is_none());
    cache.store(target.into(), key, Ok(Arc::new(43)));
    assert!(weak.upgrade().is_none());
}
