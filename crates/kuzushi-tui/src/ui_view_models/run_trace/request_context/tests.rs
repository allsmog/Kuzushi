use super::*;
use kuzushi_core::allowance::{AllowanceLimits, AllowanceReferenceV1, AllowanceSnapshot};

fn context() -> RunRequestContext {
    let allowance = RunAllowanceContext {
        reference: AllowanceReferenceV1 {
            schema_version: 1,
            investigation_id: "owned".into(),
            revision: 1,
            work_id: "job".into(),
        },
        approved_model: "selected:original".into(),
        approved_limits: AllowanceLimits {
            max_provider_calls: 3,
            protected_review_calls: 1,
        },
        current: AllowanceSnapshot {
            schema_version: 1,
            investigation_id: "owned".into(),
            revision: 2,
            model: "selected:revised".into(),
            limits: AllowanceLimits {
                max_provider_calls: 7,
                protected_review_calls: 1,
            },
            committed_calls: 2,
            review_calls: 0,
            unresolved_calls: 1,
            cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
            work_plan: None,
        },
        run_committed_calls: 2,
        run_unsettled_calls: 1,
    };
    RunRequestContext {
        run_id: "run".into(),
        read_at_unix: 1_700_000_000,
        scope: Ok(RecordedRequestScope::ExplicitPaths { count: 2 }),
        allowance: Ok(Some(allowance)),
        allowance_origin: RecordedAllowanceOrigin::Explicit,
    }
}

#[test]
fn original_grant_and_latest_read_have_distinct_labels_and_unknown_dollars() {
    let model = present(&context());
    let detail = model.details.join("\n");
    assert!(
        detail.contains("Run grant: owned r1; 3 calls total"),
        "{detail}"
    );
    assert!(
        detail.contains("Latest ledger at read: r2; 2/7 calls committed"),
        "{detail}"
    );
    assert!(
        detail.contains("4 other calls; 1 protected Review; 1 unsettled"),
        "{detail}"
    );
    assert!(detail.contains("2023-11-14T22:13:20Z"));
    assert!(detail.contains("does not establish discovery coverage"));
    assert!(!detail.contains("$0"));
    assert!(model.compact(40).contains("calls 2/7 at read"));
    assert!(model.rail.iter().any(|row| row == "Run grant r1: 3 calls"));
}

#[test]
fn inherited_grant_explains_parent_totals_without_claiming_child_spending() {
    let mut read = context();
    read.allowance_origin = RecordedAllowanceOrigin::Inherited {
        accounting_run_id: "parent-review".into(),
        work: kuzushi_core::allowance::InvestigationWork::Review,
    };
    let model = present(&read);
    let detail = model.details.join("\n");
    assert!(detail.contains("Inherited Review grant: owned r1"));
    assert!(detail.contains("Accounting run: parent-review; 2 committed calls; 1 unsettled"));
    assert!(detail.contains("not isolated child charges"));
    assert!(detail.contains("does not approve or start child work"));
    assert!(!detail.contains("This run:") && !detail.contains("$0"));
    assert!(model.compact(40).contains("inherited Review"));
    assert!(model.compact(40).contains("calls 2/7 at read"));
    assert!(model
        .rail
        .iter()
        .any(|row| row.contains("Inherited Review grant r1")));
}

#[test]
fn unknown_grant_and_independent_scope_error_are_not_zero_or_whole_repository() {
    let mut input = context();
    input.scope = Err("missing accepted record".into());
    input.allowance = Ok(None);
    let model = present(&input);
    let detail = model.details.join("\n");
    assert!(detail.contains("Requested scope unavailable"));
    assert!(model.compact(40).contains("no recorded grant"));
    assert!(model.compact(40).starts_with("Scope "));
    assert!(!detail.contains("0 calls") && !detail.contains("whole repository"));
    input.allowance = Err("ledger missing".into());
    assert!(present(&input)
        .details
        .join("\n")
        .contains("limits unavailable"));
}

#[test]
fn missing_scope_is_named_explicitly_in_compact_and_rail_projections() {
    let mut read = context();
    read.scope = Ok(RecordedRequestScope::NotRecorded);
    let model = present(&read);
    assert_eq!(model.compact(40), "Scope not recorded · calls 2/7 at read");
    assert_eq!(model.rail[0], "Scope not recorded");
    assert!(model
        .details
        .iter()
        .any(|row| row.contains("membership is not recorded")));
    assert!(!model.compact(40).contains("whole repository"));
}

#[test]
fn a_single_explicit_path_has_a_singular_label_without_inventing_accepted_membership() {
    let mut read = context();
    read.scope = Ok(RecordedRequestScope::ExplicitPaths { count: 1 });
    let model = present(&read);
    assert!(model.compact(40).contains("Scope 1 path"));
    assert!(model.details[0].contains("1 explicit path; no accepted scope reference"));
}

#[test]
fn compact_request_context_fits_unicode_at_all_supported_widths() {
    use unicode_width::UnicodeWidthStr;
    let mut model = present(&context());
    model.scope = safe("資料 👩‍💻 long\u{1b}[31m name\nsecond line");
    for width in [0, 1, 20, 40, 60, 80, 96, 120, 160] {
        let row = model.compact(width);
        assert!(row.width() <= width, "{width}: {row}");
        assert!(!row.contains('\u{1b}') && !row.contains('\n'));
    }
}

#[test]
fn request_context_cache_is_keyed_by_target_and_run_and_refreshable() {
    use crate::app::{ViewHydrationKey, ViewHydrationResult, ViewHydrationValue};
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let target = tempfile::tempdir().unwrap();
    app.set_target(Some(target.path().to_owned()));
    let read = std::sync::Arc::new(context());
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: target.path().to_owned(),
            key: ViewHydrationKey::RunRequestContext {
                run_id: "run".into(),
            },
            value: ViewHydrationValue::RunRequestContext(Ok(read)),
        });
    assert!(replay_request_context(&app, "run")
        .compact(80)
        .contains("2/7"));
    assert!(replay_request_context(&app, "other")
        .compact(80)
        .contains("loading"));
    let second = tempfile::tempdir().unwrap();
    app.set_target(Some(second.path().to_owned()));
    assert!(replay_request_context(&app, "run")
        .compact(80)
        .contains("loading"));
    app.set_target(Some(target.path().to_owned()));
    app.workbench_cache()
        .borrow_mut()
        .invalidate_run_request_context();
    assert!(replay_request_context(&app, "run")
        .compact(80)
        .contains("loading"));
}
