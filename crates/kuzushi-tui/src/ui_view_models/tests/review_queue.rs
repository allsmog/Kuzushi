use super::*;
use crate::app::{Msg, ShellEffect, TermEvent, WorkbenchPage};
use crate::commands::ReviewDecisionCommand;
use crate::ui_view_models::findings::projected_visible_finding_pairs;
use crate::ui_view_models::PhaseSurfaceId;
use crate::ui_view_models::{
    current_finding_for_detail, phase_cockpit_model_for_phase, PhaseCockpitBody,
};
use crate::{InputMode, PendingPatch, WorkflowPhase};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::findings::{
    BatchOccurrenceReport, BatchOccurrenceRow, IdentityFoldPolicy, ReviewDecision,
    ReviewDecisionRecord, ReviewDecisionVerdict, TriageAuthor,
};
use kuzushi_core::{
    Finding, FindingEvidence, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, Severity, StaticProofState, TriageOutcome, TriageVerdict, V2Config,
};

fn finding(rule: &str, severity: Severity, line: u32) -> Finding {
    Finding::new_tool("semgrep", rule, "src/lib.rs", line, None, severity, rule)
}

fn confirmed(mut finding: Finding) -> Finding {
    finding.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::TruePositive,
        confidence: 0.93,
        rationale: "reviewed".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    finding
}

fn human_confirmed(mut finding: Finding, confidence: f32) -> Finding {
    finding.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::TruePositive,
        confidence,
        rationale: "human reviewed".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    finding.triaged_by = Some(TriageAuthor::Human);
    finding
}

fn open_finding_with_evidence() -> Finding {
    let mut finding = finding("path-traversal", Severity::High, 20);
    finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    finding.evidence.push(FindingEvidence {
        kind: "code".to_string(),
        file_path: "src/lib.rs".to_string(),
        line: 20,
        snippet: "join(user_path)".to_string(),
        rationale: "untrusted path reaches file open".to_string(),
        confidence: 80,
        request_blob: None,
        response_blob: None,
    });
    finding
}

#[test]
fn review_queue_model_separates_open_and_terminal_decisions() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut open = open_finding_with_evidence();
    open.identity_id = Some("fi_0123456789abcdef0123456789abcdef".to_string());
    let done = confirmed(finding("sql-injection", Severity::Medium, 40));
    *app.selected_finding_mut() = Some(open.clone());
    *app.findings_mut() = vec![open, done];

    let open_model = review_queue_model(&app, ReviewQueueMode::Open);
    assert_eq!(open_model.total_count, 2);
    assert_eq!(open_model.visible_count, 1);
    assert_eq!(open_model.open_count, 1);
    assert_eq!(open_model.complete_count, 1);
    assert_eq!(open_model.filter_label, "completeness:open");
    assert_eq!(
        open_model.header,
        "REVIEW QUEUE - showing 1 of 2 - 1 open - 1 complete"
    );
    assert_eq!(
        open_model.ordering_indicator,
        Some(BASELINE_ORDERING_INDICATOR)
    );
    assert!(open_model.empty_reason.is_none());
    assert_eq!(open_model.rows[0].decision, "needs_review");
    assert_eq!(open_model.rows[0].identity_label, "FI-01234567");
    assert!(!open_model.rows[0].decision_complete);
    assert_eq!(open_model.rows[0].confidence_label, "-");
    assert_eq!(open_model.rows[0].lifecycle_status, "statically_supported");
    assert_eq!(open_model.rows[0].evidence_state, "evidence:1");
    assert!(open_model.row_is_selected(0));

    let complete_model = review_queue_model(&app, ReviewQueueMode::Complete);
    assert_eq!(complete_model.visible_count, 1);
    assert_eq!(complete_model.rows[0].decision, "confirmed");
    assert!(complete_model.rows[0].decision_complete);
    assert_eq!(complete_model.rows[0].confidence_label, "93%");
    assert_eq!(complete_model.rows[0].next_action, "review complete");
}

#[test]
fn review_queue_model_names_the_active_findings_filter() {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![finding("path-traversal", Severity::High, 20)];
    app.set_active_findings_filter(Some("severity:high".to_string()));

    let model = review_queue_model(&app, ReviewQueueMode::Open);

    assert_eq!(model.filter_label, "severity:high");
}

#[test]
fn review_queue_model_keeps_projected_duplicate_semantics() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let semgrep = finding("semgrep/cwe-89", Severity::Medium, 12);
    let systems = finding("systems/cwe-89", Severity::High, 14);
    assert_eq!(semgrep.dedup_key, systems.dedup_key);
    *app.findings_mut() = vec![semgrep, systems];

    let model = review_queue_model(&app, ReviewQueueMode::All);

    assert_eq!(model.total_count, 1);
    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].severity_label, "HIGH");
}

#[test]
fn active_batch_scopes_review_and_exposes_occurrence_and_run_facets() {
    let mut in_batch = finding("path-traversal", Severity::High, 20);
    in_batch.fingerprint = "batch-finding".to_string();
    in_batch.dedup_key = Some("batch-key".to_string());
    let mut outside = finding("sql-injection", Severity::Critical, 40);
    outside.fingerprint = "outside-finding".to_string();
    outside.dedup_key = Some("outside-key".to_string());
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![outside, in_batch];
    let deck = app.router.campaign_mut();
    deck.active_batch_id = Some("batch-1".to_string());
    deck.active_batch_report = Some(batch_report_for("batch-finding"));

    let model = review_queue_model(&app, ReviewQueueMode::All);

    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].rule, "path-traversal");
    assert_eq!(
        model.rows[0].occurrence,
        Some(ReviewOccurrence {
            seen: 2,
            completed: 3,
            planned: 4,
            failed: 1,
        })
    );
    assert!(model
        .active_filter_chips
        .contains(&"batch:batch-1".to_string()));
    let runs = model
        .facet_groups
        .iter()
        .find(|group| group.label == "runs")
        .unwrap();
    assert_eq!(runs.values[0].value, "run-1");
    assert_eq!(runs.values[0].count, 1);
}

#[test]
fn occurrence_ratio_is_metadata_only_for_a_tied_review_result() {
    let mut tied = finding("tied-result", Severity::High, 20);
    tied.fingerprint = "batch-finding".to_string();
    tied.dedup_key = Some("batch-key".to_string());
    tied.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::NeedsReview,
        confidence: 0.67,
        rationale: "equal votes remain tied".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    let sparse = review_row_with_occurrence(tied.clone(), 1);
    let repeated = review_row_with_occurrence(tied, 3);

    assert_eq!(sparse.decision, "needs_review");
    assert!(!sparse.decision_complete);
    assert_eq!(sparse.confidence_label, repeated.confidence_label);
    assert_eq!(sparse.workflow_group, ReviewWorkflowGroup::NeedsReview);
    let mut sparse_without_occurrence = sparse;
    let mut repeated_without_occurrence = repeated;
    sparse_without_occurrence.occurrence = None;
    repeated_without_occurrence.occurrence = None;
    assert_eq!(sparse_without_occurrence, repeated_without_occurrence);
}

fn review_row_with_occurrence(finding: Finding, seen: usize) -> ReviewQueueRow {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![finding];
    let deck = app.router.campaign_mut();
    deck.active_batch_id = Some("batch-1".to_string());
    deck.active_batch_report = Some(batch_report_with_occurrence("batch-finding", seen));
    review_queue_model(&app, ReviewQueueMode::All).rows[0].clone()
}

fn batch_report_for(fingerprint: &str) -> BatchOccurrenceReport {
    batch_report_with_occurrence(fingerprint, 2)
}

fn batch_report_with_occurrence(fingerprint: &str, seen: usize) -> BatchOccurrenceReport {
    BatchOccurrenceReport {
        schema_version: 1,
        batch_id: "batch-1".to_string(),
        equivalence_key: "eq-1".to_string(),
        identity_fold: IdentityFoldPolicy::Safe,
        planned: 4,
        completed: 3,
        failed: 1,
        pending: 0,
        gate: None,
        trials: Vec::new(),
        rows: vec![BatchOccurrenceRow {
            fold_key: fingerprint.to_string(),
            identity_id: None,
            identity_basis: None,
            seen,
            completed: 3,
            planned: 4,
            failed: 1,
            severities: vec!["high".to_string()],
            locations: vec!["src/lib.rs:20".to_string()],
            titles: vec!["path traversal".to_string()],
            fingerprints: vec![fingerprint.to_string()],
            run_ids: vec!["run-1".to_string(), "run-2".to_string()],
            representative_fingerprint: fingerprint.to_string(),
            representative_title: "path traversal".to_string(),
            representative_severity: "high".to_string(),
            representative_location: "src/lib.rs:20".to_string(),
        }],
    }
}

#[test]
fn review_queue_model_marks_cursor_row_when_no_finding_is_pinned() {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![
        finding("first", Severity::High, 1),
        finding("second", Severity::Medium, 2),
    ];
    app.router.findings_mut().set_cursor(1);
    *app.selected_finding_mut() = None;

    let model = review_queue_model(&app, ReviewQueueMode::All);

    assert!(!model.row_is_selected(0));
    assert!(model.row_is_selected(1));
}

#[test]
fn review_queue_rows_are_reused_across_cursor_only_navigation() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_findings(
        (0..400)
            .map(|index| finding(&format!("rule-{index:04}"), Severity::High, index + 1))
            .collect(),
    );

    let first = review_queue_model(&app, ReviewQueueMode::All);
    app.router.findings_mut().set_cursor(1);
    let navigated = review_queue_model(&app, ReviewQueueMode::All);

    assert!(std::sync::Arc::ptr_eq(&first.rows, &navigated.rows));
    assert!(navigated.row_is_selected(1));
    app.findings_mut()[0].severity = Severity::Critical;
    let refreshed = review_queue_model(&app, ReviewQueueMode::All);
    assert!(!std::sync::Arc::ptr_eq(&navigated.rows, &refreshed.rows));
}

#[test]
fn review_search_edits_refresh_cached_rows_and_keep_prefilter_facets() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut gateway = finding("gateway-ownership", Severity::High, 1);
    gateway.dedup_key = Some("gateway".to_string());
    let mut cookie = finding("cookie-bypass", Severity::Low, 2);
    cookie.dedup_key = Some("cookie".to_string());
    *app.findings_mut() = vec![gateway, cookie];
    app.router.workbench_mut().review_mut().search_query = "gateway".to_string();

    let gateway = review_queue_model(&app, ReviewQueueMode::All);
    let cached = review_queue_model(&app, ReviewQueueMode::All);
    assert_eq!(gateway.visible_count, 1);
    assert_eq!(gateway.total_count, 2);
    assert!(std::sync::Arc::ptr_eq(&gateway.rows, &cached.rows));
    assert_eq!(gateway.active_filter_chips, ["text:\"gateway\""]);
    let severity = gateway
        .facet_groups
        .iter()
        .find(|group| group.label == "severity")
        .expect("severity facets");
    assert!(severity
        .values
        .iter()
        .any(|value| value.value == "high" && value.count == 1));
    assert!(severity
        .values
        .iter()
        .any(|value| value.value == "low" && value.count == 1));

    app.router.workbench_mut().review_mut().search_query = "cookie".to_string();
    let cookie = review_queue_model(&app, ReviewQueueMode::All);
    assert_eq!(cookie.rows[0].rule, "cookie-bypass");
    assert!(!std::sync::Arc::ptr_eq(&gateway.rows, &cookie.rows));
}

#[test]
fn incremental_search_preserves_cursor_identity_and_pinned_finding() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut pinned = finding("pinned-cookie", Severity::Critical, 1);
    pinned.dedup_key = Some("pinned".to_string());
    let mut target = finding("needle-target", Severity::Low, 2);
    target.dedup_key = Some("needle".to_string());
    let mut other = finding("other-result", Severity::Medium, 3);
    other.dedup_key = Some("other".to_string());
    *app.findings_mut() = vec![pinned.clone(), target.clone(), other];
    *app.selected_finding_mut() = Some(pinned.clone());
    app.set_shell_view(crate::ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    app.set_input_mode(InputMode::Navigate);
    let target_position = crate::ui_view_models::visible_finding_position_for(&app, &target)
        .expect("target starts visible");
    app.router.findings_mut().set_cursor(target_position);

    press_workbench_key(&mut app, KeyCode::Char('/'));
    for character in "needle".chars() {
        press_workbench_key(&mut app, KeyCode::Char(character));
    }

    let visible = crate::ui_view_models::visible_finding_at_cursor(&app)
        .expect("matching target stays cursored");
    assert_eq!(visible.1.fingerprint, target.fingerprint);
    assert_eq!(app.selected_finding().as_ref(), Some(&pinned));

    press_workbench_key(&mut app, KeyCode::Backspace);
    assert_eq!(app.router.workbench().review().search_query, "needl");
    assert_eq!(
        crate::ui_view_models::visible_finding_at_cursor(&app)
            .expect("backspace refresh keeps matching identity")
            .1
            .fingerprint,
        target.fingerprint
    );
    press_workbench_key(&mut app, KeyCode::Enter);
    assert!(!app.router.workbench().review().search_capture);
    assert_eq!(app.router.workbench().review().search_query, "needl");

    press_workbench_key(&mut app, KeyCode::Char('/'));
    press_workbench_key(&mut app, KeyCode::Esc);
    let restored = crate::ui_view_models::visible_finding_at_cursor(&app)
        .expect("target is re-anchored after clearing search");
    assert_eq!(restored.1.fingerprint, target.fingerprint);
    assert!(app.router.workbench().review().search_query.is_empty());
    assert_eq!(app.selected_finding().as_ref(), Some(&pinned));
}

#[test]
fn zero_result_search_clamps_cursor_without_retargeting_pin() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut pinned = finding("pinned", Severity::High, 1);
    pinned.dedup_key = Some("pinned".to_string());
    let mut other = finding("other", Severity::Low, 2);
    other.dedup_key = Some("other".to_string());
    *app.findings_mut() = vec![pinned.clone(), other];
    *app.selected_finding_mut() = Some(pinned.clone());
    app.router.findings_mut().set_cursor(1);
    app.router.workbench_mut().review_mut().search_query = "no-such-result".to_string();
    app.clamp_findings_cursor();

    let model = review_queue_model(&app, ReviewQueueMode::All);
    assert_eq!(app.router.findings().cursor(), 0);
    assert_eq!(model.visible_count, 0);
    assert_eq!(model.total_count, 2);
    assert_eq!(
        model.empty_reason.as_deref(),
        Some("no findings match the active search and filters")
    );
    assert_eq!(app.selected_finding().as_ref(), Some(&pinned));
    let PhaseCockpitBody::Review(review) =
        phase_cockpit_model_for_phase(&app, WorkflowPhase::Review).body
    else {
        panic!("expected Review cockpit");
    };
    let disclosure = review
        .selection_disclosure
        .expect("pinned finding disclosure");
    assert_eq!(disclosure.filter, "search:no-such-result");
    assert!(disclosure.message.contains("outside"));
}

#[test]
fn review_queue_cursor_identity_wins_over_a_stale_pinned_finding() {
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![
        finding("first", Severity::High, 1),
        finding("second", Severity::Medium, 2),
    ];
    let projected = projected_visible_finding_pairs(&app);
    assert_eq!(projected.len(), 2);
    *app.selected_finding_mut() = Some(projected[0].1.clone());
    app.router.findings_mut().set_cursor(1);

    let model = review_queue_model(&app, ReviewQueueMode::All);
    let selected = model.selected().expect("cursor row selected");
    let detail = crate::ui_view_models::current_finding_for_detail(&app).expect("cursor detail");

    assert_eq!(selected.alias, projected[1].0);
    assert_eq!(detail.1.fingerprint, projected[1].1.fingerprint);

    app.open_finding_at_cursor();
    assert_eq!(
        app.selected_finding()
            .as_ref()
            .map(|finding| &finding.fingerprint),
        Some(&projected[1].1.fingerprint)
    );
}

#[test]
fn repeated_j_crosses_workflow_group_boundary_without_identity_drift() {
    let mut confirmed = finding("confirmed", Severity::Critical, 3);
    confirmed.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::TruePositive,
        confidence: 0.99,
        rationale: "runtime confirmed".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    confirmed.verification = Some(crate::test_support::test_empirical_verification(3));
    let needs_high = finding("needs-high", Severity::High, 1);
    let needs_low = finding("needs-low", Severity::Low, 2);
    let needs_low_fingerprint = needs_low.fingerprint.clone();
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![confirmed, needs_low, needs_high];
    app.set_shell_view(crate::ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(crate::app::WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(crate::ui_view_models::PhaseSurfaceId::ReviewQueue);
    app.set_input_mode(crate::InputMode::Navigate);

    let model = review_queue_model(&app, ReviewQueueMode::All);
    assert_eq!(model.rows[0].rule, "confirmed");
    assert_eq!(model.rows[1].rule, "needs-high");
    assert_eq!(model.rows[2].rule, "needs-low");
    assert_eq!(model.rows[0].workflow_group, ReviewWorkflowGroup::Confirmed);
    assert_eq!(
        model.rows[1].workflow_group,
        ReviewWorkflowGroup::NeedsReview
    );

    press_workbench_key(&mut app, crossterm::event::KeyCode::Char('j'));
    let model = review_queue_model(&app, ReviewQueueMode::All);
    assert_eq!(model.rows[1].rule, "needs-high");
    assert!(model.row_is_selected(1));

    press_workbench_key(&mut app, crossterm::event::KeyCode::Char('j'));
    let model = review_queue_model(&app, ReviewQueueMode::All);
    assert_eq!(model.rows[2].rule, "needs-low");
    assert_eq!(
        model.rows[2].workflow_group,
        ReviewWorkflowGroup::NeedsReview
    );
    assert!(model.row_is_selected(2));
    let detail = crate::ui_view_models::current_finding_for_detail(&app).expect("cursor detail");
    assert_eq!(detail.1.fingerprint, needs_low_fingerprint);

    press_workbench_key(&mut app, crossterm::event::KeyCode::Enter);
    assert_eq!(
        app.selected_finding()
            .as_ref()
            .map(|finding| &finding.fingerprint),
        Some(&needs_low_fingerprint)
    );
}

#[test]
fn canonical_projection_keeps_workflow_groups_as_metadata_only() {
    let needs_review = identity_finding("needs-review", Severity::Medium, 1, 1, "fi_needs_review");
    let confirmed = human_confirmed(
        identity_finding("confirmed", Severity::Low, 2, 2, "fi_confirmed"),
        0.91,
    );
    let deferred = identity_finding("deferred", Severity::Critical, 3, 3, "fi_deferred");
    let closed = human_rejected(identity_finding(
        "closed",
        Severity::High,
        4,
        4,
        "fi_closed",
    ));
    let deferred_decision = review_decision_record(&deferred, 10, ReviewDecisionVerdict::Deferred);
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![closed, confirmed, deferred, needs_review];
    app.set_review_decisions(vec![deferred_decision]);

    let projected = projected_visible_finding_pairs(&app);
    let rules = projected
        .iter()
        .map(|(_, finding)| finding.rule_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        rules,
        vec!["deferred", "needs-review", "confirmed", "closed"]
    );

    let groups = review_queue_model(&app, ReviewQueueMode::All)
        .rows
        .iter()
        .map(|row| row.workflow_group)
        .collect::<Vec<_>>();
    assert_eq!(
        groups,
        vec![
            ReviewWorkflowGroup::Deferred,
            ReviewWorkflowGroup::NeedsReview,
            ReviewWorkflowGroup::Confirmed,
            ReviewWorkflowGroup::Closed,
        ]
    );
}

#[test]
fn decision_group_change_preserves_confidence_order_and_cockpit_identity() {
    let mut selected =
        identity_finding("selected", Severity::Critical, 1, 1, "fi_selected_identity");
    selected.file_path = "src/auth/login.rs".to_string();
    selected.fingerprint = "selected-fingerprint".to_string();
    selected.dedup_key = Some("selected-key".to_string());
    let mut other = identity_finding("other", Severity::Low, 2, 2, "fi_other_identity");
    other.file_path = "src/misc/other.rs".to_string();
    other.fingerprint = "other-fingerprint".to_string();
    other.dedup_key = Some("other-key".to_string());

    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![selected.clone(), other.clone()];
    *app.selected_finding_mut() = Some(selected.clone());
    app.sync_findings_cursor_to_selected();
    assert_eq!(
        projected_visible_finding_pairs(&app)[0].1.fingerprint,
        selected.fingerprint
    );

    app.set_review_decisions(vec![review_decision_record(
        &selected,
        20,
        ReviewDecisionVerdict::Deferred,
    )]);
    app.sync_findings_cursor_to_selected();

    let projected = projected_visible_finding_pairs(&app);
    assert_eq!(projected[0].1.fingerprint, selected.fingerprint);
    assert_eq!(projected[1].1.fingerprint, other.fingerprint);
    assert_eq!(app.router.findings().cursor(), 0);
    assert_projected_identity_across_phase_models(&app, &selected, &projected[0].0);
    assert_projected_identity_across_actions(&mut app, &selected, &projected[0].0);
}

fn assert_projected_identity_across_phase_models(app: &ShellApp, selected: &Finding, alias: &str) {
    let review = review_queue_model(app, ReviewQueueMode::All);
    let selected_row = review.selected().unwrap();
    assert_eq!(selected_row.alias, alias);
    assert_eq!(selected_row.workflow_group, ReviewWorkflowGroup::Deferred);
    assert_eq!(
        current_finding_for_detail(app).unwrap().1.fingerprint,
        selected.fingerprint
    );

    let PhaseCockpitBody::Review(review) =
        phase_cockpit_model_for_phase(app, WorkflowPhase::Review).body
    else {
        panic!("expected Review cockpit");
    };
    assert_eq!(review.review.selected().unwrap().alias, alias);
    assert_eq!(
        review
            .finding
            .as_ref()
            .map(|finding| finding.fingerprint.as_str()),
        Some(selected.fingerprint.as_str())
    );

    let PhaseCockpitBody::Prove(prove) =
        phase_cockpit_model_for_phase(app, WorkflowPhase::Prove).body
    else {
        panic!("expected Prove cockpit");
    };
    assert_eq!(prove.finding.unwrap().fingerprint, selected.fingerprint);
}

fn assert_projected_identity_across_actions(app: &mut ShellApp, selected: &Finding, alias: &str) {
    prepare_prove_navigation(app);
    let verify = press_without_running_effects(app, KeyCode::Char('v'));
    assert!(verify.effects.is_empty());
    assert!(app.router.workbench().investigation_draft().is_some());
    let start = press_without_running_effects(app, KeyCode::Enter);
    assert!(start.effects.is_empty());
    assert!(app.input().starts_with("run verify:finding {"));
    assert!(app.input().contains(&selected.fingerprint));
    assert_eq!(app.input_mode(), InputMode::Prompt);

    app.set_input("");
    prepare_prove_navigation(app);
    press_without_running_effects(app, KeyCode::Char('x'));
    assert_eq!(app.input(), format!("suppress {alias} --reason "));
    prepare_prove_navigation(app);
    press_without_running_effects(app, KeyCode::Enter);
    assert_eq!(
        app.selected_finding().as_ref().unwrap().fingerprint,
        selected.fingerprint
    );

    let decision = app.reduce_review_decision_command(&ReviewDecisionCommand::Record {
        verdict: "confirmed".to_string(),
        reason: "runtime proof".to_string(),
    });
    let apply = decision.iter().find_map(|effect| match effect {
        ShellEffect::RecordReviewDecision(apply) => Some(apply),
        _ => None,
    });
    assert_eq!(apply.unwrap().finding.fingerprint, selected.fingerprint);

    app.engagement.set_pending_patch(PendingPatch {
        alias: alias.to_string(),
        patch_run_id: "patch-fixture".to_string(),
        status: kuzushi_core::PatchStatus::Sound,
        rationale: "parameterize query".to_string(),
        side_effect: None,
        diff: "- raw(query)\n+ bind(query)".to_string(),
        tests: Vec::new(),
        guardrail: None,
        staged_at: None,
    });
    let PhaseCockpitBody::Fix(fix) = phase_cockpit_model_for_phase(app, WorkflowPhase::Fix).body
    else {
        panic!("expected Fix cockpit");
    };
    assert_eq!(fix.finding.unwrap().fingerprint, selected.fingerprint);
    assert_eq!(fix.patch.unwrap().alias, alias);
}

fn prepare_prove_navigation(app: &mut ShellApp) {
    app.set_shell_view(crate::ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Prove));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ProveLadder);
    app.set_input_mode(InputMode::Navigate);
}

fn press_without_running_effects(app: &mut ShellApp, code: KeyCode) -> crate::app::UpdateResult {
    crate::app::update(
        app,
        Msg::Term(TermEvent::Key(KeyEvent::new(code, KeyModifiers::empty()))),
    )
}

fn press_workbench_key(app: &mut ShellApp, code: crossterm::event::KeyCode) {
    crate::app::update_and_execute_effects(
        app,
        crate::app::Msg::Term(crate::app::TermEvent::Key(crossterm::event::KeyEvent::new(
            code,
            crossterm::event::KeyModifiers::empty(),
        ))),
    );
}

#[test]
fn review_queue_keeps_confidence_then_severity_order_inside_a_group() {
    let mut likely_low = finding("likely-low", Severity::Low, 4);
    likely_low.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    let mut likely_high = finding("likely-high", Severity::High, 3);
    likely_high.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    let unverified_low = finding("unverified-low", Severity::Low, 2);
    let unverified_critical = finding("unverified-critical", Severity::Critical, 1);
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![unverified_low, likely_low, unverified_critical, likely_high];

    let model = review_queue_model(&app, ReviewQueueMode::All);
    let order = model
        .rows
        .iter()
        .map(|row| row.rule.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        order,
        vec![
            "likely-high",
            "likely-low",
            "unverified-critical",
            "unverified-low"
        ]
    );
    assert!(model
        .rows
        .iter()
        .all(|row| row.workflow_group == ReviewWorkflowGroup::NeedsReview));
}

#[test]
fn review_queue_model_applies_loaded_identity_review_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let reviewed = human_confirmed(
        identity_finding("semgrep/cwe-79", Severity::High, 12, 1, &identity_id),
        0.86,
    );
    let rerun = identity_finding(
        "semgrep/cwe-79-rerun",
        Severity::Medium,
        18,
        2,
        &identity_id,
    );
    assert!(rerun.triage.is_none());
    *app.findings_mut() = vec![reviewed, rerun];

    let all_model = review_queue_model(&app, ReviewQueueMode::All);
    assert_eq!(all_model.total_count, 2);
    assert_eq!(all_model.open_count, 0);
    assert_eq!(all_model.complete_count, 2);
    assert!(all_model.rows.iter().all(|row| row.decision == "confirmed"));
    assert!(all_model
        .rows
        .iter()
        .all(|row| row.decision_author == "human"));
    assert!(all_model
        .rows
        .iter()
        .all(|row| row.confidence_label == "86%"));

    let open_model = review_queue_model(&app, ReviewQueueMode::Open);
    assert_eq!(open_model.visible_count, 0);
    assert_eq!(
        open_model.empty_reason.as_deref(),
        Some("all visible findings have terminal decisions")
    );
}

#[test]
fn review_queue_model_applies_loaded_append_only_decisions() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let finding = identity_finding("semgrep/suppressed", Severity::High, 12, 1, &identity_id);
    assert!(finding.triage.is_none());
    *app.findings_mut() = vec![finding];
    app.set_review_decisions(vec![ReviewDecisionRecord {
        id: 3,
        finding_id: 1,
        identity_id: Some(identity_id),
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::Suppressed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "suppressed by approved review policy".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: None,
        created_at: "2026-07-02T00:00:00Z".to_string(),
        provenance: None,
    }]);

    let complete_model = review_queue_model(&app, ReviewQueueMode::Complete);
    assert_eq!(complete_model.visible_count, 1);
    assert_eq!(complete_model.open_count, 0);
    assert_eq!(complete_model.complete_count, 1);
    assert_eq!(complete_model.rows[0].decision, "suppressed");
    assert_eq!(complete_model.rows[0].decision_author, "human");
    assert_eq!(complete_model.rows[0].confidence_label, "100%");

    let open_model = review_queue_model(&app, ReviewQueueMode::Open);
    assert_eq!(open_model.visible_count, 0);
    assert_eq!(
        open_model.empty_reason.as_deref(),
        Some("all visible findings have terminal decisions")
    );
}

#[test]
fn review_queue_keeps_reappeared_rejected_identity_open() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let reviewed = human_rejected(identity_finding(
        "semgrep/cwe-79",
        Severity::Medium,
        12,
        1,
        &identity_id,
    ));
    let mut rerun = identity_finding("semgrep/cwe-79", Severity::High, 12, 2, &identity_id);
    rerun.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    *app.findings_mut() = vec![reviewed, rerun];

    let open_model = review_queue_model(&app, ReviewQueueMode::Open);

    assert_eq!(open_model.visible_count, 1);
    assert_eq!(open_model.open_count, 1);
    assert_eq!(open_model.complete_count, 0);
    assert_eq!(open_model.rows[0].decision, "rejected_false_positive");
    assert_eq!(open_model.rows[0].decision_author, "human");
    assert_eq!(
        open_model.rows[0].decision_conflict.as_deref(),
        Some("reappeared_after_rejection")
    );
    assert!(!open_model.rows[0].decision_complete);
}

#[test]
fn operator_calibration_counts_only_identified_evidence_outcomes() {
    let confirmed_identity = "fi_confirmed_0123456789abcdef";
    let rejected_identity = "fi_rejected_0123456789abcdef";
    let mut confirmed_finding = identity_finding(
        "semgrep/confirmed",
        Severity::High,
        12,
        10,
        confirmed_identity,
    );
    confirmed_finding.verification = Some(crate::test_support::test_empirical_verification(3));
    let mut rejected_rerun = identity_finding(
        "semgrep/rejected",
        Severity::High,
        18,
        20,
        rejected_identity,
    );
    rejected_rerun.verification = Some(crate::test_support::test_empirical_verification(3));
    let mut confirmed_decision =
        review_decision_record(&confirmed_finding, 100, ReviewDecisionVerdict::Confirmed);
    confirmed_decision.decision.actor = Some("operator".to_string());
    let mut rejected_decision = ReviewDecisionRecord {
        finding_id: 19,
        identity_id: Some(rejected_identity.to_string()),
        ..review_decision_record(
            &rejected_rerun,
            101,
            ReviewDecisionVerdict::RejectedFalsePositive,
        )
    };
    rejected_decision.decision.actor = Some("operator".to_string());

    let model = operator_calibration_model(
        &[confirmed_finding, rejected_rerun],
        &[confirmed_decision, rejected_decision],
    );

    assert_eq!(model.identified, 2);
    assert_eq!(model.runtime_supported, 1);
    assert_eq!(model.contradicted, 1);
    assert_eq!(model.needs_follow_up, 0);
    assert_eq!(
        model.label(false),
        "your evidence follow-up · 1 runtime-supported · 1 contradicted · 0 need follow-up"
    );
}

#[test]
fn operator_calibration_discloses_unattributed_legacy_decisions() {
    let finding = identity_finding(
        "semgrep/legacy",
        Severity::Medium,
        8,
        1,
        "fi_legacy_0123456789abcdef",
    );
    let decision = review_decision_record(&finding, 3, ReviewDecisionVerdict::Confirmed);

    let model = operator_calibration_model(&[finding], &[decision]);

    assert_eq!(model.identified, 0);
    assert!(model.unattributed_human_history);
    assert_eq!(model.label(true), "my decisions · identity unavailable");
}

fn identity_finding(
    rule: &str,
    severity: Severity,
    line: u32,
    id: i64,
    identity_id: &str,
) -> Finding {
    let mut finding = finding(rule, severity, line);
    finding.identity_id = Some(identity_id.to_string());
    finding.id = Some(id);
    finding.created_at = format!("2026-07-{id:02}T00:00:00Z");
    finding
}

fn review_decision_record(
    finding: &Finding,
    id: i64,
    verdict: ReviewDecisionVerdict,
) -> ReviewDecisionRecord {
    ReviewDecisionRecord {
        id,
        finding_id: finding.id.expect("persisted test finding"),
        identity_id: finding.identity_id.clone(),
        decision: ReviewDecision {
            verdict,
            author: TriageAuthor::Human,
            confidence: 0.88,
            rationale: "operator decision".to_string(),
            dismiss_reason: None,
            actor: None,
        },
        triage_verdict: None,
        created_at: "2026-07-10T00:00:00Z".to_string(),
        provenance: None,
    }
}

fn human_rejected(mut finding: Finding) -> Finding {
    finding.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::FalsePositive,
        confidence: 0.91,
        rationale: "operator rejected prior occurrence".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    finding.triaged_by = Some(TriageAuthor::Human);
    finding
}

#[test]
fn workflow_groups_map_every_review_decision_without_merging_opposites() {
    assert_eq!(
        workflow_group("needs_review", None),
        ReviewWorkflowGroup::NeedsReview
    );
    assert_eq!(
        workflow_group("confirmed", None),
        ReviewWorkflowGroup::Confirmed
    );
    assert_eq!(
        workflow_group("to_fix", None),
        ReviewWorkflowGroup::Confirmed
    );
    assert_eq!(
        workflow_group("accepted_risk", None),
        ReviewWorkflowGroup::Deferred
    );
    assert_eq!(
        workflow_group("deferred", None),
        ReviewWorkflowGroup::Deferred
    );
    assert_eq!(
        workflow_group("rejected_false_positive", None),
        ReviewWorkflowGroup::Closed
    );
    assert_eq!(
        workflow_group("suppressed", None),
        ReviewWorkflowGroup::Closed
    );
    assert_eq!(
        workflow_group("rejected_false_positive", Some("reappeared")),
        ReviewWorkflowGroup::NeedsReview
    );
}
