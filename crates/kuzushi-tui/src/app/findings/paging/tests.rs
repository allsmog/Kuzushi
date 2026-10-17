use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use kuzushi_core::{OptionScope, OptionTarget, Severity, V2Config, WorkflowPhase};
use std::collections::BTreeSet;

pub(super) fn fixture() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("lib.rs"),
        "// Benign fixture; never executed.\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("fixture", workspace.root(), "completed")
        .unwrap();
    let rows = (0..6)
        .map(|index| {
            Finding::new_tool(
                "fixture",
                &format!("page.{index}"),
                "lib.rs",
                1,
                None,
                Severity::Low,
                &format!("Synthetic page candidate {index}"),
            )
        })
        .collect::<Vec<_>>();
    store.insert_findings("fixture", &rows).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".into()),
        "identityFold",
        serde_json::json!("legacy"),
    );
    app.refresh_findings_filtered("limit:2");
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.set_input_mode(InputMode::Navigate);
    (root, app)
}

pub(super) fn control(app: &mut ShellApp, key: char) {
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char(key), KeyModifiers::CONTROL));
    assert!(update.handled);
    EffectRuntime::execute(app, update.effects);
}

fn identities(app: &ShellApp) -> BTreeSet<String> {
    app.findings()
        .iter()
        .map(|finding| finding.fingerprint.clone())
        .collect()
}

#[test]
fn next_and_previous_reach_all_rows_without_relabeling() {
    let (_root, mut app) = fixture();
    let first = identities(&app);
    let aliases = app.finding_aliases().to_vec();
    let mut all = first.clone();
    control(&mut app, 'n');
    assert_eq!(app.domain().findings_page().unwrap().offset, 2);
    all.extend(identities(&app));
    control(&mut app, 'n');
    assert_eq!(app.domain().findings_page().unwrap().offset, 4);
    all.extend(identities(&app));
    assert_eq!(all.len(), 6);
    control(&mut app, 'p');
    control(&mut app, 'p');
    assert_eq!(identities(&app), first);
    assert_eq!(app.finding_aliases(), aliases.as_slice());
    assert_eq!(app.active_findings_filter().as_deref(), Some("limit:2"));
}

#[test]
fn typing_keeps_page_controls_out_of_the_composer() {
    let (_root, mut app) = fixture();
    app.set_input_mode(InputMode::Prompt);
    app.set_input("retained draft");
    control(&mut app, 'n');
    assert_eq!(app.domain().findings_page().unwrap().offset, 0);
    assert!(!app.input().is_empty());
}

#[test]
fn external_refresh_reanchors_the_current_page() {
    let (root, mut app) = fixture();
    control(&mut app, 'n');
    let selected = crate::ui_view_models::visible_finding_at_cursor(&app)
        .unwrap()
        .1;
    let store = FindingStore::open(
        WorkspaceTarget::new(root.path())
            .unwrap()
            .findings_db_path(),
    )
    .unwrap();
    store
        .insert_finding(
            "fixture",
            &Finding::new_tool(
                "fixture",
                "new-critical",
                "lib.rs",
                1,
                None,
                Severity::Critical,
                "Synthetic added row",
            ),
        )
        .unwrap();
    EffectRuntime::execute(
        &mut app,
        vec![ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: Some("limit:2".into()),
        })],
    );
    assert!(app
        .findings()
        .iter()
        .any(|finding| finding.id == selected.id));
    assert_eq!(
        crate::ui_view_models::visible_finding_at_cursor(&app)
            .unwrap()
            .1
            .id,
        selected.id
    );
}

#[test]
fn a_new_filter_returns_to_its_first_page() {
    let (_root, mut app) = fixture();
    control(&mut app, 'n');
    app.refresh_findings_filtered("limit:2 name:Synthetic");
    assert_eq!(app.domain().findings_page().unwrap().offset, 0);
}

#[test]
fn page_position_and_controls_remain_visible_at_tiny_width() {
    let (_root, mut app) = fixture();
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(40, 12)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    assert!(format!("{:?}", terminal.backend().buffer()).contains("Ctrl+N"));
    control(&mut app, 'n');
    control(&mut app, 'n');
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let text = format!("{:?}", terminal.backend().buffer());
    assert!(text.contains("5-6/6"), "{text}");
    assert!(text.contains("Ctrl+P"), "{text}");
}

#[test]
fn page_controls_remain_visible_at_ordinary_width() {
    let (_root, mut app) = fixture();
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 36)).unwrap();
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let text = format!("{:?}", terminal.backend().buffer());
    assert!(text.contains("Ctrl+N next page"), "{text}");
    control(&mut app, 'n');
    terminal
        .draw(|frame| crate::renderer::render_app(frame, &app))
        .unwrap();
    let text = format!("{:?}", terminal.backend().buffer());
    assert!(text.contains("Ctrl+N/P pages"), "{text}");
}

#[test]
fn opening_a_carried_global_alias_uses_its_row_on_later_pages() {
    let (_root, mut app) = fixture();
    control(&mut app, 'n');
    let alias = app.finding_aliases()[1].clone();
    let intended = app.findings()[1].id;
    let effects = app.open_finding_effects(&alias);
    EffectRuntime::execute(&mut app, effects);
    assert_eq!(app.selected_finding().as_ref().unwrap().id, intended);
}

#[test]
fn later_page_rail_and_detail_share_the_whole_ledger_alias() {
    let (_root, mut app) = fixture();
    control(&mut app, 'n');
    let (alias, finding) = crate::ui_view_models::visible_finding_at_cursor(&app).unwrap();
    let local_alias = kuzushi_core::stable_finding_alias(app.findings(), &finding.fingerprint);
    assert_ne!(local_alias.as_deref(), Some(alias.as_str()));
    let context = crate::ui_view_models::screen_context_model(&app);
    assert_eq!(
        context.selected_item.unwrap().alias.as_deref(),
        Some(alias.as_str())
    );
    for width in [160, 180] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, 48)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(
            text.contains(&format!("scope: {alias} · Review")),
            "{width}: {text}"
        );
        assert!(text.contains("Viewing Review · next required Map"));
    }
}

#[test]
fn previous_page_control_stays_visible_with_detail_focus() {
    let (_root, mut app) = fixture();
    control(&mut app, 'n');
    app.router
        .workbench_mut()
        .set_focus(crate::ui_view_models::PhaseSurfaceId::ReviewDetail);
    for width in [80, 96, 120] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, 24)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("Ctrl+N/P pages"), "{width}: {text}");
    }
}

#[test]
fn suppression_resolves_the_whole_ledger_alias_on_a_later_page() {
    let (root, mut app) = fixture();
    control(&mut app, 'n');
    let (alias, finding) = crate::ui_view_models::visible_finding_at_cursor(&app).unwrap();
    let effects = app.record_suppression_effect(SuppressionApply {
        target: app.target_owned(),
        reference: alias,
        reason: "Synthetic reviewed exception".into(),
        author: "operator".into(),
        days: 90,
    });
    EffectRuntime::execute(&mut app, effects);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let decision = store
        .latest_review_decision(finding.id.unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        decision.decision.verdict,
        kuzushi_core::findings::ReviewDecisionVerdict::Suppressed
    );
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 1);
}

#[test]
fn explicit_open_loads_the_later_page_before_showing_its_finding() {
    let (_root, mut app) = fixture();
    app.refresh_findings_filtered("limit:2");
    app.set_active_findings_filter(None);
    let effects = app.resolve_open_finding_effect(OpenFindingReference {
        reference: "F-0005".into(),
    });
    assert!(matches!(
        effects.first(),
        Some(ShellEffect::RefreshFindings(_))
    ));
    EffectRuntime::execute(&mut app, effects);
    let detail = crate::ui_view_models::selected_finding_detail_model(&app).unwrap();
    assert_eq!(detail.alias.as_deref(), Some("F-0005"));
    assert!(app.finding_aliases().iter().any(|alias| alias == "F-0005"));
    assert_eq!(
        app.selected_finding().as_ref().unwrap().fingerprint,
        detail.fingerprint
    );
}

fn filtered_pin(app: &mut ShellApp) -> (String, Finding) {
    let alias = app.finding_aliases()[0].clone();
    let finding = app.findings()[0].clone();
    let other = app.findings()[1].title.clone();
    app.refresh_findings_filtered(&format!("name:{other}"));
    let effects = app.open_finding_effects(&alias);
    EffectRuntime::execute(app, effects);
    (alias, finding)
}

pub(super) fn review_decision() -> ReviewDecision {
    ReviewDecision {
        verdict: ReviewDecisionVerdict::Confirmed,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "Synthetic external decision".into(),
        dismiss_reason: None,
        actor: Some("operator".into()),
    }
}

#[test]
fn filtered_pin_drives_both_the_detail_and_manual_action() {
    let (_root, mut app) = fixture();
    let (alias, finding) = filtered_pin(&mut app);
    let model = crate::ui_view_models::phase_cockpit_model_for_phase(&app, WorkflowPhase::Review);
    let detail = model.selected_finding_detail().unwrap();
    assert_eq!(detail.alias.as_deref(), Some(alias.as_str()));
    assert_eq!(detail.fingerprint, finding.fingerprint);
    let (reference, displayed) = crate::ui_view_models::current_finding_for_detail(&app).unwrap();
    assert_eq!(reference.as_deref(), Some(alias.as_str()));
    assert_eq!(displayed.id, finding.id);
}

#[test]
fn passive_refresh_recovers_a_removed_anchor_without_erasing_decisions() {
    let (root, mut app) = fixture();
    app.refresh_findings_filtered("completeness:open limit:2");
    let selected = crate::ui_view_models::visible_finding_at_cursor(&app)
        .unwrap()
        .1;
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .append_user_review_decision(selected.id.unwrap(), &review_decision())
        .unwrap();
    app.refresh_findings_preserving_active_filter(false);
    assert_eq!(app.findings_total_count(), 5);
    assert_eq!(app.domain().findings_page().unwrap().offset, 0);
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("left this query"));
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 1);
}

#[test]
fn explicit_missing_anchor_stays_an_error() {
    let (_root, mut app) = fixture();
    let before = identities(&app);
    app.runtime_state.requested_findings_page = Some(FindingPageRequest {
        anchor: Some("generation:99999".into()),
        ..Default::default()
    });
    app.refresh_findings_preserving_active_filter(false);
    assert_eq!(identities(&app), before);
    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.body.contains("left this query")),
        "notice={:?}; logs={:?}",
        app.advisory().notice,
        app.log_lines()
    );
}

#[test]
fn old_alias_is_withheld_but_the_pinned_read_watermark_is_retained() {
    let (root, mut app) = fixture();
    let (alias, finding) = filtered_pin(&mut app);
    let watermark = app.findings_read_watermark();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .append_user_review_decision(finding.id.unwrap(), &review_decision())
        .unwrap();
    app.refresh_findings_preserving_active_filter(false);
    assert!(app.selected_finding_reference(&finding).is_none());
    assert_eq!(
        app.router.findings().selected_read_watermark(&finding),
        watermark
    );
    assert_eq!(
        crate::ui_view_models::current_finding_for_detail(&app)
            .unwrap()
            .1
            .id,
        finding.id
    );
    let effect = app.current_finding_decision_effect(Some(alias), finding, review_decision());
    EffectRuntime::execute(&mut app, vec![effect]);
    assert_eq!(store.list_all_review_decisions().unwrap().len(), 1);
}

#[test]
fn list_navigation_releases_a_filtered_pin() {
    let (_root, mut app) = fixture();
    let (_, pinned) = filtered_pin(&mut app);
    app.router.findings_mut().step_direction(1, 1);
    assert!(!app.router.findings().selection_is_explicit());
    assert_ne!(
        crate::ui_view_models::current_finding_for_detail(&app)
            .unwrap()
            .1
            .id,
        pinned.id
    );
}

#[test]
fn explicit_pin_outside_a_component_keeps_the_displayed_identity() {
    let (_root, mut app) = fixture();
    let alias = app.finding_aliases()[0].clone();
    let finding = app.findings()[0].clone();
    app.set_active_scope(Some(TargetCandidateScope {
        id: "fixture-component".into(),
        kind: kuzushi_core::NestedProjectKind::Submodule,
        rel_path: "other".into(),
    }));
    let effects = app.open_finding_effects(&alias);
    EffectRuntime::execute(&mut app, effects);
    assert_eq!(
        crate::ui_view_models::active_workbench_page(&app),
        WorkbenchPage::Review
    );
    let detail = crate::ui_view_models::phase_cockpit_model_for_phase(
        &app,
        kuzushi_core::WorkflowPhase::Review,
    )
    .selected_finding_detail()
    .unwrap()
    .clone();
    assert_eq!(detail.fingerprint, finding.fingerprint);
    assert_eq!(detail.alias.as_deref(), Some(alias.as_str()));
}

#[test]
fn a_suppressed_pin_keeps_its_history_outside_the_query() {
    let (root, mut app) = fixture();
    let (_, finding) = filtered_pin(&mut app);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let decision = ReviewDecision {
        verdict: ReviewDecisionVerdict::Suppressed,
        rationale: "Synthetic suppressed pin".into(),
        ..review_decision()
    };
    store
        .append_user_review_decision(finding.id.unwrap(), &decision)
        .unwrap();
    app.refresh_findings_preserving_active_filter(false);
    let detail = crate::ui_view_models::selected_finding_detail_model(&app).unwrap();
    assert_eq!(detail.fingerprint, finding.fingerprint);
    assert_eq!(
        detail.current_decision.unwrap().rationale,
        "Synthetic suppressed pin"
    );
}
