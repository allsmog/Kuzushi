use super::tests::{control, fixture, review_decision};
use super::*;

fn replace_cursored_generation(root: &std::path::Path, app: &ShellApp) -> (Finding, Finding) {
    let before = crate::ui_view_models::visible_finding_at_cursor(app)
        .unwrap()
        .1;
    let workspace = WorkspaceTarget::new(root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    std::fs::write(
        root.join("lib.rs"),
        "// Owned new source revision, never executed.\n",
    )
    .unwrap();
    store
        .record_run_started("replacement", workspace.root(), "completed")
        .unwrap();
    store.insert_finding("replacement", &before).unwrap();
    let after = store
        .get_finding_by_fingerprint(&before.fingerprint)
        .unwrap()
        .unwrap();
    assert_ne!(before.id, after.id);
    (before, after)
}

#[test]
fn passive_generation_replacement_keeps_the_page_cursor_draft_and_scroll() {
    let (root, mut app) = fixture();
    control(&mut app, 'n');
    app.router.findings_mut().set_cursor(1);
    let (before, after) = replace_cursored_generation(root.path(), &app);
    app.set_input_mode(InputMode::Prompt);
    app.set_input("retained investigation draft");
    app.router
        .workbench_mut()
        .scroll_mut()
        .set(crate::ui_view_models::PhaseSurfaceId::ReviewDetail, 5);
    let mode = app.input_mode();
    app.refresh_findings_preserving_active_filter(false);
    assert_eq!(app.domain().findings_page().unwrap().offset, 2);
    let current = crate::ui_view_models::visible_finding_at_cursor(&app)
        .unwrap()
        .1;
    assert_eq!(current.id, after.id);
    assert_eq!(current.identity_id, before.identity_id);
    assert_eq!(app.input(), "retained investigation draft");
    assert_eq!(app.input_mode(), mode);
    assert_eq!(
        app.router
            .workbench()
            .scroll()
            .get(crate::ui_view_models::PhaseSurfaceId::ReviewDetail),
        5
    );
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .is_none_or(|notice| !notice.message.contains("left this query")));
}

#[test]
fn historical_selection_is_not_rebound_when_the_same_finding_is_observed_again() {
    let (root, mut app) = fixture();
    control(&mut app, 'n');
    app.open_finding_at_cursor();
    let pinned = app.selected_finding().as_ref().unwrap().clone();
    let watermark = app.router.findings().selected_read_watermark(&pinned);
    assert!(watermark.is_some());
    replace_cursored_generation(root.path(), &app);
    app.refresh_findings_preserving_active_filter(false);
    let selected = app.selected_finding().as_ref().unwrap();
    assert_eq!(selected.id, pinned.id);
    assert_eq!(
        app.router.findings().selected_read_watermark(selected),
        watermark
    );
    assert_eq!(
        crate::ui_view_models::current_finding_for_detail(&app)
            .unwrap()
            .1
            .id,
        pinned.id
    );
    assert!(
        crate::ui_view_models::selected_finding_out_of_window_notice(&app)
            .unwrap()
            .contains("pinned")
    );
    assert!(app.selected_finding_reference(selected).is_none());
    assert_current_observation_recovery(&app);
}

#[test]
fn explicit_generation_open_does_not_require_a_folded_page_anchor() {
    let (root, mut app) = fixture();
    app.set_active_findings_filter(None);
    app.refresh_findings_preserving_active_filter(false);
    let before = crate::ui_view_models::visible_finding_at_cursor(&app)
        .unwrap()
        .1;
    replace_cursored_generation(root.path(), &app);
    app.refresh_findings_preserving_active_filter(false);
    let offset = app.domain().findings_page().unwrap().offset;
    let reference = format!("generation:{}", before.id.unwrap());
    let effects = app.resolve_open_finding_effect(OpenFindingReference {
        reference: reference.clone(),
    });
    assert!(
        !effects
            .iter()
            .any(|effect| matches!(effect, ShellEffect::RefreshFindings(_))),
        "An exact generation is a pinned reader, not a canonical-page query"
    );
    EffectRuntime::execute(&mut app, effects);
    assert_eq!(app.selected_finding().as_ref().unwrap().id, before.id);
    assert_eq!(
        crate::ui_view_models::current_finding_for_detail(&app)
            .unwrap()
            .1
            .id,
        before.id
    );
    assert_eq!(app.domain().findings_page().unwrap().offset, offset);
    assert_eq!(
        app.selected_finding_reference(app.selected_finding().as_ref().unwrap()),
        Some(reference)
    );
}

fn assert_current_observation_recovery(app: &ShellApp) {
    let crate::ui_view_models::PhaseCockpitBody::Review(review) =
        crate::ui_view_models::phase_cockpit_model_for_phase(
            app,
            kuzushi_core::WorkflowPhase::Review,
        )
        .body
    else {
        panic!("Review expected");
    };
    let disclosure = review.selection_disclosure.unwrap();
    let current_alias = crate::ui_view_models::visible_finding_at_cursor(app)
        .unwrap()
        .0;
    assert_eq!(disclosure.reveal_command, format!("open {current_alias}"));
    assert_eq!(disclosure.reveal_label, "inspect current");
    assert!(disclosure.filter.is_none());
    assert!(disclosure.message.contains("earlier observation"));
}

#[test]
fn resize_preserves_review_detail_draft_scroll_and_list_return() {
    use crate::ui_view_models::PhaseSurfaceId::{ReviewDetail, ReviewQueue};
    let (_root, mut app) = fixture();
    control(&mut app, 'n');
    app.set_viewport(crate::TerminalViewport::new(120, 36));
    app.open_finding_at_cursor();
    app.router.workbench_mut().scroll_mut().set(ReviewDetail, 5);
    app.set_input("retained resize draft");
    let cursor = app.router.findings().cursor();
    for (width, height) in [(60, 20), (40, 12), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.set_viewport(crate::TerminalViewport::new(width, height));
        let plan = crate::renderer::workbench_phase_plan_for_app(
            &app,
            ratatui::layout::Rect::new(0, 0, width, height),
        )
        .unwrap();
        assert!(plan.surface(ReviewDetail).is_some(), "{width}x{height}");
        assert_eq!(plan.effective_focus, ReviewDetail);
        assert!(app.router.workbench().zoom().surface().is_none());
        assert_eq!(app.router.workbench().scroll().get(ReviewDetail), 5);
        assert_eq!(app.input(), "retained resize draft");
        assert_eq!(app.router.findings().cursor(), cursor);
    }
    app.set_input("");
    let back = app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('q'),
        crossterm::event::KeyModifiers::NONE,
    ));
    assert!(back.handled);
    assert_eq!(
        app.router.workbench().focus_for(WorkbenchPage::Review),
        ReviewQueue
    );
    assert_eq!(app.domain().findings_page().unwrap().offset, 2);
}

#[test]
fn historical_recovery_does_not_offer_a_related_variant_or_ambiguous_observation() {
    let (_root, mut app) = fixture();
    app.open_finding_at_cursor();
    let pinned = app.selected_finding().as_ref().unwrap().clone();
    let mut replacement = pinned.clone();
    replacement.id = Some(pinned.id.unwrap() + 100);
    let mut variant = replacement.clone();
    variant.fingerprint = "related-variant".into();
    let mut other_generation = replacement.clone();
    other_generation.id = Some(replacement.id.unwrap() + 1);
    for rows in [vec![variant], vec![replacement, other_generation]] {
        *app.findings_mut() = rows;
        let crate::ui_view_models::PhaseCockpitBody::Review(review) =
            crate::ui_view_models::phase_cockpit_model_for_phase(
                &app,
                kuzushi_core::WorkflowPhase::Review,
            )
            .body
        else {
            panic!("Review expected");
        };
        let disclosure = review.selection_disclosure.unwrap();
        assert_eq!(disclosure.reveal_command, "findings");
        assert_eq!(disclosure.reveal_label, "reveal");
        assert!(disclosure.filter.is_some());
    }
}

#[test]
fn reused_alias_cannot_move_an_old_decision_to_the_new_generation() {
    let (root, mut app) = fixture();
    control(&mut app, 'n');
    app.open_finding_at_cursor();
    let pinned = app.selected_finding().as_ref().unwrap().clone();
    let alias = app.selected_finding_reference(&pinned).unwrap();
    let before_id = pinned.id.unwrap();
    let before_watermark = app.router.findings().selected_read_watermark(&pinned);
    let (_, replacement) = replace_cursored_generation(root.path(), &app);
    app.refresh_findings_preserving_active_filter(false);
    let effect = app.current_finding_decision_effect(Some(alias), pinned, review_decision());
    let ShellEffect::RecordReviewDecision(apply) = &effect else {
        panic!("manual decision expected");
    };
    assert_eq!(apply.finding.id, Some(before_id));
    assert_eq!(apply.read_watermark, before_watermark);
    EffectRuntime::execute(&mut app, vec![effect]);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert!(store.list_all_review_decisions().unwrap().is_empty());
    app.open_finding_at_cursor();
    let current = crate::ui_view_models::current_finding_for_detail(&app).unwrap();
    assert_eq!(current.1.id, replacement.id);
    let effect = app.current_finding_decision_effect(current.0, current.1, review_decision());
    EffectRuntime::execute(&mut app, vec![effect]);
    let records = store.list_all_review_decisions().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].finding_id, replacement.id.unwrap());
}

fn native_fixture_findings() -> Vec<Finding> {
    (0..800)
        .map(|index| {
            Finding::new_tool(
                "fixture",
                &format!("continuity.{index:04}"),
                "lib.rs",
                1,
                None,
                kuzushi_core::Severity::Low,
                &format!("Synthetic continuity candidate {index:04}"),
            )
        })
        .collect::<Vec<_>>()
}

#[test]
#[ignore = "explicit native fixture preparation only"]
fn prepare_native_continuity_fixture() {
    let root = std::path::PathBuf::from(std::env::var("KUZUSHI_CONTINUITY_FIXTURE_OUT").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    for name in ["app.py", "config.env"] {
        let _ = std::fs::remove_file(root.join(name));
    }
    std::fs::write(
        root.join("lib.rs"),
        "// Owned initial source; never executed.\n",
    )
    .unwrap();
    std::fs::write(root.join("README.md"), "Synthetic findings and review decision for page-continuity testing. No model, scanner or source execution.\n").unwrap();
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("continuity-base", workspace.root(), "completed")
        .unwrap();
    let rows = native_fixture_findings();
    store.insert_findings("continuity-base", &rows).unwrap();
    let stored = store.list_all_findings().unwrap();
    let ordered = kuzushi_core::sorted_finding_aliases(&stored);
    let (alias, target) = &ordered[600];
    store
        .append_user_review_decision(target.id.unwrap(), &review_decision())
        .unwrap();
    let receipt = serde_json::json!({"findingCount":800,"beforeId":target.id,"fingerprint":target.fingerprint,
        "identityId":target.identity_id,"alias":alias,"title":target.title,"findingsAreSynthetic":true,
        "providerRequests":0,"scannerJobs":0,"sourceExecuted":false});
    std::fs::write(
        root.join("continuity-fixture.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}

#[test]
#[ignore = "explicit owned external writer only"]
fn write_native_continuity_replacement() {
    let root = std::path::PathBuf::from(std::env::var("KUZUSHI_CONTINUITY_FIXTURE_OUT").unwrap());
    let path = root.join("continuity-fixture.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = store
        .get_finding_by_fingerprint(receipt["fingerprint"].as_str().unwrap())
        .unwrap()
        .unwrap();
    std::fs::write(
        root.join("lib.rs"),
        "// Owned later source; never executed.\n",
    )
    .unwrap();
    store
        .record_run_started("continuity-later", workspace.root(), "completed")
        .unwrap();
    store.insert_finding("continuity-later", &finding).unwrap();
    let replacement = store
        .get_finding_by_fingerprint(&finding.fingerprint)
        .unwrap()
        .unwrap();
    assert_ne!(replacement.id, finding.id);
    assert_eq!(replacement.identity_id, finding.identity_id);
    receipt["afterId"] = serde_json::json!(replacement.id);
    std::fs::write(path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
}
