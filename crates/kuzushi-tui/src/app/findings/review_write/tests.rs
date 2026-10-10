use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use kuzushi_core::{Severity, V2Config};
use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

#[derive(Debug, Default)]
struct ControlledWriter {
    started: (Mutex<bool>, Condvar),
    released: (Mutex<bool>, Condvar),
}

impl ControlledWriter {
    fn wait_started(&self) {
        let (started, _) = self
            .started
            .1
            .wait_timeout_while(
                self.started.0.lock().unwrap(),
                Duration::from_secs(5),
                |started| !*started,
            )
            .unwrap();
        assert!(*started);
    }

    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}

impl ReviewDecisionWriter for ControlledWriter {
    fn write(&self, apply: &ReviewDecisionApply) -> ReviewWriteResult {
        *self.started.0.lock().unwrap() = true;
        self.started.1.notify_all();
        let (_guard, timeout) = self
            .released
            .1
            .wait_timeout_while(
                self.released.0.lock().unwrap(),
                Duration::from_secs(5),
                |released| !*released,
            )
            .unwrap();
        assert!(!timeout.timed_out(), "test releases the writer");
        LedgerReviewDecisionWriter.write(apply)
    }
}

fn fixture() -> (tempfile::TempDir, ShellApp, Arc<ControlledWriter>) {
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
    store
        .insert_finding(
            "fixture",
            &Finding::new_tool(
                "fixture",
                "review-write",
                "lib.rs",
                1,
                None,
                Severity::Low,
                "Synthetic review candidate",
            ),
        )
        .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.refresh_findings_effect(FindingsRefresh {
        announce: false,
        filter: None,
    });
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    let (_, wake) = TerminalLoopInbox::channel_for_test();
    app.set_loop_wake(Some(wake));
    let writer = Arc::new(ControlledWriter::default());
    app.runtime_state.review_write.writer = writer.clone();
    (root, app, writer)
}

fn request(app: &ShellApp) -> ReviewDecisionApply {
    let (alias, finding) = crate::ui_view_models::current_finding_for_detail(app).unwrap();
    let effect = app.current_finding_decision_effect(
        alias,
        finding,
        ReviewDecision {
            verdict: ReviewDecisionVerdict::Deferred,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "Synthetic operator decision".into(),
            dismiss_reason: None,
            actor: Some("operator".into()),
        },
    );
    let ShellEffect::RecordReviewDecision(apply) = effect else {
        panic!("decision effect")
    };
    apply
}

fn decisions(root: &Path) -> Vec<kuzushi_core::findings::ReviewDecisionRecord> {
    FindingStore::open(WorkspaceTarget::new(root).unwrap().findings_db_path())
        .unwrap()
        .list_all_review_decisions()
        .unwrap()
}

fn settle(app: &mut ShellApp, writer: &ControlledWriter) {
    writer.release();
    wait_for_result(app);
}

fn wait_for_result(app: &mut ShellApp) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.review_decision_write_pending() && Instant::now() < deadline {
        app.apply_review_decision_write_result();
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!app.review_decision_write_pending());
}

#[test]
fn pending_save_keeps_typing_and_verdict_truth_separate() {
    let (root, mut app, writer) = fixture();
    let started = Instant::now();
    let apply = request(&app);
    app.record_review_decision_effect(apply);
    assert!(started.elapsed() < Duration::from_millis(100));
    writer.wait_started();
    app.set_input_mode(InputMode::Prompt);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    EffectRuntime::execute(&mut app, update.effects);
    assert_eq!(app.input(), "x");
    assert!(decisions(root.path()).is_empty());
    assert_eq!(app.router.workbench().review().session_decided, 0);
    assert!(crate::ui_view_models::review_queue_model(
        &app,
        crate::ui_view_models::ReviewQueueMode::All
    )
    .population_title()
    .contains("saving F-0001"));
    settle(&mut app, &writer);
    assert_eq!(decisions(root.path()).len(), 1);
    assert_eq!(app.input(), "x");
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().review().session_decided, 1);
}

#[test]
fn pending_save_refuses_duplicate_submission_and_shell_exit() {
    let (root, mut app, writer) = fixture();
    app.record_review_decision_effect(request(&app));
    writer.wait_started();
    app.record_review_decision_effect(request(&app));
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("not queued"));
    EffectRuntime::execute(&mut app, vec![ShellEffect::Quit]);
    assert!(!app.should_quit());
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("save result"));
    settle(&mut app, &writer);
    assert_eq!(decisions(root.path()).len(), 1);
    app.finish_shell_quit_effect();
    assert!(app.should_quit());
}

#[test]
fn target_switch_does_not_redirect_the_captured_decision_or_its_result() {
    let (root, mut app, writer) = fixture();
    app.record_review_decision_effect(request(&app));
    writer.wait_started();
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().to_path_buf()));
    app.set_shell_view(ShellView::Help);
    app.set_input("retained other-target draft");
    settle(&mut app, &writer);
    assert_eq!(decisions(root.path()).len(), 1);
    assert!(decisions(other.path()).is_empty());
    assert_eq!(app.shell_view(), ShellView::Help);
    assert_eq!(app.input(), "retained other-target draft");
    assert_eq!(app.router.workbench().review().session_decided, 0);
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains(&root.path().display().to_string()));
}

#[test]
fn a_newer_human_decision_rejects_the_stale_pending_write() {
    let (root, mut app, writer) = fixture();
    let apply = request(&app);
    app.record_review_decision_effect(apply.clone());
    writer.wait_started();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut newer = apply.decision.clone();
    newer.rationale = "Newer synthetic operator decision".into();
    newer.verdict = ReviewDecisionVerdict::Confirmed;
    kuzushi_core::workspace::record_user_review_decision_for_finding(
        &workspace,
        &apply.finding,
        &newer,
    )
    .unwrap();
    settle(&mut app, &writer);
    assert_eq!(decisions(root.path()).len(), 1);
    assert_eq!(app.router.workbench().review().session_decided, 0);
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("changed after read watermark"));
}

#[test]
fn pending_identity_and_previous_verdict_fit_all_viewports() {
    let (_root, mut app, writer) = fixture();
    app.set_success_notice("review", "A deliberately long previous synthetic save receipt that must stay in history without crowding out a new pending save.");
    app.record_review_decision_effect(request(&app));
    writer.wait_started();
    for (width, height) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("saving F-0001"), "{width}: {text}");
        assert!(text.contains("F-0001"), "{width}: {text}");
    }
    settle(&mut app, &writer);
}

#[derive(Debug)]
struct FailedWriter;

impl ReviewDecisionWriter for FailedWriter {
    fn write(&self, _apply: &ReviewDecisionApply) -> ReviewWriteResult {
        Err(ReviewWriteFailure::Commit(anyhow::anyhow!(
            "Synthetic store unavailable"
        )))
    }
}

#[test]
fn failed_write_preserves_the_later_draft_and_reports_the_actual_error() {
    let (root, mut app, _writer) = fixture();
    app.runtime_state.review_write.writer = Arc::new(FailedWriter);
    app.record_review_decision_effect(request(&app));
    app.set_input_mode(InputMode::Prompt);
    let update = app.reduce_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
    EffectRuntime::execute(&mut app, update.effects);
    wait_for_result(&mut app);
    assert_eq!(app.input(), "x");
    assert!(decisions(root.path()).is_empty());
    assert_eq!(app.router.workbench().review().session_decided, 0);
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("Synthetic store unavailable"));
    assert_eq!(app.shell_view(), ShellView::Workbench);
}

#[derive(Debug)]
struct PanickedWriter;

impl ReviewDecisionWriter for PanickedWriter {
    fn write(&self, _apply: &ReviewDecisionApply) -> ReviewWriteResult {
        panic!("Synthetic worker failure")
    }
}

#[test]
fn a_worker_without_a_receipt_is_not_retried_or_counted_as_saved() {
    let (root, mut app, _writer) = fixture();
    app.runtime_state.review_write.writer = Arc::new(PanickedWriter);
    app.record_review_decision_effect(request(&app));
    wait_for_result(&mut app);
    assert!(decisions(root.path()).is_empty());
    assert_eq!(app.router.workbench().review().session_decided, 0);
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("without a receipt"));
    app.runtime_state.review_write.writer = Arc::new(LedgerReviewDecisionWriter);
    app.record_review_decision_effect(request(&app));
    wait_for_result(&mut app);
    assert_eq!(decisions(root.path()).len(), 1);
}

#[test]
fn newer_observation_rejects_the_captured_old_source_decision() {
    let (root, mut app, writer) = fixture();
    let apply = request(&app);
    app.record_review_decision_effect(apply.clone());
    writer.wait_started();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("newer", workspace.root(), "completed")
        .unwrap();
    let mut finding = apply.finding;
    finding.title = "Newer synthetic observation".into();
    store.insert_finding("newer", &finding).unwrap();
    settle(&mut app, &writer);
    assert!(decisions(root.path()).is_empty());
    assert_eq!(app.router.workbench().review().session_decided, 0);
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("changed after read watermark"));
}
