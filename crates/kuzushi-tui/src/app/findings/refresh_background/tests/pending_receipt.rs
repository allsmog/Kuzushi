use super::*;

fn park_current_read(app: &mut ShellApp) -> FindingsReadRequest {
    app.defer_findings_refresh(
        FindingsRefresh {
            announce: false,
            filter: None,
        },
        vec![ShellEffect::OpenFinding(OpenFindingReference {
            reference: "F-0001".into(),
        })],
    );
    let request = app
        .runtime_state
        .findings_refresh
        .pending
        .as_ref()
        .unwrap()
        .request
        .clone();
    let target = app.target_owned().unwrap();
    app.finish_findings_refresh(&target, &request, Err(FindingsReadFailure::ReceiptPending));
    request
}

#[test]
fn typed_pending_survives_context_but_error_wording_never_changes_its_class() {
    let error =
        anyhow::Error::new(kuzushi_core::findings::BatchReceiptPending).context("owned attempt");
    assert!(matches!(
        FindingsReadFailure::from(error),
        FindingsReadFailure::ReceiptPending
    ));
    assert!(matches!(
        FindingsReadFailure::from(anyhow::anyhow!(
            "Study attempt receipt is pending publication"
        )),
        FindingsReadFailure::Failed(_)
    ));
}

#[test]
fn pending_receipt_preserves_projection_draft_and_origin_without_polling_or_navigation() {
    let (_root, mut app) = fixture();
    app.set_input("Unsubmitted operator draft");
    let messages = app
        .findings()
        .iter()
        .map(|f| f.message.clone())
        .collect::<Vec<_>>();
    let origin = app.shell_view();
    let request = park_current_read(&mut app);
    assert_eq!(app.shell_view(), origin);
    assert_eq!(app.input(), "Unsubmitted operator draft");
    assert_eq!(
        app.findings()
            .iter()
            .map(|f| f.message.clone())
            .collect::<Vec<_>>(),
        messages
    );
    let feedback = app.findings_read_feedback().unwrap();
    assert_eq!(feedback.population_title(), "FINDINGS · receipts pending");
    assert!(feedback
        .recovery_lines()
        .contains(&"Retry: findings refresh"));
    assert!(app.advisory().notice.is_none());
    for _ in 0..50 {
        assert!(!app.schedule_pending_findings_refresh());
    }
    let pending = app.runtime_state.findings_refresh.pending.as_ref().unwrap();
    assert_eq!(pending.request, request);
    assert_eq!(pending.continuation.len(), 1);
    assert!(!pending.scheduled);
}

#[test]
fn a_later_refresh_resumes_the_read_but_keeps_later_operator_focus() {
    let (root, mut app) = fixture();
    park_current_read(&mut app);
    app.set_input("Retained retry draft");
    app.set_shell_view(ShellView::Report);
    app.ui_mut().record_operator_interaction(Instant::now());
    app.defer_findings_refresh(
        FindingsRefresh {
            announce: false,
            filter: None,
        },
        vec![],
    );
    let request = app
        .runtime_state
        .findings_refresh
        .pending
        .as_ref()
        .unwrap()
        .request
        .clone();
    let snapshot = read_findings_projection(root.path(), &request).unwrap();
    let target = app.target_owned().unwrap();
    app.finish_findings_refresh(&target, &request, Ok(snapshot));
    assert_eq!(app.shell_view(), ShellView::Report);
    assert!(app.findings_read_feedback().is_none());
    assert!(app.runtime_state.findings_refresh.pending.is_none());
    assert_eq!(app.input(), "Retained retry draft");
    assert_eq!(receipt_recovery_notes(&app), 1);
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.starts_with("Work receipts pending")));
    let snapshot = read_findings_projection(root.path(), &request).unwrap();
    app.apply_findings_read_snapshot(snapshot, &request, false);
    assert_eq!(receipt_recovery_notes(&app), 1);
}

fn receipt_recovery_notes(app: &ShellApp) -> usize {
    app.log_lines()
        .iter()
        .filter(|line| line.body == "Findings refreshed; receipt wait cleared")
        .count()
}

#[test]
fn synchronous_recovery_reports_the_refreshed_projection_once() {
    let (root, mut app) = fixture();
    app.log_refresh_findings_error(kuzushi_core::findings::BatchReceiptPending.into(), true);
    let request = app.findings_read_request(0, root.path().to_path_buf(), None);
    let snapshot = read_findings_projection(root.path(), &request).unwrap();
    app.apply_findings_read_snapshot(snapshot, &request, false);
    assert_eq!(receipt_recovery_notes(&app), 1);
    assert!(app.findings_read_feedback().is_none());
    assert!(app.advisory().notice.is_none());
}

#[test]
fn a_refreshed_projection_keeps_its_assessment_warning_visible() {
    let (root, mut app) = fixture();
    app.log_refresh_findings_error(kuzushi_core::findings::BatchReceiptPending.into(), true);
    let request = app.findings_read_request(0, root.path().to_path_buf(), None);
    let mut snapshot = read_findings_projection(root.path(), &request).unwrap();
    snapshot.page_recovery_notice = Some("Owned assessment remains unavailable".into());
    app.apply_findings_read_snapshot(snapshot, &request, false);
    assert_eq!(receipt_recovery_notes(&app), 1);
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("Owned assessment remains unavailable"));
}

#[test]
fn another_targets_projection_cannot_claim_receipt_recovery() {
    let (_root, mut app) = fixture();
    park_current_read(&mut app);
    let (other, _) = fixture();
    app.set_target(Some(other.path().to_path_buf()));
    let request = app.findings_read_request(0, other.path().to_path_buf(), None);
    let snapshot = read_findings_projection(other.path(), &request).unwrap();
    app.apply_findings_read_snapshot(snapshot, &request, false);
    assert_eq!(receipt_recovery_notes(&app), 0);
    assert!(app.findings_read_feedback().is_none());
}

#[test]
fn a_real_failure_after_waiting_is_visible_and_does_not_keep_waiting_status() {
    let (_root, mut app) = fixture();
    park_current_read(&mut app);
    let request = app
        .runtime_state
        .findings_refresh
        .pending
        .as_ref()
        .unwrap()
        .request
        .clone();
    let target = app.target_owned().unwrap();
    app.finish_findings_refresh(&target, &request, Err("Malformed owned receipt".into()));
    assert_eq!(
        app.findings_read_feedback().unwrap().population_title(),
        "FINDINGS · read failed"
    );
    assert!(app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("Malformed owned receipt"));
    assert_eq!(receipt_recovery_notes(&app), 0);
    let snapshot = read_findings_projection(&target, &request).unwrap();
    app.apply_findings_read_snapshot(snapshot, &request, false);
    assert_eq!(receipt_recovery_notes(&app), 0);
}

#[test]
fn synchronous_pending_is_visible_and_does_not_follow_a_different_target() {
    let (_root, mut app) = fixture();
    app.log_refresh_findings_error(kuzushi_core::findings::BatchReceiptPending.into(), true);
    assert_eq!(
        app.findings_read_feedback().unwrap().population_title(),
        "FINDINGS · receipts pending"
    );
    assert!(app.advisory().notice.is_none());
    let other = tempfile::tempdir().unwrap();
    app.set_target(Some(other.path().to_path_buf()));
    assert!(app.findings_read_feedback().is_none());
}
