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
