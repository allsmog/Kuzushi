use super::*;
use crossterm::event::KeyModifiers;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::empty())
}

fn row(stable_fp: &str) -> ReviewRow {
    ReviewRow {
        stable_fp: stable_fp.to_string(),
        observation_hash: "obs3_demo".to_string(),
        snapshot_hash: "snap".to_string(),
        blob_hash: Some("blob".to_string()),
        byte_span: Some((1, 10)),
        display_path: "src/app.rs".to_string(),
        display_line: 12,
        code_snippet: Vec::new(),
        trace_hops: Vec::new(),
        attestations: Vec::new(),
        verdict: "unreviewed".to_string(),
        confidence: 50,
        justification: None,
        provenance_refs: Vec::new(),
        projection_seq: 7,
    }
}

#[test]
fn cursor_is_single_selection_source() {
    let mut state = WorkbenchReviewState::default();
    state.replace_frame(vec![row("fp3_a"), row("fp3_b")], 9, 1);

    state.route_key(key(KeyCode::Char('j')));

    assert_eq!(state.cursor, 1);
    assert_eq!(state.selected().unwrap().stable_fp, "fp3_b");
    assert_eq!(state.ledger_scroll.selected(), Some(1));
}

#[test]
fn triage_draft_commits_command_with_read_watermark() {
    let mut state = WorkbenchReviewState::default();
    state.replace_frame(vec![row("fp3_a")], 11, 1);

    state.route_key(key(KeyCode::Char('t')));
    state.route_key(key(KeyCode::Char('o')));
    state.route_key(key(KeyCode::Char('k')));
    let command = state.route_key(key(KeyCode::Enter)).unwrap();

    assert_eq!(
        command,
        ReviewCommand::DecideTriage {
            stable_fp: "fp3_a".to_string(),
            read_watermark: 11,
            justification: "ok".to_string(),
        }
    );
    assert_eq!(state.mode, ReviewMode::Browse);
}

#[test]
fn read_watermark_is_available_for_visible_or_drafted_row() {
    let mut state = WorkbenchReviewState::default();
    state.replace_frame(vec![row("fp3_a")], 11, 1);

    assert_eq!(state.read_watermark_for("fp3_a"), Some(11));
    assert_eq!(state.read_watermark_for("fp3_missing"), None);

    state.route_key(key(KeyCode::Char('t')));

    assert_eq!(state.read_watermark_for("fp3_a"), Some(11));
}

#[test]
fn draft_editor_is_utf8_safe() {
    let mut state = WorkbenchReviewState::default();
    state.replace_frame(vec![row("fp3_a")], 0, 0);
    state.route_key(key(KeyCode::Char('t')));
    state.route_key(key(KeyCode::Char('é')));
    state.route_key(key(KeyCode::Left));
    state.route_key(key(KeyCode::Delete));

    let ReviewMode::TriageDraft { buffer, cursor, .. } = &state.mode else {
        panic!("expected triage draft");
    };
    assert_eq!(buffer, "");
    assert_eq!(*cursor, 0);
}
