use super::*;
use kuzushi_core::session_transcript::{
    ContextDraftField, ContextDraftMode, ContextDraftRecord, ContextDraftSnapshot, DraftText,
};
use serde_json::json;

fn draft() -> ContextEditDraft {
    let reference = kuzushi_core::ThreatModelRef {
        model_id: Default::default(),
        revision_id: Default::default(),
        sha256: "a".repeat(64),
    };
    let mut draft = ContextEditDraft::new(
        reference,
        &json!({"systemContext":"Original context"}),
        "Original copy".into(),
    );
    draft.mode = ContextEditMode::Recovery;
    draft
}

fn saved(draft: &ContextEditDraft, content: bool) -> RecoveredContextDraft {
    let snapshot = content.then(|| ContextDraftSnapshot {
        name: DraftText {
            text: "Operator\ncopy 東京".into(),
            cursor: 0,
        },
        fields: vec![ContextDraftField {
            pointer: "/systemContext".into(),
            text: Some("Unfinished α\nsecond line 東京".into()),
            cursor: 2,
        }],
        selected_pointer: Some("/systemContext".into()),
        scroll: 0,
        mode: ContextDraftMode::Writing,
        origin_hashes: Vec::new(),
    });
    let record = ContextDraftRecord {
        version: 1,
        target: "/owned-context-fixture".into(),
        source: draft.reference.clone(),
        session_id: "session-owned-fixture".into(),
        saved_at_seconds: 1,
        snapshot,
        resolved_hashes: Vec::new(),
    };
    RecoveredContextDraft {
        record,
        record_hash: "b".repeat(64),
    }
}

#[test]
fn missing_snapshot_is_readable_and_keeps_the_original_draft() {
    let mut draft = draft();
    draft.recovery = ContextDraftRecovery::Choices {
        drafts: vec![saved(&draft, false)],
        cursor: 0,
    };
    let before = draft.clone();
    for width in [40, 60, 80, 96, 120, 160] {
        let lines = context_recovery_lines(&draft, width, 8);
        let text = lines.join(" ");
        assert!(text.contains("Saved draft unavailable"), "{text}");
        assert!(text.contains("Original checkpoint retained"), "{text}");
        assert!(lines
            .iter()
            .all(|line| unicode_width::UnicodeWidthStr::width(line.as_str()) <= width));
    }
    assert_eq!(draft, before);
}

#[test]
fn empty_or_outdated_selection_offers_an_exit_without_selecting_another_draft() {
    for count in [0, 1] {
        let mut draft = draft();
        let drafts = (0..count).map(|_| saved(&draft, true)).collect();
        draft.recovery = ContextDraftRecovery::Choices {
            drafts,
            cursor: usize::MAX,
        };
        let before = draft.clone();
        let text = context_recovery_lines(&draft, 40, 8).join(" ");
        assert!(text.contains("selection is unavailable"), "{text}");
        assert!(text.contains("Start a new draft or return."), "{text}");
        assert!(!text.contains("Unfinished"), "{text}");
        assert_eq!(draft, before);
    }
}

#[test]
fn valid_recovery_keeps_multiline_preview_and_cursor_without_terminal_controls() {
    let mut draft = draft();
    draft.recovery = ContextDraftRecovery::Choices {
        drafts: vec![saved(&draft, true)],
        cursor: 0,
    };
    let before = draft.clone();
    let lines = context_recovery_lines(&draft, 80, 8);
    let text = lines.join(" ");
    assert!(text.contains("Operator copy 東京"), "{text}");
    assert!(text.contains("cursor 2"), "{text}");
    assert!(text.contains("Unfinished α second line 東京"), "{text}");
    assert!(lines.iter().all(|line| !line.chars().any(char::is_control)));
    assert_eq!(draft, before);
}
