use super::*;
use serde_json::json;

fn document() -> Value {
    json!({"systemContext":"Original overview","dfd":{"nodes":[{"id":"reader","name":"Reader","purpose":"Read input","codeEvidence":[{"file":"lib.rs","line":1}]}]},"openQuestions":[{"id":"q1","question":"Who owns the input?"}],"provenance":{"sourceRevision":"old"},"verification":{"verdict":"pass"}})
}

#[test]
fn text_edits_preserve_evidence_and_unselected_fields() {
    let original = document();
    let edits = vec![
        ContextTextEdit {
            pointer: "/systemContext".into(),
            text: "Operator overview\nSecond line".into(),
        },
        ContextTextEdit {
            pointer: "/openQuestions/0/answer".into(),
            text: "Application owner".into(),
        },
    ];
    let revised = apply_context_text_edits(&original, &edits).unwrap();
    assert_eq!(revised["dfd"], original["dfd"]);
    assert_eq!(revised["provenance"], original["provenance"]);
    assert_eq!(revised["systemContext"], "Operator overview\nSecond line");
    assert_eq!(revised["openQuestions"][0]["answer"], "Application owner");
}

#[test]
fn protected_unknown_duplicate_and_oversized_edits_are_rejected() {
    for pointer in [
        "/verification/verdict",
        "/provenance/sourceRevision",
        "/dfd/nodes/0/id",
        "/openQuestions/9/answer",
    ] {
        assert!(apply_context_text_edits(
            &document(),
            &[ContextTextEdit {
                pointer: pointer.into(),
                text: "changed".into()
            }]
        )
        .is_err());
    }
    let edit = ContextTextEdit {
        pointer: "/systemContext".into(),
        text: "changed".into(),
    };
    assert!(apply_context_text_edits(&document(), &[edit.clone(), edit]).is_err());
    assert!(apply_context_text_edits(
        &document(),
        &[ContextTextEdit {
            pointer: "/systemContext".into(),
            text: "x".repeat(MAX_CONTEXT_EDIT_BYTES + 1)
        }]
    )
    .is_err());
}

#[test]
fn empty_optional_text_is_removed_and_no_change_is_refused() {
    let edit = ContextTextEdit {
        pointer: "/systemContext".into(),
        text: String::new(),
    };
    assert!(apply_context_text_edits(&document(), &[edit])
        .unwrap()
        .get("systemContext")
        .is_none());
    let unchanged = ContextTextEdit {
        pointer: "/systemContext".into(),
        text: "Original overview".into(),
    };
    assert!(apply_context_text_edits(&document(), &[unchanged]).is_err());
    assert!(serde_json::from_value::<ContextTextEdit>(
        json!({"pointer":"/systemContext","text":"text","extra":true})
    )
    .is_err());
}

#[test]
fn answering_a_legacy_question_preserves_its_text_and_other_rows() {
    let original = json!({"openQuestions":["Who owns input?",{"question":"Other question"}]});
    let revised = apply_context_text_edits(
        &original,
        &[ContextTextEdit {
            pointer: "/openQuestions/0/answer".into(),
            text: "The application owner".into(),
        }],
    )
    .unwrap();
    assert_eq!(
        revised["openQuestions"][0],
        json!({"question":"Who owns input?","answer":"The application owner"})
    );
    assert_eq!(revised["openQuestions"][1], original["openQuestions"][1]);
}

#[test]
fn text_comparison_includes_removal_and_added_answers_without_metadata_diffs() {
    let original = document();
    let revised = apply_context_text_edits(
        &original,
        &[
            ContextTextEdit {
                pointer: "/systemContext".into(),
                text: String::new(),
            },
            ContextTextEdit {
                pointer: "/openQuestions/0/answer".into(),
                text: "Owner α\nSecond line".into(),
            },
        ],
    )
    .unwrap();
    let changes = context_text_differences(&original, &revised);
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].pointer, "/systemContext");
    assert_eq!(changes[0].before, "Original overview");
    assert_eq!(changes[0].after, "");
    assert_eq!(changes[1].pointer, "/openQuestions/0/answer");
    assert_eq!(changes[1].before, "");
    assert_eq!(changes[1].after, "Owner α\nSecond line");
    assert!(context_text_differences(&original, &original).is_empty());
}

#[test]
fn reordered_component_and_question_ids_do_not_forge_text_changes() {
    let before = json!({"dfd":{"nodes":[{"id":"a","purpose":"Read"},{"id":"b","purpose":"Record"}]},"openQuestions":[{"id":"q1","question":"Owner?","answer":"Team"},{"id":"q2","question":"Scope?","answer":"Local"}]});
    let after = json!({"dfd":{"nodes":[{"id":"b","purpose":"Record"},{"id":"a","purpose":"Read"}]},"openQuestions":[{"id":"q2","question":"Scope?","answer":"Local"},{"id":"q1","question":"Owner?","answer":"Team"}]});
    assert!(context_text_differences(&before, &after).is_empty());
}

#[test]
fn removed_component_text_and_question_answers_are_retained_as_removals() {
    let before = json!({"dfd":{"nodes":[{"id":"reader","purpose":"Read input"}]},"openQuestions":[{"question":"Owner?","answer":"Team"}]});
    let after = json!({"dfd":{"nodes":[]},"openQuestions":[]});
    let changes = context_text_differences(&before, &after);
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].before, "Read input");
    assert_eq!(changes[1].before, "Team");
    assert!(changes.iter().all(|change| change.after.is_empty()));
}

#[test]
fn exact_question_text_matches_legacy_and_reordered_answers() {
    let before = json!({"openQuestions":["Owner?",{"question":"Scope?","answer":"Local"}]});
    let after = json!({"openQuestions":[{"question":"Scope?","answer":"Local"},{"question":"Owner?","answer":"Team"}]});
    let changes = context_text_differences(&before, &after);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].pointer, "/openQuestions/1/answer");
    assert_eq!(changes[0].after, "Team");
}

#[test]
fn ambiguous_component_ids_compare_by_position_without_dropping_rows() {
    let before = json!({"dfd":{"nodes":[{"id":"duplicate","description":"Alpha"},{"id":"duplicate","description":"Beta"}]}});
    let after = json!({"dfd":{"nodes":[{"id":"duplicate","description":"New Alpha"},{"id":"duplicate","description":"Beta"}]}});
    let changes = context_text_differences(&before, &after);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].pointer, "/dfd/nodes/0/description");
    assert_eq!(changes[0].before, "Alpha");
    assert_eq!(changes[0].after, "New Alpha");
}
