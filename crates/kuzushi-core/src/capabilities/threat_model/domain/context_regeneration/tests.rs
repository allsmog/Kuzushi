use super::*;

fn document() -> Value {
    json!({"systemContext":"Operator overview","dfd":{"nodes":[{"id":"component","name":"Component","description":"Operator description","purpose":"Original purpose"}],"flows":[],"trustBoundaries":[]},"openQuestions":[{"question":"Who owns input?","answer":"Operator answer"}],"provenance":{"revision":"recorded"},"userEdited":true})
}

#[test]
fn selected_text_changes_preserve_all_unselected_operator_text_and_evidence() {
    let original = document();
    let selected: Vec<String> = vec!["/dfd/nodes/0/purpose".into()];
    let response = ContextRegenerationResponse {
        schema_version: 1,
        edits: vec![ContextTextEdit {
            pointer: selected[0].clone(),
            text: "Proposed purpose".into(),
        }],
    };
    let revised = validate_regenerated_text(&original, &selected, &response).unwrap();
    assert_eq!(revised["systemContext"], original["systemContext"]);
    assert_eq!(
        revised["dfd"]["nodes"][0]["description"],
        original["dfd"]["nodes"][0]["description"]
    );
    assert_eq!(revised["openQuestions"], original["openQuestions"]);
    assert_eq!(revised["provenance"], original["provenance"]);
    assert_eq!(revised["dfd"]["nodes"][0]["purpose"], "Proposed purpose");
}

#[test]
fn missing_duplicate_extra_and_protected_edits_are_refused() {
    let original = document();
    let selected = vec!["/systemContext".into()];
    for edits in [
        vec![],
        vec![ContextTextEdit {
            pointer: "/provenance/revision".into(),
            text: "new".into(),
        }],
        vec![
            ContextTextEdit {
                pointer: "/systemContext".into(),
                text: "new".into()
            };
            2
        ],
        vec![
            ContextTextEdit {
                pointer: "/systemContext".into(),
                text: "new".into(),
            },
            ContextTextEdit {
                pointer: "/dfd/nodes/0/purpose".into(),
                text: "extra".into(),
            },
        ],
    ] {
        assert!(validate_regenerated_text(
            &original,
            &selected,
            &ContextRegenerationResponse {
                schema_version: 1,
                edits
            }
        )
        .is_err());
    }
    assert!(regeneration_fields(&original, &[]).is_err());
    assert!(regeneration_fields(&original, &vec!["/systemContext".into(); 9]).is_err());
    assert!(regeneration_fields(&original, &vec!["/systemContext".into(); 2]).is_err());
    assert!(regeneration_fields(&original, &["/verification/verdict".into()]).is_err());
}
