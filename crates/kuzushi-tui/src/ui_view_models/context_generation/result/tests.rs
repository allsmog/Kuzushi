use super::*;
use serde_json::json;

fn reference() -> kuzushi_core::ThreatModelRef {
    kuzushi_core::ThreatModelRef {
        model_id: kuzushi_core::ThreatModelId::new(),
        revision_id: kuzushi_core::ThreatModelRevisionId::new(),
        sha256: format!("sha256:{}", "a".repeat(64)),
    }
}

#[test]
fn unicode_preview_is_bounded_and_discloses_the_complete_read_route() {
    let preview = context_preview(GeneratedStudyContext {
        reference: reference(),
        document: json!({"title":"界".repeat(300),"systemContext":"界".repeat(9000),"provenance":{"treeHash":"saved-host-hash"}}),
    });
    assert_eq!(preview.title.chars().count(), 257);
    assert!(preview.title.ends_with('…'));
    let text = preview.lines.join("\n");
    assert!(text.chars().count() < PREVIEW_CHAR_LIMIT + 500);
    assert!(text.contains("Preview limited") && text.contains("complete saved revision"));
    assert!(text.contains("Saved source content: saved-host-hash"));
    assert!(text.contains("claims need human review"));
}

#[test]
fn mismatched_preview_cannot_replace_the_selected_result() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    let generation = StudyContextGeneration {
        generated: Some(reference()),
        generated_preview: Some(context_preview(GeneratedStudyContext {
            reference: reference(),
            document: json!({"title":"Other context must remain hidden"}),
        })),
        ..Default::default()
    };
    config.context_generation = Some(generation.clone());
    let text = overview(&config, &generation, 80).join(" ");
    assert!(text.contains("Preview unavailable"));
    assert!(!text.contains("Other context must remain hidden"));
    assert!(text.contains("another context is never substituted"));
}

#[test]
fn missing_result_reason_precedes_allowance_and_plan_metadata() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    let generation = StudyContextGeneration {
        result_error: Some("Owned immutable output is unavailable".into()),
        ..Default::default()
    };
    config.context_generation = Some(generation.clone());
    let lines = overview(&config, &generation, 80);
    assert!(lines
        .iter()
        .take(3)
        .any(|line| line.contains("Owned immutable output is unavailable")));
    assert!(!lines.iter().any(|line| line.contains("Plan digest:")));
    assert!(lines
        .join(" ")
        .contains("replacement draft needs separate approval"));
}
