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

#[test]
fn recorded_partial_grounding_survives_a_long_model_overview() {
    let preview = context_preview(GeneratedStudyContext {
        reference: reference(),
        document: json!({"title":"Owned context fixture","systemContext":"Labeled model text. ".repeat(900),
            "verification":{"verdict":"partial","groundingSource":"partial-catalog",
            "groundingDegraded":"Per-file inspection cap of 262144 bytes; unseen entry points remain unknown."}}),
    });
    assert_eq!(preview.lines[0], "Recorded grounding: partial.");
    assert!(preview.lines[1].contains("262144") && preview.lines[1].contains("unknown"));
    assert!(preview.lines.join("\n").contains("Preview limited"));
}

#[test]
fn partial_action_uses_recorded_checks_with_a_neutral_model_title() {
    let root = tempfile::tempdir().unwrap();
    let config = BatchScanConfig::load(root.path(), None);
    let reference = reference();
    let generation = StudyContextGeneration {
        generated: Some(reference.clone()),
        generated_preview: Some(context_preview(GeneratedStudyContext {
            reference,
            document: json!({"title":"Owned architecture","verification":{"verdict":"partial"}}),
        })),
        ..Default::default()
    };
    assert_eq!(
        overview(&config, &generation, 40)[0],
        "Inspect partial context"
    );
}
