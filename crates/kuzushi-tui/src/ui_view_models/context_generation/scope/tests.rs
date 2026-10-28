use super::*;

#[test]
fn explicit_saved_context_does_not_claim_map_acceptance() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    let reference = serde_json::json!({"modelId":"inactive-manual", "revisionId":"saved-one",
        "sha256":format!("sha256:{}", "a".repeat(64))});
    config.context_generation = Some(StudyContextGeneration {
        generation_tool: Some("pack:suggest-scopes".into()),
        context_input: serde_json::json!({"threatModelRef":reference}),
        ..Default::default()
    });
    for width in [40, 60, 80, 96, 120, 160] {
        let text = summary(&config, width).join(" ");
        assert!(text.contains("exact saved revision"), "{width}: {text}");
        assert!(!text.contains("accepted Map"), "{width}: {text}");
    }
}

#[test]
fn frozen_scope_receipt_names_explicit_effort_without_inventing_a_default() {
    let mut receipt: kuzushi_core::capabilities::campaign::ContextStudyReceipt =
        serde_json::from_value(serde_json::json!({"generationTool":"pack:suggest-scopes",
            "campaignId":"scope-fixture", "investigationId":"scope-fixture",
            "planSha256":"sha256:owned", "sourceIdentity":"tree:owned", "configSha256":"sha256:owned",
            "model":"openai-codex:gpt-6-luna", "input":{"thinkingLevel":"low","maxOutputTokens":4096}})).unwrap();
    let text = super::super::receipts::receipt_lines(&receipt).join("\n");
    assert!(text.contains("reasoning: low"));
    receipt
        .input
        .as_object_mut()
        .unwrap()
        .remove("thinkingLevel");
    let text = super::super::receipts::receipt_lines(&receipt).join("\n");
    assert!(text.contains("reasoning: recorded runtime setting"));
    assert!(!text.contains("reasoning: medium"));
}

#[test]
fn failed_scope_cause_precedes_planning_terms_at_every_required_width() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    config.context_generation = Some(StudyContextGeneration {
        generation_tool: Some("pack:suggest-scopes".into()),
        result_error: Some("Scope proposal rejected: unknown shared dependency greeting".into()),
        ..Default::default()
    });
    for width in [40, 60, 80, 96, 120, 160] {
        let lines = summary(&config, width);
        let text = lines.join(" ");
        assert!(text.find("greeting").unwrap() < text.find("One scope proposal job").unwrap());
        assert!(
            lines
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("Scope proposal rejected"),
            "{width}: {lines:?}"
        );
        assert!(
            text.contains("separate approval") && text.contains("No automatic repair or rerun")
        );
        assert!(!text.contains("Enter reviews the fixed plan"), "{text}");
    }
}

#[test]
fn absent_scope_form_has_no_work_or_planning_copy() {
    let root = tempfile::tempdir().unwrap();
    let config = BatchScanConfig::load(root.path(), None);
    assert!(summary(&config, 80).is_empty());
}

#[test]
fn filename_selection_distinguishes_new_defaults_from_unchanged_legacy_receipts() {
    let absent = serde_json::json!({});
    assert!(file_selection_line(&absent, false).contains("root files first"));
    assert!(file_selection_line(&absent, true).contains("recorded filename prefix"));
    let balanced = serde_json::json!({"fileSelection":"root-balanced-v1"});
    assert!(file_selection_line(&balanced, true).contains("root files first"));
    let explicit = serde_json::json!({"fileSelection":"prefix-v1"});
    assert!(file_selection_line(&explicit, false).contains("recorded filename prefix"));
    for invalid in [serde_json::Value::Null, serde_json::json!("unknown")] {
        let input = serde_json::json!({"fileSelection":invalid});
        assert!(file_selection_line(&input, true).contains("unsupported saved option"));
    }
}

#[test]
fn the_frozen_scope_policy_is_shown_once_in_each_viewport() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    let receipt = serde_json::from_value(serde_json::json!({
        "generationTool":"pack:suggest-scopes", "campaignId":"owned",
        "investigationId":"owned", "planSha256":"sha256:owned", "sourceIdentity":"tree:owned",
        "configSha256":"sha256:owned", "model":"openai-codex:gpt-6-luna",
        "input":{"fileSelection":"root-balanced-v1","maxOutputTokens":4096}}))
    .unwrap();
    config.context_generation = Some(StudyContextGeneration {
        generation_tool: Some("pack:suggest-scopes".into()),
        receipt: Some(receipt),
        ..Default::default()
    });
    for width in [40, 60, 80, 96, 120, 160] {
        let text = summary(&config, width).join(" ");
        assert_eq!(text.matches("Filename sample:").count(), 1, "{text}");
        assert!(text.contains("root files first"));
    }
}
