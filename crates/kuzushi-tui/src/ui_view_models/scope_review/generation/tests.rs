use super::*;

fn generation(limitations: Vec<String>) -> ScanScopeGeneration {
    ScanScopeGeneration {
        schema_version: 1,
        model: "openai-codex:gpt-5.5".into(),
        run_id: "recorded-run".into(),
        prompt_sha256: "prompt-hash".into(),
        draft_sha256: "draft-hash".into(),
        context_ref: None,
        input_bytes: 4096,
        supplied_files: 4,
        inventoried_files: 8,
        limitations,
    }
}

#[test]
fn compact_summary_keeps_recorded_input_counts_and_first_limitation() {
    let value = generation(vec![
        "Context sections: 0/1; omitted 1.".into(),
        "Detailed recorded limitation".into(),
    ]);
    let summary = generation_summary(Some(&value)).join("\n");
    assert!(summary.contains("4096 bytes; 4/8 files"));
    assert!(summary.contains("Context sections: 0/1; omitted 1."));
    assert!(!summary.contains("recorded-run"));
}

#[test]
fn legacy_limitations_are_displayed_without_inventing_context_counts() {
    let value = generation(vec!["Historical inventory was partial".into()]);
    let summary = generation_summary(Some(&value)).join("\n");
    assert!(summary.contains("Historical inventory was partial"));
    assert!(!summary.contains("Context sections:"));
    assert!(generation_summary(None).is_empty());
}

#[test]
fn proposal_summary_names_its_saved_context_without_claiming_map_acceptance() {
    let mut value = generation(Vec::new());
    value.context_ref = Some(
        serde_json::from_value(serde_json::json!({
            "modelId":"owned-model", "revisionId":"owned-revision", "sha256":"owned-hash"
        }))
        .unwrap(),
    );
    let summary = generation_summary(Some(&value)).join("\n");
    assert!(summary.contains("Proposal context: saved revision owned-revision"));
    assert!(!summary.contains("accepted"));
    assert!(!summary.contains("active"));
}

#[test]
fn legacy_proposal_does_not_claim_context_was_omitted() {
    let summary = generation_summary(Some(&generation(Vec::new()))).join("\n");
    assert!(summary.contains("Proposal context reference: not recorded"));
    assert!(!summary.contains("omitted"));
}

#[test]
fn proposal_detail_preserves_the_full_reference_for_a_later_reader() {
    let mut value = generation(Vec::new());
    value.context_ref = Some(
        serde_json::from_value(serde_json::json!({
            "modelId":"owned-model", "revisionId":"owned-revision", "sha256":"owned-hash"
        }))
        .unwrap(),
    );
    let detail = proposal_context_detail(&value).join("\n");
    assert!(detail.contains("saved revision owned-revision"));
    assert!(detail.contains("Proposal context model: owned-model"));
    assert!(detail.contains("Proposal context SHA-256: owned-hash"));
    assert!(detail.contains("Map acceptance and scan context are reviewed separately"));
    assert_eq!(proposal_context_detail(&generation(Vec::new())).len(), 1);
}
