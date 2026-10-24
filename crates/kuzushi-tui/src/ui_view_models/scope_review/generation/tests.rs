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
