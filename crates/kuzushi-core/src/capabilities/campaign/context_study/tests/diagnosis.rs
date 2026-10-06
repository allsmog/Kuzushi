use super::*;

fn fixture() -> (tempfile::TempDir, ContextStudyReceipt) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    draft(
        &ModuleRegistry::with_v2_builtins(),
        &context(&workspace, &config),
        json!({}),
    )
    .unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    write_json_atomic(
        &campaign_queue_path(root.path(), "context-draft"),
        &json!({"jobs":{"context-001":{"state":"failed","attempts":1,"runId":"rejected-run"}}}),
    )
    .unwrap();
    crate::run_artifacts::write_run_artifact_json(
        root.path(),
        "rejected-run",
        "input.json",
        "tool input",
        &receipt.input,
    )
    .unwrap();
    (root, receipt)
}

fn publish(root: &Path, body: &str) {
    crate::run_artifacts::write_run_artifact_text(
        root,
        "rejected-run",
        "rejected-context-output.txt",
        "Labeled rejected output",
        "text",
        body,
    )
    .unwrap();
}

#[test]
fn retained_diagnosis_reads_exact_input_and_content_without_creating_context() {
    let (root, receipt) = fixture();
    assert_eq!(receipt.input["saveRejectedOutput"], true);
    assert!(!receipt.rejected_output_available(root.path()).unwrap());
    publish(root.path(), "Labeled initial and repair rejection");
    assert!(receipt.rejected_output_available(root.path()).unwrap());
    let output = receipt.rejected_output(root.path()).unwrap().unwrap();
    assert_eq!(output.run_id, "rejected-run");
    assert_eq!(output.model, MODEL);
    assert_eq!(output.source_identity, receipt.source_identity);
    assert!(output.text.contains("Labeled initial"));
    assert!(receipt.generated_context(root.path()).is_err());
    assert!(!root
        .path()
        .join(".kuzushi/threat-models/manifest.json")
        .exists());
}

#[test]
fn changed_output_foreign_inputs_or_oversized_evidence_are_refused() {
    for damage in ["content", "input", "oversize"] {
        let (root, receipt) = fixture();
        publish(root.path(), "Labeled original diagnostic");
        let path = root
            .path()
            .join(".kuzushi/v3/runs/rejected-run/rejected-context-output.txt");
        match damage {
            "content" => std::fs::write(path, "Replaced diagnostic").unwrap(),
            "oversize" => std::fs::write(path, "X".repeat(24 * 1024 + 2)).unwrap(),
            _ => {
                let mut foreign = receipt.input.clone();
                foreign["model"] = json!("other:model");
                crate::run_artifacts::write_run_artifact_json(
                    root.path(),
                    "rejected-run",
                    "input.json",
                    "tool input",
                    &foreign,
                )
                .unwrap();
            }
        }
        assert!(receipt.rejected_output(root.path()).is_err(), "{damage}");
    }
}

#[test]
fn historical_plans_without_explicit_retention_never_read_injected_output() {
    let (root, mut receipt) = fixture();
    publish(root.path(), "Labeled rejected diagnostic");
    receipt
        .input
        .as_object_mut()
        .unwrap()
        .remove("saveRejectedOutput");
    assert!(!receipt.rejected_output_available(root.path()).unwrap());
    assert!(receipt.rejected_output(root.path()).unwrap().is_none());
    receipt.input["saveRejectedOutput"] = json!(false);
    assert!(receipt.rejected_output(root.path()).unwrap().is_none());
}
