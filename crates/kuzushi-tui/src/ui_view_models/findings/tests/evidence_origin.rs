use super::*;

#[test]
fn imported_assertions_do_not_claim_model_authorship_or_runtime_verification() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.rs"), "// Owned inert evidence.\n").unwrap();
    let payload = root.path().join("observations.jsonl");
    std::fs::write(
        &payload,
        serde_json::json!({"file":"owned.rs","line":1,"severity":"info",
            "title":"Labeled imported assertion","class":"owned-note"})
        .to_string(),
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    kuzushi_core::findings::import::import_ledger_jsonl(&workspace, &payload, "owned-import")
        .unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    let before = serde_json::to_value(&findings).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_findings(findings);
    app.set_shell_view(crate::app::ShellView::Workbench);
    app.set_workbench_page(crate::app::WorkbenchPage::Review);

    let detail = selected_finding_detail_model(&app).unwrap();
    let assertion = detail
        .evidence
        .iter()
        .find(|row| row.header.starts_with("reasoning ·"))
        .unwrap();
    assert_eq!(assertion.origin, "reasoning assertion");
    assert!(assertion
        .rationale
        .contains("Imported from external findings ledger"));
    assert_eq!(detail.runtime_label, "not verified");
    assert_eq!(detail.decision, "needs_review");
    for width in [40, 120] {
        let plain = crate::renderer::render_plain_app(&app, width);
        assert!(plain.contains("reasoning assertion"), "{width}: {plain}");
        assert!(
            !plain.contains("model-generated reasoning"),
            "{width}: {plain}"
        );
    }
    assert_eq!(
        serde_json::to_value(store.list_findings(10).unwrap()).unwrap(),
        before
    );
}

#[test]
fn legacy_reasoning_remains_an_assertion_even_with_source_or_capture_fields() {
    let evidence = FindingEvidence {
        kind: " ReAsOnInG ".into(),
        file_path: "owned.rs".into(),
        line: 1,
        snippet: "Claimed source text".into(),
        request_blob: Some("owned-request".into()),
        confidence: 0,
        ..Default::default()
    };
    let row = FindingEvidenceRow::from_evidence(&evidence);
    assert_eq!(row.origin, "reasoning assertion");
    assert!(row.header.contains("conf 0"));
    assert!(!evidence.has_unscored_confidence());
    assert!(evidence.is_model_generated_reasoning());
}

#[test]
fn explicit_model_claims_and_observed_evidence_keep_their_existing_labels() {
    for (kind, path, request, expected) in [
        (
            FindingEvidence::UNSCORED_MODEL_CLAIM,
            "owned.rs",
            None,
            "model-generated reasoning",
        ),
        (
            "request",
            "owned.rs",
            Some("owned-request"),
            "observed capture evidence",
        ),
        ("code", "owned.rs", None, "observed code evidence"),
        ("note", "", None, "observed evidence"),
    ] {
        let evidence = FindingEvidence {
            kind: kind.into(),
            file_path: path.into(),
            request_blob: request.map(str::to_string),
            ..Default::default()
        };
        assert_eq!(
            FindingEvidenceRow::from_evidence(&evidence).origin,
            expected
        );
    }
}
