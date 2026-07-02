use super::*;
use kuzushi_core::workspace::ROOT_SCOPE_ID;
use kuzushi_core::{
    Finding, FindingEvidence, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, RunSummary, RunTargetGitMetadata, Severity, StaticProofState,
    TriageOutcome, TriageVerdict, V2Config, WorkspaceTarget,
};
use std::collections::BTreeMap;

#[test]
fn findings_model_projects_counts_rows_and_selection() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut high = Finding::new_semgrep(
        "demo.sql",
        "src/search.ts",
        12,
        Some(14),
        Severity::High,
        "SQL injection\nEvidence: query reaches db.query\nCWE: CWE-89",
    );
    high.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "source and sink are linked".to_string(),
        cost_usd: 0.0,
    });
    let medium = Finding::new_tool(
        "codeql",
        "js/path-injection",
        "src/files.ts",
        22,
        None,
        Severity::Medium,
        "Path traversal candidate",
    );
    app.selected_finding = Some(high.clone());
    app.findings = vec![high, medium];

    let model = findings_model(&app);

    assert_eq!(model.total, 2);
    assert_eq!(model.triaged, 1);
    assert_eq!(model.pending, 1);
    assert_eq!(model.counts.high, 1);
    assert_eq!(model.counts.medium, 1);
    assert_eq!(model.header, "FINDINGS · 2 · 1H · 1M");
    assert_eq!(model.rows[0].alias, "F-0001");
    assert_eq!(model.rows[0].severity_label, "HIGH");
    assert_eq!(model.rows[0].location, "src/search.ts:12-14");
    assert_eq!(model.rows[0].run_label, "run:unknown");
    assert_eq!(model.rows[0].revision_label, "rev:unknown");
    assert_eq!(model.rows[0].verdict, "tp");
    assert_eq!(model.rows[0].confidence, "91%");
    assert_eq!(model.rows[0].proof_label, "triaged-tp");
    assert_eq!(model.rows[0].proof_marker, "◇");
    assert_eq!(model.rows[0].proof_tier, ProofTier::Confirmed);
    assert_eq!(model.rows[0].source, "semgrep:demo.sql");
    assert!(model.rows[0].selected);
    assert_eq!(model.rows[1].proof_label, "unverified");
    assert_eq!(model.rows[1].proof_marker, "?");
    assert_eq!(model.rows[1].proof_tier, ProofTier::Suspected);
    assert_eq!(model.preview.header, "FINDINGS · 1 triaged · 1 pending");
    assert_eq!(model.preview.rows.len(), 2);
    assert!(model.preview.overflow.is_none());
}

#[test]
fn findings_model_filters_rows_to_active_component_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let scope = kuzushi_core::NestedProjectScope {
        id: "package-web-app".to_string(),
        parent: Some(ROOT_SCOPE_ID.to_string()),
        kind: kuzushi_core::NestedProjectKind::PackageRoot,
        rel_path: "web/app".to_string(),
        inherited_sections: Vec::new(),
    };
    let tree = kuzushi_core::NestedProjectScopeTree {
        schema_version: 1,
        root: ROOT_SCOPE_ID.to_string(),
        scopes: vec![
            kuzushi_core::NestedProjectScope {
                id: ROOT_SCOPE_ID.to_string(),
                parent: None,
                kind: kuzushi_core::NestedProjectKind::Root,
                rel_path: ".".to_string(),
                inherited_sections: Vec::new(),
            },
            scope.clone(),
        ],
    };
    kuzushi_core::save_nested_project_scopes(workspace.root(), &tree).unwrap();

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.active_scope = Some(crate::app::TargetCandidateScope {
        id: scope.id,
        kind: scope.kind,
        rel_path: scope.rel_path,
    });
    app.findings = vec![
        Finding::new_semgrep(
            "demo.web",
            "web/app/src/main.ts",
            12,
            None,
            Severity::High,
            "web finding",
        ),
        Finding::new_semgrep(
            "demo.cli",
            "cmd/proxy/main.go",
            8,
            None,
            Severity::Medium,
            "cli finding",
        ),
    ];

    let model = findings_model(&app);

    assert_eq!(model.total, 1);
    assert_eq!(model.header, "FINDINGS · 1 · component:web/app · 1H");
    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].location, "web/app/src/main.ts:12");
    assert_eq!(visible_findings_len(&app), 1);
}

#[test]
fn finding_proof_label_prioritizes_runtime_and_static_evidence() {
    let mut verified = Finding::new_tool(
        "verify",
        "demo.rule",
        "src/lib.rs",
        7,
        None,
        Severity::High,
        "runtime verified",
    );
    verified.verification = Some(PersistedVerification {
        proof_level: 4,
        proof_verdict: PersistedProofVerdict::Exploited,
        backend: PersistedSandboxBackend::Plain,
        language: None,
        harness_path: None,
        crash_evidence: None,
        duration_ms: 12,
        cost_usd: 0.0,
        notes: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
    });
    assert_eq!(finding_proof_label(&verified), "verified L4");
    assert_eq!(
        finding_proof_badge(&verified).tier,
        ProofTier::RuntimeVerified
    );

    let linked = Finding::new_tool(
        "static",
        "demo.rule",
        "src/lib.rs",
        7,
        None,
        Severity::High,
        "linked",
    )
    .with_static_proof_state(StaticProofState::SourceSinkLinked);
    assert_eq!(finding_proof_label(&linked), "path-linked");
    assert_eq!(finding_proof_badge(&linked).tier, ProofTier::StaticLinked);

    let mut rejected = linked.clone();
    rejected.static_proof_state = Some(StaticProofState::StaticallyRejected);
    assert_eq!(finding_proof_label(&rejected), "static-no");
    assert_eq!(finding_proof_badge(&rejected).tier, ProofTier::Rejected);
}

#[test]
fn finding_run_provenance_uses_run_summary_target_revision() {
    let mut finding = Finding::new_tool(
        "demo",
        "demo.rule",
        "src/lib.rs",
        7,
        None,
        Severity::Medium,
        "finding with run provenance",
    );
    finding.scan_id = Some("scan-run-provenance-123456".to_string());
    let summary = RunSummary::running(
        "scan-run-provenance-123456",
        "scan",
        Some("sast:scan".to_string()),
        ".",
    )
    .with_target_git(Some(RunTargetGitMetadata {
        sha: "abcdef1234567890".to_string(),
        branch: Some("main".to_string()),
        dirty: true,
    }));
    let runs = BTreeMap::from([(summary.run_id.clone(), summary)]);

    let provenance = finding_run_provenance(&finding, &runs);

    assert_eq!(provenance.run_label, "run:scan-r..3456");
    assert_eq!(provenance.revision_label, "rev:abcdef1*");
}

#[test]
fn findings_model_describes_context_prereq_when_empty() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = findings_model(&app);

    assert_eq!(model.total, 0);
    assert!(model.rows.is_empty());
    assert_eq!(
        model.empty.context_cta,
        Some((
            "context build",
            "optional: index the repo first for richer analysis."
        ))
    );
}

#[test]
fn findings_model_surfaces_malformed_context_prereq_when_empty() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.context_view.status = "malformed context snapshot. Next: context build".to_string();

    let model = findings_model(&app);

    assert_eq!(
        model.empty.hint,
        "context snapshot is malformed; rebuild it before scanning."
    );
    assert_eq!(
        model.empty.context_cta,
        Some(("context build", "rewrite the malformed snapshot first"))
    );
}

#[test]
fn clean_scan_empty_state_describes_latest_zero_finding_scan() {
    let mut clean = RunSummary::running(
        "scan-clean-123456",
        "scan",
        Some("sast:scan".to_string()),
        ".",
    )
    .with_findings(Some(0))
    .complete();
    clean.started_at_unix = 900;
    clean.completed_at_unix = Some(940);
    let runs = BTreeMap::from([(clean.run_id.clone(), clean)]);

    let state = clean_scan_empty_state(
        &runs,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000),
    )
    .expect("zero-finding completed scan should render as clean");

    assert_eq!(
        state.summary,
        "scanned ~1 min ago · 0 findings · run:scan-c..3456"
    );
}

#[test]
fn findings_model_caps_module_preview_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.findings = (0..10)
        .map(|index| {
            Finding::new_tool(
                "semgrep",
                &format!("rule-{index}"),
                &format!("src/file_{index}.rs"),
                index + 1,
                None,
                Severity::Low,
                "preview finding",
            )
        })
        .collect();

    let model = findings_model(&app);

    assert_eq!(model.preview.header, "FINDINGS · 0 triaged · 10 pending");
    assert_eq!(model.preview.rows.len(), 8);
    assert_eq!(
        model.preview.overflow,
        Some(FindingsPreviewOverflow {
            label: "… 2 more · ".to_string(),
            command: "/findings",
            suffix: " to drill in",
        })
    );
}

#[test]
fn selected_finding_detail_model_bounds_evidence_and_message() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let finding = Finding::new_semgrep(
        "demo.rule",
        "src/app.ts",
        8,
        Some(8),
        Severity::High,
        "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9",
    )
    .with_evidence(
        (0..10)
            .map(|index| FindingEvidence {
                kind: "filesystem_sink".to_string(),
                file_path: "src/app.ts".to_string(),
                line: 8 + index,
                snippet: "file.save(filepath)".to_string(),
                rationale: "Raw upload path reaches a filesystem write".to_string(),
                confidence: 92,
                request_blob: (index == 0).then(|| "RAW REQUEST".to_string()),
                response_blob: (index == 0).then(|| "RAW RESPONSE".to_string()),
                ..Default::default()
            })
            .collect(),
    );
    app.findings = vec![finding.clone()];
    app.selected_finding = Some(finding);

    let model = selected_finding_detail_model(&app).expect("selected finding");

    assert_eq!(model.alias.as_deref(), Some("F-0001"));
    assert_eq!(model.severity_label, "high");
    assert_eq!(model.location, "src/app.ts:8");
    assert_eq!(
        model.evidence[0].header,
        "filesystem_sink · conf 92 · src/app.ts:8"
    );
    assert_eq!(
        model.evidence[0].capture.as_deref(),
        Some("http capture: request body recorded, response body recorded")
    );
    assert_eq!(model.message_lines.len(), 8);
    assert_eq!(model.message_overflow, 1);
    assert_eq!(model.evidence.len(), 8);
    assert_eq!(model.evidence_overflow, 2);
    assert_eq!(model.static_proof_label, "signal-only");
    assert_eq!(model.runtime_label, "not verified");
    assert_eq!(model.next_action_label, "validate");
    assert_eq!(model.next_command.as_deref(), Some("verify F-0001"));
    assert!(model.remediation_hint.is_none());
}

#[test]
fn selected_finding_detail_uses_same_proof_badge_as_list() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut finding = Finding::new_semgrep(
        "demo.sql",
        "src/search.ts",
        12,
        Some(14),
        Severity::High,
        "SQL injection",
    )
    .with_static_proof_state(StaticProofState::SignalOnly);
    finding.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "source and sink are linked".to_string(),
        cost_usd: 0.0,
    });
    app.findings = vec![finding];

    let list = findings_model(&app);
    let detail = selected_finding_detail_model(&app).expect("selected finding");

    assert_eq!(list.rows[0].proof_label, "triaged-tp");
    assert_eq!(detail.proof_label, list.rows[0].proof_label);
    assert_eq!(detail.proof_marker, list.rows[0].proof_marker);
    assert_eq!(detail.proof_tier, list.rows[0].proof_tier);
    assert!(detail.proof_state.contains("signal_only"));
    assert_eq!(detail.static_proof_label, "signal-only");
    assert!(detail.static_proof_explanation.contains("scanner signal"));
    assert_eq!(detail.next_command.as_deref(), Some("verify F-0001"));
}

#[test]
fn selected_finding_detail_recommends_patch_for_runtime_verified_findings() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut finding = Finding::new_semgrep(
        "demo.sql",
        "src/search.ts",
        12,
        Some(14),
        Severity::High,
        "SQL injection\nRemediation: bind the order id parameter",
    )
    .with_static_proof_state(StaticProofState::SourceSinkLinked);
    finding.verification = Some(PersistedVerification {
        proof_level: 4,
        proof_verdict: PersistedProofVerdict::Exploited,
        backend: PersistedSandboxBackend::Plain,
        language: None,
        harness_path: None,
        crash_evidence: None,
        duration_ms: 12,
        cost_usd: 0.0,
        notes: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
    });
    app.findings = vec![finding];

    let detail = selected_finding_detail_model(&app).expect("selected finding");

    assert_eq!(detail.static_proof_label, "path-linked");
    assert_eq!(detail.runtime_label, "verified L4");
    assert_eq!(detail.next_action_label, "patch");
    assert_eq!(detail.next_command.as_deref(), Some("patch F-0001"));
    assert_eq!(
        detail.remediation_hint.as_deref(),
        Some("bind the order id parameter")
    );
}

#[test]
fn selected_out_of_window_finding_drives_detail_with_notice() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let visible = Finding::new_tool(
        "demo",
        "visible.rule",
        "src/visible.rs",
        3,
        None,
        Severity::Medium,
        "visible finding",
    );
    let opened = Finding::new_tool(
        "demo",
        "opened.rule",
        "src/opened.rs",
        9,
        None,
        Severity::High,
        "opened outside loaded list",
    );
    app.findings = vec![visible];
    app.findings_cursor = 0;
    app.selected_finding = Some(opened.clone());

    let list = findings_model(&app);
    let detail = selected_finding_detail_model(&app).expect("opened detail");

    assert!(list.selected_out_of_window.is_some());
    assert!(!list.rows[0].selected);
    assert_eq!(detail.alias, None);
    assert_eq!(detail.title, opened.title);
    assert_eq!(detail.location, "src/opened.rs:9");
}
