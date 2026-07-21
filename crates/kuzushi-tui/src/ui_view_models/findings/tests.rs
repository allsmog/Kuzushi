use super::*;
use kuzushi_core::findings::TriageAuthor;
use kuzushi_core::workspace::ROOT_SCOPE_ID;
use kuzushi_core::{
    write_run_summary, Finding, FindingEvidence, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, RunSummary, RunTargetGitMetadata, Severity, StaticProofState,
    TriageOutcome, TriageVerdict, V2Config, WorkspaceTarget,
};
use std::collections::BTreeMap;

#[test]
fn visible_projection_cache_reuses_shared_storage_until_findings_change() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_findings(vec![Finding::new_semgrep(
        "demo.rule",
        "src/lib.rs",
        7,
        None,
        Severity::High,
        "finding",
    )]);

    let first = projected_visible_findings(&app);
    let cached = projected_visible_findings(&app);
    assert!(std::sync::Arc::ptr_eq(&first, &cached));

    app.findings_mut()[0].severity = Severity::Critical;
    let refreshed = projected_visible_findings(&app);
    assert!(!std::sync::Arc::ptr_eq(&cached, &refreshed));
    assert_eq!(refreshed[0].finding.severity, Severity::Critical);
}

#[test]
fn provenance_filtered_projection_refreshes_when_run_history_finishes_loading() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let run_id = "run-provenance-hydration";
    let mut summary =
        RunSummary::running(run_id, "scan", None, workspace.root().display().to_string());
    summary.target_git = Some(RunTargetGitMetadata {
        sha: "abcdef1234567890".to_string(),
        branch: Some("main".to_string()),
        dirty: false,
    });
    write_run_summary(workspace.root(), &summary.complete()).unwrap();

    let mut finding = Finding::new_tool(
        "semgrep",
        "demo.provenance-filter",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "finding with delayed run provenance",
    );
    finding.scan_id = Some(run_id.to_string());
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_findings(vec![finding]);
    app.set_active_findings_filter(Some("branch:main dirty:clean".to_string()));

    let key = crate::app::ViewHydrationKey::RunSummaryEntries;
    app.workbench_cache()
        .borrow_mut()
        .mark_view_hydration_loading(workspace.root(), std::slice::from_ref(&key));
    let loading = projected_visible_findings(&app);
    assert!(loading.is_empty());

    let entries = kuzushi_core::list_recent_run_summary_entries(workspace.root(), 100).unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(crate::app::ViewHydrationResult {
            target: workspace.root().to_path_buf(),
            key,
            value: crate::app::ViewHydrationValue::RunSummaryEntries(
                crate::app::RunSummaryEntriesState::Ready(entries),
            ),
        });
    let ready = projected_visible_findings(&app);

    assert_eq!(ready.len(), 1);
    assert!(!std::sync::Arc::ptr_eq(&loading, &ready));
}

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
        cost_usd_exact: true,
    });
    high.identity_id = Some("fi_0123456789abcdef0123456789abcdef".to_string());
    let medium = Finding::new_tool(
        "codeql",
        "js/path-injection",
        "src/files.ts",
        22,
        None,
        Severity::Medium,
        "Path traversal candidate",
    );
    *app.selected_finding_mut() = Some(high.clone());
    *app.findings_mut() = vec![high, medium];

    let model = findings_model(&app);

    assert_eq!(model.total, 2);
    assert_eq!(model.triaged, 1);
    assert_eq!(model.pending, 1);
    assert_eq!(model.counts.high, 1);
    assert_eq!(model.counts.medium, 1);
    assert_eq!(model.header, "FINDINGS · 2 · 1H · 1M");
    assert_eq!(
        model.reconciliation_header,
        "showing 2 of 2 · filters:all · review:all · sorted by priority"
    );
    assert_eq!(
        model
            .rows
            .iter()
            .map(|row| row.alias.as_str())
            .collect::<Vec<_>>(),
        vec!["F-0001", "F-0002"],
        "finding rows keep the documented confidence-first projection"
    );
    let high = model
        .rows
        .iter()
        .find(|row| row.alias == "F-0001")
        .expect("confirmed high row");
    assert_eq!(high.identity_label, "FI-01234567");
    assert_eq!(high.severity_label, "HIGH");
    assert_eq!(high.location, "src/search.ts:12-14");
    assert_eq!(high.run_label, "run:unknown");
    assert_eq!(high.revision_label, "rev:unknown");
    assert_eq!(high.verdict, "tp");
    assert_eq!(high.confidence, "91%");
    assert_eq!(high.priority_label, "p:1");
    assert_eq!(high.lifecycle_status, "candidate");
    assert_eq!(high.decision, "confirmed");
    assert_eq!(high.proof_label, "signal-only");
    assert_eq!(high.proof_marker, "?");
    assert_eq!(high.proof_tier, ProofTier::Suspected);
    assert_eq!(high.source, "semgrep:demo.sql");
    assert!(high.selected);
    let medium = model
        .rows
        .iter()
        .find(|row| row.alias == "F-0002")
        .expect("needs-review medium row");
    assert_eq!(medium.proof_label, "unverified");
    assert_eq!(medium.proof_marker, "?");
    assert_eq!(medium.proof_tier, ProofTier::Suspected);
    assert_eq!(model.preview.header, "FINDINGS · 1 triaged · 1 pending");
    assert_eq!(model.preview.rows.len(), 2);
    assert!(model.preview.overflow.is_none());
}

#[test]
fn findings_model_reconciliation_header_names_active_filter_expression() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_active_findings_filter(Some("decision:needs_review completeness:open".to_string()));
    *app.findings_mut() = vec![Finding::new_tool(
        "semgrep",
        "demo.review",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "finding awaiting review",
    )];

    let model = findings_model(&app);

    assert_eq!(
        model.reconciliation_header,
        "showing 1 of 1 · filters:decision:needs_review completeness:open · review:all · sorted by priority"
    );
}

#[test]
fn findings_model_reconciliation_header_tells_the_truth_in_backlog_mode() {
    // The backlog preset hides decided rows, filters by chips, and sorts
    // severity-major — the header must not keep claiming
    // "review:all · sorted by priority".
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![Finding::new_tool(
        "semgrep",
        "demo.backlog",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "untriaged finding",
    )];
    let review = app.router.workbench_mut().review_mut();
    review.backlog = true;
    review.backlog_severity = Some("high");
    review.backlog_tool = Some("semgrep".to_string());

    let model = findings_model(&app);

    assert_eq!(
        model.reconciliation_header,
        "showing 1 of 1 · filters:sev:high + tool:semgrep · review:open · sorted by severity"
    );
}

#[test]
fn findings_header_names_the_ledger_population_when_it_differs() {
    // 481 loaded rows vs a 4340-candidate ledger must read as two labeled
    // populations, not as two contradictory findings counts.
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![Finding::new_tool(
        "semgrep",
        "demo.ledger",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "loaded finding",
    )];
    let counts = crate::app::FindingLedgerCounts {
        total: 4340,
        ..Default::default()
    };
    app.domain_mut().set_finding_ledger_counts(counts);

    let model = findings_model(&app);

    assert_eq!(model.header, "FINDINGS · 1 · 1H · ledger:4340");

    // Same populations → no redundant ledger segment.
    let matching = crate::app::FindingLedgerCounts {
        total: 1,
        ..Default::default()
    };
    app.domain_mut().set_finding_ledger_counts(matching);
    let model = findings_model(&app);
    assert_eq!(model.header, "FINDINGS · 1 · 1H");
}

#[test]
fn findings_model_applies_active_filter_to_visible_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_active_findings_filter(Some("decision:confirmed completeness:complete".to_string()));
    let open = Finding::new_tool(
        "semgrep",
        "demo.open",
        "src/open.rs",
        12,
        None,
        Severity::High,
        "open finding",
    );
    let mut confirmed = Finding::new_tool(
        "semgrep",
        "demo.confirmed",
        "src/confirmed.rs",
        44,
        None,
        Severity::Medium,
        "confirmed finding",
    );
    confirmed.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.86,
        rationale: "reviewed".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
    });
    *app.findings_mut() = vec![open, confirmed];

    let model = findings_model(&app);

    assert_eq!(model.total, 1);
    assert_eq!(model.triaged, 1);
    assert_eq!(model.pending, 0);
    assert_eq!(
        model.reconciliation_header,
        "showing 1 of 2 · filters:decision:confirmed completeness:complete · review:all · sorted by priority"
    );
    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].title, "confirmed finding");
    assert_eq!(model.rows[0].decision, "confirmed");
}

#[test]
fn findings_model_empty_state_distinguishes_filtered_out_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_active_findings_filter(Some(
        "decision:suppressed completeness:complete".to_string(),
    ));

    let model = findings_model(&app);

    assert!(model.rows.is_empty());
    assert_eq!(
        model
            .empty
            .filtered_out
            .as_ref()
            .map(|state| state.expression.as_str()),
        Some("decision:suppressed completeness:complete")
    );
    assert_eq!(
        model.reconciliation_header,
        "showing 0 of 0 · filters:decision:suppressed completeness:complete · review:all · sorted by priority"
    );
}

#[test]
fn findings_model_counts_reviewed_by_durable_identity() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = Finding::new_tool(
        "semgrep",
        "demo.reviewed",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "reviewed finding",
    );
    reviewed.identity_id = Some(identity_id.clone());
    reviewed.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "reviewed".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
    });
    let mut rerun = Finding::new_tool(
        "semgrep",
        "demo.rerun",
        "src/lib.rs",
        20,
        None,
        Severity::Medium,
        "same durable finding seen later",
    );
    rerun.identity_id = Some(identity_id);
    assert!(rerun.triage.is_none());
    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![reviewed, rerun];

    let model = findings_model(&app);

    assert_eq!(model.total, 2);
    assert_eq!(model.triaged, 2);
    assert_eq!(model.pending, 0);
    assert_eq!(model.preview.header, "FINDINGS · 2 triaged · 0 pending");
    assert_eq!(model.rows[1].verdict, "untriaged");
    assert_eq!(model.rows[1].confidence, "91%");
    assert_eq!(model.rows[1].priority_label, "p:2");
    assert_eq!(model.rows[1].decision, "confirmed");
}

#[test]
fn selected_finding_detail_uses_durable_identity_review_decision() {
    let identity_id = "fi_0123456789abcdef0123456789abcdef".to_string();
    let mut reviewed = Finding::new_tool(
        "semgrep",
        "demo.reviewed",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "reviewed finding",
    );
    reviewed.id = Some(1);
    reviewed.identity_id = Some(identity_id.clone());
    reviewed.triage = Some(TriageOutcome {
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "operator confirmed this identity".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
    });
    reviewed.triaged_by = Some(TriageAuthor::Human);

    let mut rerun = Finding::new_tool(
        "semgrep",
        "demo.rerun",
        "src/lib.rs",
        20,
        None,
        Severity::Medium,
        "same durable finding seen later",
    );
    rerun.id = Some(2);
    rerun.identity_id = Some(identity_id);
    assert!(rerun.triage.is_none());

    let mut app = ShellApp::new(V2Config::default(), None);
    *app.findings_mut() = vec![reviewed, rerun];
    app.router.findings_mut().set_cursor(1);

    let detail = selected_finding_detail_model(&app).expect("selected finding");
    let triage = detail.triage.as_ref().expect("carried review decision");

    assert_eq!(detail.location, "src/lib.rs:20");
    assert_eq!(detail.decision, "confirmed");
    assert_eq!(detail.confidence, "91%");
    assert_eq!(detail.decision_source, "durable identity");
    assert_eq!(
        detail.decision_history,
        "latest loaded decision from durable identity"
    );
    assert_eq!(triage.review_decision, "confirmed");
    assert_eq!(triage.verdict, "true_positive");
    assert_eq!(triage.confidence, "91%");
    assert_eq!(triage.author, "human");
    assert_eq!(triage.source, "durable identity");
    assert_eq!(triage.rationale, "operator confirmed this identity");
}

#[test]
fn selected_finding_detail_includes_run_summary_provenance() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut summary = RunSummary::running(
        "run-detail",
        "scan",
        Some("sast:scan".to_string()),
        workspace.root().display().to_string(),
    )
    .complete();
    summary.model = Some("openai:gpt-test".to_string());
    summary.platform = Some("codex".to_string());
    summary.kuzushi_version = Some("0.24.0-test".to_string());
    summary.target_git = Some(RunTargetGitMetadata {
        sha: "abcdef1234567890".to_string(),
        branch: Some("main".to_string()),
        dirty: true,
    });
    write_run_summary(workspace.root(), &summary).unwrap();

    let mut finding = Finding::new_tool(
        "semgrep",
        "demo.provenance",
        "src/lib.rs",
        12,
        None,
        Severity::High,
        "finding with run provenance",
    );
    finding.scan_id = Some("run-detail".to_string());

    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.hydrate_all_view_data_for_test();
    *app.findings_mut() = vec![finding];

    let detail = selected_finding_detail_model(&app).expect("selected finding");

    assert_eq!(detail.run_label, "run:run-detail");
    assert_eq!(detail.run_status, "status:completed");
    assert_eq!(detail.run_tool, "tool:sast:scan");
    assert_eq!(detail.run_model, "model:openai:gpt-test");
    assert_eq!(detail.run_runtime, "runtime:codex");
    assert_eq!(detail.run_kuzushi_version, "kuzushi:0.24.0-test");
    assert_eq!(detail.revision_label, "rev:abcdef1*");
    assert_eq!(detail.branch_label, "branch:main");
    assert_eq!(detail.vuln_source_label, "sarif");
}

#[test]
fn finding_identity_label_is_explicit_when_unassigned() {
    let mut finding = Finding::new_semgrep(
        "demo.sql",
        "src/search.ts",
        12,
        None,
        Severity::High,
        "SQL injection",
    );

    assert_eq!(finding_identity_label(&finding), "unassigned");

    finding.identity_id = Some("fi_89abcdef0123456789abcdef01234567".to_string());
    assert_eq!(finding_identity_label(&finding), "FI-89ABCDEF");
}

#[test]
fn findings_model_projects_cross_run_duplicates_by_engagement_key() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut semgrep = Finding::new_tool(
        "semgrep",
        "semgrep/cwe-89",
        "src/search.ts",
        12,
        None,
        Severity::Medium,
        "SQL injection CWE-89 reaches db.query",
    );
    semgrep.scan_id = Some("scan-a".to_string());
    let mut systems = Finding::new_tool(
        "systems-hunt",
        "systems/cwe-89",
        "src/search.ts",
        14,
        None,
        Severity::High,
        "SQL injection CWE-89 reaches db.query",
    );
    systems.scan_id = Some("scan-b".to_string());
    assert_eq!(semgrep.dedup_key, systems.dedup_key);
    *app.selected_finding_mut() = Some(semgrep.clone());
    *app.findings_mut() = vec![semgrep, systems];

    let model = findings_model(&app);

    assert_eq!(model.total, 1);
    assert_eq!(visible_findings_len(&app), 1);
    assert_eq!(model.header, "FINDINGS · 1 · 1H");
    assert_eq!(model.counts.high, 1);
    assert_eq!(model.counts.medium, 0);
    assert_eq!(model.rows.len(), 1);
    assert_eq!(model.rows[0].severity_label, "HIGH");
    assert!(model.rows[0].selected);
    assert!(model.rows[0].source.contains("corroboration 2"));
}

#[test]
fn current_finding_for_detail_tracks_projected_cursor_not_raw_duplicate() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut semgrep = Finding::new_tool(
        "semgrep",
        "semgrep/cwe-89",
        "src/search.ts",
        12,
        None,
        Severity::Medium,
        "SQL injection CWE-89 reaches db.query",
    );
    semgrep.scan_id = Some("scan-a".to_string());
    let mut systems = Finding::new_tool(
        "systems-hunt",
        "systems/cwe-89",
        "src/search.ts",
        14,
        None,
        Severity::High,
        "SQL injection CWE-89 reaches db.query",
    );
    systems.scan_id = Some("scan-b".to_string());
    let distinct = Finding::new_tool(
        "semgrep",
        "semgrep/cwe-200",
        "src/info.ts",
        30,
        None,
        Severity::Low,
        "Information exposure CWE-200",
    );
    *app.selected_finding_mut() = Some(semgrep);
    *app.findings_mut() = vec![systems, distinct.clone()];
    app.router.findings_mut().set_cursor(1);

    let (_, finding) = current_finding_for_detail(&app).expect("projected cursor finding");

    assert_eq!(finding.fingerprint, distinct.fingerprint);
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
    app.set_active_scope(Some(crate::app::TargetCandidateScope {
        id: scope.id,
        kind: scope.kind,
        rel_path: scope.rel_path,
    }));
    *app.findings_mut() = vec![
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
    app.hydrate_all_view_data_for_test();

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
        verification_run_id: None,
        verified_scan_id: None,
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

    let mut strong_static = linked.clone();
    strong_static.static_proof_state = Some(StaticProofState::StaticallyConfirmed);
    assert_eq!(finding_proof_label(&strong_static), "static-supported");
    assert_eq!(
        finding_proof_badge(&strong_static).tier,
        ProofTier::StaticLinked
    );

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
    assert_eq!(provenance.branch_label, "branch:main");
}

#[test]
fn finding_run_provenance_reports_unknown_branch_without_target_git() {
    let mut finding = Finding::new_tool(
        "demo",
        "demo.rule",
        "src/lib.rs",
        7,
        None,
        Severity::Medium,
        "finding scanned before target git capture",
    );
    finding.scan_id = Some("scan-no-git".to_string());
    let summary = RunSummary::running("scan-no-git", "scan", Some("sast:scan".to_string()), ".");
    let runs = BTreeMap::from([(summary.run_id.clone(), summary)]);

    let provenance = finding_run_provenance(&finding, &runs);

    assert_eq!(provenance.revision_label, "rev:unknown");
    assert_eq!(provenance.branch_label, "branch:unknown");
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
    app.domain_mut().context_view_mut().status =
        "malformed context snapshot. Next: context build".to_string();

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
    *app.findings_mut() = (0..10)
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
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);

    let model = selected_finding_detail_model(&app).expect("selected finding");

    assert_eq!(model.alias.as_deref(), Some("F-0001"));
    assert_eq!(model.severity_label, "high");
    assert_eq!(model.location, "src/app.ts:8");
    assert_eq!(
        model.evidence[0].header,
        "filesystem_sink · conf 92 · src/app.ts:8"
    );
    assert_eq!(model.evidence[0].origin, "observed capture evidence");
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
fn selected_finding_detail_labels_observed_and_model_generated_evidence() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let finding = Finding::new_tool(
        "agentic-sast",
        "demo.reasoning",
        "src/app.ts",
        8,
        Some(8),
        Severity::High,
        "model-reviewed finding",
    )
    .with_evidence(vec![
        FindingEvidence {
            kind: "code".to_string(),
            file_path: "src/app.ts".to_string(),
            line: 8,
            snippet: "db.query(input)".to_string(),
            rationale: "source reaches sink in code".to_string(),
            confidence: 91,
            ..Default::default()
        },
        FindingEvidence {
            kind: "reasoning".to_string(),
            file_path: String::new(),
            line: 0,
            snippet: "model compared source and sink context".to_string(),
            rationale: "LLM analysis only; not observed runtime evidence".to_string(),
            confidence: 67,
            ..Default::default()
        },
    ]);
    *app.findings_mut() = vec![finding];

    let model = selected_finding_detail_model(&app).expect("selected finding");

    assert_eq!(model.evidence[0].origin, "observed code evidence");
    assert_eq!(model.evidence[1].origin, "model-generated reasoning");
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
        cost_usd_exact: true,
    });
    finding.triaged_by = Some(TriageAuthor::Human);
    *app.findings_mut() = vec![finding];

    let list = findings_model(&app);
    let detail = selected_finding_detail_model(&app).expect("selected finding");
    let triage = detail.triage.as_ref().expect("triage summary");

    assert_eq!(list.rows[0].proof_label, "signal-only");
    assert_eq!(detail.proof_label, list.rows[0].proof_label);
    assert_eq!(detail.proof_marker, list.rows[0].proof_marker);
    assert_eq!(detail.proof_tier, list.rows[0].proof_tier);
    assert!(detail.proof_state.contains("signal_only"));
    assert_eq!(detail.static_proof_label, "signal-only");
    assert!(detail.static_proof_explanation.contains("scanner signal"));
    assert_eq!(triage.review_decision, "confirmed");
    assert_eq!(triage.verdict, "true_positive");
    assert_eq!(triage.source, "selected finding");
    assert_eq!(triage.author, "human");
    assert_eq!(detail.decision, "confirmed");
    assert_eq!(detail.confidence, "91%");
    assert_eq!(detail.decision_source, "selected finding");
    assert_eq!(
        detail.decision_history,
        "latest loaded decision from selected finding"
    );
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
        verification_run_id: None,
        verified_scan_id: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
    });
    *app.findings_mut() = vec![finding];

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
    *app.findings_mut() = vec![visible];
    app.router.findings_mut().set_cursor(0);
    *app.selected_finding_mut() = Some(opened.clone());

    let list = findings_model(&app);
    let detail = selected_finding_detail_model(&app).expect("opened detail");

    assert!(list.selected_out_of_window.is_some());
    assert!(!list.rows[0].selected);
    assert_eq!(detail.alias, None);
    assert_eq!(detail.title, opened.title);
    assert_eq!(detail.location, "src/opened.rs:9");
}

#[test]
fn snippet_window_centers_on_the_finding_line_with_bounded_context() {
    let content = (1..=20)
        .map(|n| format!("line {n}"))
        .collect::<Vec<_>>()
        .join("\n");

    let snippet = snippet_from_content(&content, 10);

    assert_eq!(snippet.start_line, 10 - SNIPPET_CONTEXT_BEFORE);
    assert_eq!(snippet.focus_line, 10);
    assert_eq!(
        snippet.lines.len(),
        SNIPPET_CONTEXT_BEFORE + 1 + SNIPPET_CONTEXT_AFTER
    );
    assert_eq!(snippet.lines[SNIPPET_CONTEXT_BEFORE], "line 10");
    assert_eq!(snippet.note, None);
}

#[test]
fn snippet_window_clamps_at_file_edges() {
    let content = "one\ntwo\nthree";

    let top = snippet_from_content(content, 1);
    assert_eq!(top.start_line, 1);
    assert_eq!(top.lines, vec!["one", "two", "three"]);

    let bottom = snippet_from_content(content, 3);
    assert_eq!(bottom.start_line, 1);
    assert_eq!(bottom.lines.last().map(String::as_str), Some("three"));
}

#[test]
fn snippet_window_reports_a_drifted_line_instead_of_guessing() {
    let snippet = snippet_from_content("only line", 42);

    assert!(snippet.lines.is_empty());
    let note = snippet.note.expect("drift note");
    assert!(note.contains("line 42"), "{note}");
    assert!(note.contains("source has changed"), "{note}");
}

#[test]
fn snippet_window_expands_tabs_for_stable_gutters() {
    let snippet = snippet_from_content("\tindented", 1);

    assert_eq!(snippet.lines, vec!["  indented"]);
}

fn scanned_fold_app() -> (tempfile::TempDir, ShellApp) {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let app = ShellApp::new(V2Config::default(), Some(&workspace));
    (temp, app)
}

fn scanned_fold_finding() -> Finding {
    Finding::new_tool(
        "semgrep",
        "demo.snippet",
        "src/app.rs",
        1,
        None,
        Severity::High,
        "finding with a scanned copy",
    )
}

fn store_scanned_window(app: &ShellApp, finding: &Finding, state: crate::ScannedSnippetState) {
    app.workbench_cache().borrow_mut().store_scanned_snippet(
        app.target().unwrap(),
        &finding.fingerprint,
        finding.scan_id.as_deref(),
        finding.start_line,
        state,
    );
}

#[test]
fn snippet_falls_back_to_the_scanned_copy_when_the_live_line_drifts() {
    let (temp, app) = scanned_fold_app();
    std::fs::create_dir_all(temp.path().join("src")).unwrap();
    std::fs::write(temp.path().join("src/app.rs"), "let x = 2;\n").unwrap();
    let finding = scanned_fold_finding();
    store_scanned_window(
        &app,
        &finding,
        crate::ScannedSnippetState::Ready(crate::ScannedSnippetWindow {
            start_line: 1,
            focus_line: 1,
            lines: vec!["let x = 1;".to_string()],
        }),
    );

    let snippet = source_snippet_model(&app, &finding).expect("snippet");

    assert_eq!(snippet.lines, vec!["let x = 1;"]);
    let note = snippet.note.expect("as-scanned note");
    assert!(note.starts_with("as scanned @ unknown"), "{note}");
}

#[test]
fn snippet_keeps_the_live_source_when_it_matches_the_scanned_copy() {
    let (temp, app) = scanned_fold_app();
    std::fs::create_dir_all(temp.path().join("src")).unwrap();
    std::fs::write(temp.path().join("src/app.rs"), "let x = 2;\n").unwrap();
    let finding = scanned_fold_finding();
    store_scanned_window(
        &app,
        &finding,
        crate::ScannedSnippetState::Ready(crate::ScannedSnippetWindow {
            start_line: 1,
            focus_line: 1,
            lines: vec!["let  x  =  2;".to_string()],
        }),
    );

    let snippet = source_snippet_model(&app, &finding).expect("snippet");

    assert_eq!(snippet.lines, vec!["let x = 2;"]);
    assert_eq!(snippet.note, None);
}

#[test]
fn missing_live_source_renders_the_scanned_copy() {
    let (_temp, app) = scanned_fold_app();
    let finding = scanned_fold_finding();
    store_scanned_window(
        &app,
        &finding,
        crate::ScannedSnippetState::Ready(crate::ScannedSnippetWindow {
            start_line: 1,
            focus_line: 1,
            lines: vec!["let x = 1;".to_string()],
        }),
    );

    let snippet = source_snippet_model(&app, &finding).expect("snippet");

    assert_eq!(snippet.lines, vec!["let x = 1;"]);
    assert!(snippet.note.unwrap().starts_with("as scanned @"));
}

#[test]
fn missing_live_source_without_a_scanned_copy_notes_the_absence() {
    let (_temp, app) = scanned_fold_app();
    let finding = scanned_fold_finding();
    store_scanned_window(&app, &finding, crate::ScannedSnippetState::Missing);

    let snippet = source_snippet_model(&app, &finding).expect("snippet");

    assert!(snippet.lines.is_empty());
    let note = snippet.note.expect("absence note");
    assert!(note.contains("source unavailable"), "{note}");
    assert!(note.contains("no scanned copy recorded"), "{note}");
}
