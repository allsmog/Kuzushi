use super::*;

pub(in crate::modules) fn persist_semgrep_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
    index_static_evidence: bool,
    scan_errors: &[String],
) -> Result<Option<SemgrepPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let static_evidence = if index_static_evidence {
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(workspace)?;
        Some(
            crate::static_evidence::index_semgrep_findings_as_static_evidence(
                &evidence_store,
                workspace.root(),
                findings,
            )?,
        )
    } else {
        None
    };

    let run_id = ctx.finding_run_id();
    persist_findings_run_with_coverage(ctx, store, &run_id, target, findings, scan_errors)?;

    Ok(Some(SemgrepPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        static_evidence,
    }))
}

pub(in crate::modules) fn persist_codeql_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
    sarif_documents: &[String],
    index_static_evidence: bool,
    scan_errors: &[String],
) -> Result<Option<CodeqlPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let static_evidence = if index_static_evidence {
        Some(index_codeql_static_evidence(workspace, sarif_documents)?)
    } else {
        None
    };

    let run_id = ctx.finding_run_id();
    persist_findings_run_with_coverage(ctx, store, &run_id, target, findings, scan_errors)?;

    Ok(Some(CodeqlPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        static_evidence,
    }))
}

fn index_codeql_static_evidence(
    workspace: &crate::workspace::WorkspaceTarget,
    sarif_documents: &[String],
) -> Result<crate::static_evidence::StaticEvidenceIndexReport> {
    let evidence_store = crate::static_evidence::StaticEvidenceStore::open(workspace)?;
    let mut combined =
        crate::static_evidence::StaticEvidenceIndexReport::new(evidence_store.db_path());
    let reports = index_grounded_codeql_sarif_documents_as_static_evidence(
        &evidence_store,
        workspace.root(),
        sarif_documents,
    )?;
    for report in reports {
        append_static_evidence_report(&mut combined, report);
    }
    Ok(combined)
}

fn append_static_evidence_report(
    combined: &mut crate::static_evidence::StaticEvidenceIndexReport,
    report: crate::static_evidence::StaticEvidenceIndexReport,
) {
    combined.findings_indexed += report.findings_indexed;
    combined.nodes_indexed += report.nodes_indexed;
    combined.edges_indexed += report.edges_indexed;
    combined.node_ids.extend(report.node_ids);
    combined.edge_ids.extend(report.edge_ids);
    combined.results_omitted += report.results_omitted;
}

pub(in crate::modules) fn persist_iac_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<Value>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let run_id = ctx.finding_run_id();
    persist_findings_run(ctx, store, &run_id, target, findings)?;

    Ok(Some(json!({
        "runId": run_id,
        "findingsDb": workspace.findings_db_path().display().to_string(),
    })))
}

/// Commit through the shared observed path so the dispatching run records a
/// typed finding delta (receipts would otherwise show an unmeasured `+0`).
fn persist_findings_run(
    ctx: &ToolExecutionContext<'_>,
    store: &FindingStore,
    run_id: &str,
    target: &Path,
    findings: &[Finding],
) -> Result<()> {
    crate::findings::commit_observed_findings(
        store,
        ctx.run_observation().as_ref(),
        run_id,
        target,
        findings,
    )
}

fn persist_findings_run_with_coverage(
    ctx: &ToolExecutionContext<'_>,
    store: &FindingStore,
    run_id: &str,
    target: &Path,
    findings: &[Finding],
    scan_errors: &[String],
) -> Result<()> {
    let status = if scan_errors.is_empty() {
        crate::run_lifecycle::RunItemStatus::Completed
    } else {
        crate::run_lifecycle::RunItemStatus::Partial
    };
    crate::findings::commit_observed_findings_with_status(
        store,
        ctx.run_observation().as_ref(),
        run_id,
        target,
        findings,
        status,
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::run_artifacts::TraceHandle;
    use crate::workspace::WorkspaceTarget;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn registry_semgrep_persists_the_trace_run_identity() {
        let fixture = tempfile::tempdir().unwrap();
        fs::create_dir_all(fixture.path().join("src")).unwrap();
        fs::write(fixture.path().join("src/lib.rs"), "fn main() {}\n").unwrap();
        let binary = fake_semgrep_binary(fixture.path());
        let workspace = WorkspaceTarget::new(fixture.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let trace = TraceHandle::jsonl(fixture.path(), "run-registry-semgrep");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };

        let output = ModuleRegistry::with_v2_builtins()
            .execute_tool(
                "semgrep:scan",
                json!({"binary": binary, "config": "fixture"}),
                &ctx,
            )
            .unwrap();

        assert_eq!(
            output.pointer("/data/persisted/runId"),
            Some(&json!("run-registry-semgrep"))
        );
        let findings = store
            .list_findings_for_scan_id("run-registry-semgrep")
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].scan_id.as_deref(), Some("run-registry-semgrep"));

        // Dropping the trace joins the run-item writer so the projection
        // read sees the committed delta.
        drop(trace);
        let delta = last_finding_delta(fixture.path(), "run-registry-semgrep");
        assert_eq!((delta.added, delta.updated), (1, 0));
    }

    fn last_finding_delta(
        target: &Path,
        run_id: &str,
    ) -> crate::run_lifecycle::FindingDeltaSummary {
        crate::run_lifecycle::load_run_projection(target, run_id)
            .unwrap()
            .projection
            .finding_deltas
            .pop()
            .expect("semgrep persistence commits a typed finding delta")
    }

    fn fake_semgrep_binary(root: &Path) -> PathBuf {
        let path = root.join("semgrep-fixture");
        let report = r#"{"results":[{"check_id":"audit.rule","path":"src/lib.rs","start":{"line":1},"end":{"line":1},"extra":{"severity":"ERROR","message":"fixture"}}]}"#;
        fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{report}'\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }
}

#[cfg(all(test, unix))]
mod partial_tests;
