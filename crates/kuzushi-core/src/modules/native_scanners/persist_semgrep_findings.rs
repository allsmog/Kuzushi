use super::*;

pub(in crate::modules) fn persist_semgrep_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
    index_static_evidence: bool,
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

    let run_id = Uuid::new_v4().to_string();
    store.record_run_started(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.record_run_finished(&run_id, "completed", findings.len())?;

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

    let run_id = Uuid::new_v4().to_string();
    store.record_run_started(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.record_run_finished(&run_id, "completed", findings.len())?;

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
    for sarif in sarif_documents {
        let report =
            index_codeql_sarif_as_static_evidence(&evidence_store, workspace.root(), sarif)?;
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
    let run_id = Uuid::new_v4().to_string();
    store.record_run_started(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.record_run_finished(&run_id, "completed", findings.len())?;

    Ok(Some(json!({
        "runId": run_id,
        "findingsDb": workspace.findings_db_path().display().to_string(),
    })))
}
