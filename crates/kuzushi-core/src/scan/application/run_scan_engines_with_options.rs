use super::*;

pub fn run_scan_engines_with_options(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
) -> Result<ScanRun> {
    workspace.ensure_state_dir()?;

    let run_id = scan_run_id(options);
    store.insert_scan_run(&run_id, workspace.root(), "running")?;

    let cancellation = ScanCancellation::default();
    let mut scan_output = collect_scan_engine_outputs(workspace, scanners, &cancellation)?;
    apply_scan_run_options(&mut scan_output.findings, options);
    index_scan_static_evidence(workspace, options, &scan_output)?;

    for finding in &scan_output.findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", scan_output.findings.len())?;

    Ok(ScanRun {
        id: run_id,
        target: workspace.root().to_path_buf(),
        findings_count: scan_output.findings.len(),
    })
}

fn scan_run_id(options: &ScanRunOptions) -> String {
    options
        .run_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

struct ScanEngineOutputs {
    findings: Vec<Finding>,
    codeql_sarif_documents: Vec<String>,
}

fn collect_scan_engine_outputs(
    workspace: &WorkspaceTarget,
    scanners: &[Box<dyn ScanEngine>],
    cancellation: &ScanCancellation,
) -> Result<ScanEngineOutputs> {
    let mut findings = Vec::new();
    let mut codeql_sarif_documents = Vec::new();
    for scanner in scanners {
        let mut scanner_output = scanner.scan_artifacts(workspace.root(), cancellation)?;
        findings.append(&mut scanner_output.findings);
        codeql_sarif_documents.append(&mut scanner_output.codeql_sarif_documents);
    }
    Ok(ScanEngineOutputs {
        findings,
        codeql_sarif_documents,
    })
}

fn apply_scan_run_options(findings: &mut Vec<Finding>, options: &ScanRunOptions) {
    if let Some(allowed) = &options.severity {
        findings.retain(|finding| allowed.contains(&finding.severity));
    }
    if let Some(static_proof_state) = options.static_proof_state {
        for finding in findings {
            finding.set_static_proof_state(static_proof_state);
        }
    }
}

fn index_scan_static_evidence(
    workspace: &WorkspaceTarget,
    options: &ScanRunOptions,
    output: &ScanEngineOutputs,
) -> Result<()> {
    if !options.index_static_evidence {
        return Ok(());
    }

    let evidence_store = StaticEvidenceStore::open(workspace)?;
    index_semgrep_findings_as_static_evidence(&evidence_store, workspace.root(), &output.findings)?;
    for sarif in &output.codeql_sarif_documents {
        index_codeql_sarif_as_static_evidence(&evidence_store, workspace.root(), sarif)?;
    }
    Ok(())
}

pub fn normalize_semgrep_json(raw: &str) -> Result<Vec<Finding>> {
    let report: SemgrepReport =
        serde_json::from_str(raw).context("Could not parse semgrep JSON")?;
    Ok(report
        .results
        .into_iter()
        .map(|result| {
            Finding::new_semgrep(
                result.check_id,
                result.path,
                result.start.line,
                result.end.map(|end| end.line),
                Severity::from_semgrep(result.extra.severity.as_deref().unwrap_or("UNKNOWN")),
                result
                    .extra
                    .message
                    .unwrap_or_else(|| "Semgrep finding".to_string()),
            )
        })
        .collect())
}

#[derive(Debug, Deserialize)]
pub(crate) struct SemgrepReport {
    #[serde(default)]
    pub(crate) results: Vec<SemgrepResult>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SemgrepResult {
    pub(crate) check_id: String,
    pub(crate) path: String,
    pub(crate) start: SemgrepLocation,
    #[serde(default)]
    pub(crate) end: Option<SemgrepLocation>,
    pub(crate) extra: SemgrepExtra,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SemgrepLocation {
    pub(crate) line: u32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SemgrepExtra {
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) severity: Option<String>,
}
