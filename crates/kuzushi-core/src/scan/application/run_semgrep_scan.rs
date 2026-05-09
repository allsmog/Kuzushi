use super::*;

#[derive(Debug, Clone)]
pub struct ScanRun {
    pub id: String,
    pub target: PathBuf,
    pub findings_count: usize,
}

pub fn run_semgrep_scan(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanner: &SemgrepScanner,
) -> Result<ScanRun> {
    workspace.ensure_state_dir()?;

    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, workspace.root(), "running")?;

    let findings = scanner.scan(workspace.root())?;
    for finding in &findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(ScanRun {
        id: run_id,
        target: workspace.root().to_path_buf(),
        findings_count: findings.len(),
    })
}

pub fn default_scan_engines() -> Vec<Box<dyn ScanEngine>> {
    vec![
        Box::new(SemgrepScanner::default()),
        Box::new(DepHygieneScanner),
        Box::new(CargoAuditScanner),
        Box::new(SecretScanScanner),
        Box::new(IacScanScanner::default()),
    ]
}

pub fn scan_engines_for_tasks(tasks: &[String]) -> Result<Vec<Box<dyn ScanEngine>>> {
    if tasks.is_empty() {
        return Ok(default_scan_engines());
    }

    let mut scanners: Vec<Box<dyn ScanEngine>> = Vec::new();
    for task in tasks {
        match task.trim() {
            "semgrep" | "semgrep:scan" => scanners.push(Box::new(SemgrepScanner::default())),
            "codeql" | "codeql:scan" => scanners.push(Box::new(CodeqlScanner::default())),
            "dep-hygiene" | "dep-hygiene:check" => scanners.push(Box::new(DepHygieneScanner)),
            "cargo-audit" | "cargo-audit:scan" => scanners.push(Box::new(CargoAuditScanner)),
            "secret-scan" | "secret-scan:scan" => scanners.push(Box::new(SecretScanScanner)),
            "iac-scan" | "iac-scan:scan" => scanners.push(Box::new(IacScanScanner::default())),
            "" => {}
            other => anyhow::bail!(
                "unknown scan task {other:?}; supported tasks: semgrep, codeql, dep-hygiene, cargo-audit, secret-scan, iac-scan, agentic, carlini-threat-hunt, taint-iris, taint-iris-next, systems-hunt"
            ),
        }
    }

    Ok(scanners)
}

pub fn run_scan_engines(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
) -> Result<ScanRun> {
    run_scan_engines_with_options(workspace, store, scanners, &ScanRunOptions::default())
}

#[derive(Debug, Default, Clone)]
pub struct ScanRunOptions {
    pub severity: Option<Vec<Severity>>,
    pub tasks: Option<Vec<String>>,
    pub static_proof_state: Option<StaticProofState>,
    pub index_static_evidence: bool,
}
