use super::*;
use crate::scan::domain::scanner_binary_available;

#[derive(Debug, Clone)]
pub struct ScanRun {
    pub id: String,
    pub target: PathBuf,
    pub findings_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkippedDefaultScanEngine {
    pub(crate) id: &'static str,
    pub(crate) warning: String,
}

pub(crate) struct DefaultScanEngineSelection {
    pub(crate) engines: Vec<Box<dyn ScanEngine>>,
    pub(crate) skipped: Vec<SkippedDefaultScanEngine>,
}

pub fn run_semgrep_scan(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanner: &SemgrepScanner,
) -> Result<ScanRun> {
    scanner.preflight()?;
    workspace.ensure_state_dir()?;

    let run_id = Uuid::new_v4().to_string();
    store.with_run_lifecycle(&run_id, workspace.root(), || {
        let findings = scanner.scan(workspace.root())?;
        for finding in &findings {
            store.insert_finding(&run_id, finding)?;
        }
        let findings_count = findings.len();
        Ok((
            ScanRun {
                id: run_id.clone(),
                target: workspace.root().to_path_buf(),
                findings_count,
            },
            findings_count,
        ))
    })
}

pub fn default_scan_engines() -> Vec<Box<dyn ScanEngine>> {
    select_default_scan_engines().engines
}

pub(crate) fn select_default_scan_engines() -> DefaultScanEngineSelection {
    default_scan_engine_selection(
        scanner_binary_available("semgrep"),
        CargoAuditScanner::binary_available(),
    )
}

fn default_scan_engine_selection(
    semgrep_available: bool,
    cargo_audit_available: bool,
) -> DefaultScanEngineSelection {
    let mut engines: Vec<Box<dyn ScanEngine>> = Vec::new();
    let mut skipped = Vec::new();
    if semgrep_available {
        engines.push(Box::new(SemgrepScanner::default()));
    } else {
        skipped.push(SkippedDefaultScanEngine {
            id: "semgrep",
            warning: "optional auto task semgrep skipped: semgrep was not found on PATH; continuing with built-in scanners"
                .to_string(),
        });
    }
    engines.push(Box::new(DepHygieneScanner));
    if cargo_audit_available {
        engines.push(Box::new(CargoAuditScanner));
    } else {
        skipped.push(SkippedDefaultScanEngine {
            id: "cargo-audit",
            warning: "optional auto task cargo-audit skipped: `cargo audit` was not found; continuing with built-in scanners"
                .to_string(),
        });
    }
    engines.push(Box::new(SecretScanScanner));
    engines.push(Box::new(IacScanScanner::default()));
    DefaultScanEngineSelection { engines, skipped }
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
            "govulncheck" | "govulncheck:scan" => scanners.push(Box::new(GovulncheckScanner)),
            "cargo-audit" | "cargo-audit:scan" => scanners.push(Box::new(CargoAuditScanner)),
            "secret-scan" | "secret-scan:scan" => scanners.push(Box::new(SecretScanScanner)),
            "license-scan" | "license-scan:scan" => scanners.push(Box::new(LicenseScanScanner)),
            "exploit-chain" | "exploit-chain:scan" => anyhow::bail!(
                "exploit-chain is LLM-only; run exploit-chain:scan directly so Kuzushi can require and pass an agent runtime"
            ),
            "iac-scan" | "iac-scan:scan" => scanners.push(Box::new(IacScanScanner::default())),
            "" => {}
            other => anyhow::bail!(
                "unknown scan task {other:?}; supported tasks: semgrep, codeql, dep-hygiene, govulncheck, cargo-audit, secret-scan, license-scan, iac-scan, agentic, offense-review, taint-iris, taint-iris-next, systems-hunt"
            ),
        }
    }

    Ok(scanners)
}

#[cfg(test)]
pub(in crate::scan) fn default_scan_engine_selection_for_test(
    semgrep_available: bool,
    cargo_audit_available: bool,
) -> DefaultScanEngineSelection {
    default_scan_engine_selection(semgrep_available, cargo_audit_available)
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
    pub run_id: Option<String>,
    pub severity: Option<Vec<Severity>>,
    pub paths: Vec<String>,
    pub tasks: Option<Vec<String>>,
    pub static_proof_state: Option<StaticProofState>,
    pub index_static_evidence: bool,
}
