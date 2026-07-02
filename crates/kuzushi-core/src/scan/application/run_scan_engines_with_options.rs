use super::*;

pub fn run_scan_engines_with_options(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
) -> Result<ScanRun> {
    preflight_scan_engines(scanners)?;
    workspace.ensure_state_dir()?;

    let run_id = scan_run_id(options);
    store.insert_scan_run(&run_id, workspace.root(), "running")?;

    let cancellation = ScanCancellation::default();
    let mut scan_output = collect_scan_engine_outputs(workspace, scanners, &cancellation, options)?;
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

fn preflight_scan_engines(scanners: &[Box<dyn ScanEngine>]) -> Result<()> {
    for scanner in scanners {
        scanner
            .preflight()
            .map_err(|error| anyhow::anyhow!("{} preflight failed: {error:#}", scanner.id()))?;
    }
    Ok(())
}

fn scan_run_id(options: &ScanRunOptions) -> String {
    options
        .run_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

#[derive(Default)]
struct ScanEngineOutputs {
    findings: Vec<Finding>,
    codeql_sarif_documents: Vec<String>,
}

#[derive(Debug, Clone)]
struct ScanRoot {
    path: PathBuf,
    prefix: Option<String>,
}

impl ScanRoot {
    fn workspace(root: &Path) -> Self {
        Self {
            path: root.to_path_buf(),
            prefix: None,
        }
    }
}

fn collect_scan_engine_outputs(
    workspace: &WorkspaceTarget,
    scanners: &[Box<dyn ScanEngine>],
    cancellation: &ScanCancellation,
    options: &ScanRunOptions,
) -> Result<ScanEngineOutputs> {
    let roots = scan_roots(workspace.root(), options)?;
    let mut output = ScanEngineOutputs::default();
    for root in roots {
        collect_scan_root_outputs(&root, scanners, cancellation, &mut output)?;
    }
    Ok(output)
}

fn scan_roots(root: &Path, options: &ScanRunOptions) -> Result<Vec<ScanRoot>> {
    if options.paths.is_empty() {
        return Ok(vec![ScanRoot::workspace(root)]);
    }
    options
        .paths
        .iter()
        .map(|path| scan_root(root, path))
        .collect()
}

fn scan_root(root: &Path, path: &str) -> Result<ScanRoot> {
    let prefix = normalized_scan_path(path)?;
    let absolute = root.join(&prefix);
    if !absolute.is_dir() {
        anyhow::bail!("sast:scan paths entry {prefix:?} is not a directory under the target");
    }
    Ok(ScanRoot {
        path: absolute,
        prefix: Some(prefix),
    })
}

fn normalized_scan_path(path: &str) -> Result<String> {
    let path = path.trim().trim_start_matches("./");
    let mut parts = Vec::new();
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                anyhow::bail!("sast:scan paths entries must be workspace-relative")
            }
        }
    }
    if parts.is_empty() {
        anyhow::bail!("sast:scan paths entries must not be empty");
    }
    Ok(parts.join("/"))
}

fn collect_scan_root_outputs(
    root: &ScanRoot,
    scanners: &[Box<dyn ScanEngine>],
    cancellation: &ScanCancellation,
    output: &mut ScanEngineOutputs,
) -> Result<()> {
    for scanner in scanners {
        let mut scanner_output = scanner.scan_artifacts(&root.path, cancellation)?;
        rewrite_scoped_findings(root, &mut scanner_output.findings);
        output.findings.append(&mut scanner_output.findings);
        output
            .codeql_sarif_documents
            .append(&mut scanner_output.codeql_sarif_documents);
    }
    Ok(())
}

fn rewrite_scoped_findings(root: &ScanRoot, findings: &mut [Finding]) {
    let Some(prefix) = root.prefix.as_deref() else {
        return;
    };
    for finding in findings {
        finding.file_path = prefixed_finding_path(&root.path, prefix, &finding.file_path);
    }
}

fn prefixed_finding_path(scan_root: &Path, prefix: &str, path: &str) -> String {
    let candidate = Path::new(path);
    let relative = if candidate.is_absolute() {
        candidate.strip_prefix(scan_root).unwrap_or(candidate)
    } else {
        candidate
    };
    let relative = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    if relative == prefix || relative.starts_with(&format!("{prefix}/")) {
        relative
    } else {
        format!("{}/{}", prefix, relative.trim_start_matches("./"))
    }
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
