use super::*;

pub fn run_scan_engines_with_options(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
) -> Result<ScanRun> {
    run_scan_engines_with_options_and_cancellation(
        workspace,
        store,
        scanners,
        options,
        &ScanCancellation::default(),
    )
}

pub fn run_scan_engines_with_options_and_cancellation(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
    cancellation: &ScanCancellation,
) -> Result<ScanRun> {
    ensure_scan_active(cancellation)?;
    preflight_scan_engines(scanners)?;
    workspace.ensure_state_dir()?;

    let run_id = scan_run_id(options);
    store.with_run_lifecycle(&run_id, workspace.root(), || {
        let mut scan_output =
            collect_scan_engine_outputs(workspace, scanners, cancellation, options)?;
        ensure_scan_active(cancellation)?;
        apply_scan_run_options(workspace.root(), &mut scan_output.findings, options);
        index_scan_static_evidence(workspace, options, &scan_output)?;
        for finding in &scan_output.findings {
            store.insert_finding(&run_id, finding)?;
        }
        let findings_count = scan_output.findings.len();
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

fn ensure_scan_active(cancellation: &ScanCancellation) -> Result<()> {
    if cancellation.is_cancelled() {
        anyhow::bail!("scan cancelled")
    }
    Ok(())
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
    let mut roots = options
        .paths
        .iter()
        .map(|path| scan_root(root, path))
        .collect::<Result<Vec<_>>>()?;
    roots.sort_by_key(|scope| scope.path.components().count());
    roots.dedup_by(|left, right| left.path == right.path);
    let mut minimal = Vec::<ScanRoot>::new();
    for scope in roots {
        if !minimal
            .iter()
            .any(|parent| scope.path.starts_with(&parent.path))
        {
            minimal.push(scope);
        }
    }
    Ok(minimal)
}

fn scan_root(root: &Path, path: &str) -> Result<ScanRoot> {
    let prefix = normalized_scan_path(path)?;
    let absolute = root.join(&prefix);
    let scan_path = if absolute.is_dir() {
        absolute
    } else if absolute.is_file() {
        absolute
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.to_path_buf())
    } else {
        anyhow::bail!("sast:scan paths entry {prefix:?} does not exist under the target");
    };
    let scan_prefix = scan_path
        .strip_prefix(root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .map(path_to_slash_string);
    Ok(ScanRoot {
        path: scan_path,
        prefix: scan_prefix,
    })
}

fn path_to_slash_string(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn finding_matches_scan_paths(root: &Path, finding: &Finding, paths: &[String]) -> bool {
    paths.iter().any(|path| {
        let Ok(scope) = normalized_scan_path(path) else {
            return false;
        };
        let absolute = root.join(&scope);
        if absolute.is_file() {
            finding.file_path == scope
        } else {
            finding.file_path == scope || finding.file_path.starts_with(&format!("{scope}/"))
        }
    })
}

fn retain_scoped_findings(root: &Path, findings: &mut Vec<Finding>, paths: &[String]) {
    if !paths.is_empty() {
        findings.retain(|finding| finding_matches_scan_paths(root, finding, paths));
    }
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
        ensure_aggregate_scan_coverage(scanner.id(), &scanner_output.scan_errors)?;
        rewrite_scoped_findings(root, &mut scanner_output.findings);
        output.findings.append(&mut scanner_output.findings);
        output
            .codeql_sarif_documents
            .append(&mut scanner_output.codeql_sarif_documents);
    }
    Ok(())
}

const MAX_AGGREGATE_SCAN_ERRORS: usize = 3;
const MAX_AGGREGATE_SCAN_ERROR_CHARS: usize = 240;

/// The aggregate scan result has no coverage-error field. Until it does, an
/// engine that reports any unscanned portion must fail here rather than let a
/// non-empty finding set make the umbrella run look complete.
fn ensure_aggregate_scan_coverage(scanner_id: &str, scan_errors: &[String]) -> Result<()> {
    if scan_errors.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{scanner_id} scan coverage incomplete: {} part{} of the target went unanalyzed; aggregate scan cannot report partial coverage: {}",
        scan_errors.len(),
        if scan_errors.len() == 1 { "" } else { "s" },
        bounded_scan_error_summary(scan_errors)
    )
}

fn bounded_scan_error_summary(scan_errors: &[String]) -> String {
    let mut summaries = scan_errors
        .iter()
        .take(MAX_AGGREGATE_SCAN_ERRORS)
        .map(|error| {
            let first_line = error.lines().next().unwrap_or_default().trim();
            let first_line = if first_line.is_empty() {
                "unspecified scan error"
            } else {
                first_line
            };
            let mut chars = first_line.chars();
            let visible = chars
                .by_ref()
                .take(MAX_AGGREGATE_SCAN_ERROR_CHARS)
                .collect::<String>();
            if chars.next().is_some() {
                format!("{visible}…")
            } else {
                visible
            }
        })
        .collect::<Vec<_>>();
    if scan_errors.len() > MAX_AGGREGATE_SCAN_ERRORS {
        summaries.push(format!(
            "... and {} more scan errors",
            scan_errors.len() - MAX_AGGREGATE_SCAN_ERRORS
        ));
    }
    summaries.join("; ")
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

fn apply_scan_run_options(root: &Path, findings: &mut Vec<Finding>, options: &ScanRunOptions) {
    retain_scoped_findings(root, findings, &options.paths);
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
    Ok(semgrep_findings_from_report(parse_semgrep_report(raw)?))
}

pub(crate) fn parse_semgrep_report(raw: &str) -> Result<SemgrepReport> {
    serde_json::from_str(raw).context("Could not parse semgrep JSON")
}

pub(crate) fn semgrep_findings_from_report(report: SemgrepReport) -> Vec<Finding> {
    report
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
        .collect()
}

/// One line per semgrep-reported scan error, e.g. a target file it could not
/// parse or a rule it skipped. These describe coverage the scan did NOT get.
pub(crate) fn semgrep_error_summaries(errors: &[SemgrepReportError]) -> Vec<String> {
    errors.iter().map(semgrep_error_summary).collect()
}

fn semgrep_error_summary(error: &SemgrepReportError) -> String {
    // Semgrep error messages can carry multi-line tracebacks; keep the first
    // line so summaries stay one row per skipped file/rule.
    let message = error
        .message
        .as_deref()
        .and_then(|text| text.lines().next())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or("semgrep reported an unspecified scan error");
    match error.path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        Some(path) => format!("{path}: {message}"),
        None => message.to_string(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct SemgrepReport {
    #[serde(default)]
    pub(crate) results: Vec<SemgrepResult>,
    #[serde(default)]
    pub(crate) errors: Vec<SemgrepReportError>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SemgrepReportError {
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) path: Option<String>,
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

#[cfg(test)]
mod aggregate_coverage_tests {
    use super::*;

    struct PartialCoverageScanner;

    impl ScanEngine for PartialCoverageScanner {
        fn id(&self) -> &'static str {
            "partial-native"
        }

        fn scan(
            &self,
            _target: &Path,
            _cancellation: &ScanCancellation,
        ) -> Result<Vec<Finding>> {
            unreachable!("aggregate runner should use scan_artifacts")
        }

        fn scan_artifacts(
            &self,
            _target: &Path,
            _cancellation: &ScanCancellation,
        ) -> Result<ScanEngineOutput> {
            Ok(ScanEngineOutput {
                findings: vec![Finding::new_tool(
                    self.id(),
                    "partial/demo",
                    "src/app.rs",
                    12,
                    None,
                    Severity::High,
                    "finding from the analyzed portion",
                )],
                codeql_sarif_documents: Vec::new(),
                scan_errors: vec!["src/missed.rs: parser failed".to_string()],
            })
        }
    }

    #[test]
    fn aggregate_scan_refuses_findings_that_would_hide_a_coverage_gap() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let scanners: Vec<Box<dyn ScanEngine>> = vec![Box::new(PartialCoverageScanner)];

        let error = run_scan_engines_with_options(
            &workspace,
            &store,
            &scanners,
            &ScanRunOptions::default(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("partial-native scan coverage incomplete"));
        assert!(error.contains("1 part of the target went unanalyzed"));
        assert!(store.list_findings(10).unwrap().is_empty());
    }

    #[test]
    fn aggregate_scan_error_summary_is_bounded() {
        let errors = vec![
            "a".repeat(MAX_AGGREGATE_SCAN_ERROR_CHARS + 40),
            "second\nsecret-looking second line".to_string(),
            "third".to_string(),
            "fourth".to_string(),
        ];

        let summary = bounded_scan_error_summary(&errors);

        assert!(summary.contains('…'));
        assert!(!summary.contains("secret-looking second line"));
        assert!(summary.contains("... and 1 more scan errors"));
    }
}
