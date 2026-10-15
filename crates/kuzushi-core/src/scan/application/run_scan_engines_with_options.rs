use super::*;

#[cfg(test)]
mod exact_tests;
#[cfg(test)]
mod partial_tests;
#[cfg(test)]
mod scope_tests;
#[cfg(test)]
mod stopped_tests;

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
    let report =
        run_native_scan_with_cancellation(workspace, store, scanners, options, cancellation)?;
    for engine in &report.coverage.engines {
        ensure_aggregate_scan_coverage(&engine.engine, &engine.scan_errors)?;
    }
    Ok(report.run)
}

pub(crate) fn run_native_scan_with_cancellation(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
    cancellation: &ScanCancellation,
) -> Result<NativeScanReport> {
    ensure_scan_active(cancellation)?;
    let roots = scan_roots(workspace.root(), options)?;
    ensure_file_scopes_supported(scanners, &roots)?;
    run_native_scan_on_roots(workspace, store, scanners, options, &roots, cancellation)
}

pub(crate) fn run_native_scan_files_with_cancellation(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
    files: &[String],
    cancellation: &ScanCancellation,
) -> Result<NativeScanReport> {
    ensure_scan_active(cancellation)?;
    anyhow::ensure!(
        options.paths.is_empty(),
        "exact membership cannot be combined with directory paths"
    );
    validate_exact_engine_contract(scanners)?;
    let roots = exact_file_root(workspace.root(), files)?;
    run_native_scan_on_roots(workspace, store, scanners, options, &roots, cancellation)
}

fn run_native_scan_on_roots(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
    roots: &[ScanRoot],
    cancellation: &ScanCancellation,
) -> Result<NativeScanReport> {
    preflight_scan_engines(scanners)?;
    workspace.ensure_state_dir()?;

    let run_id = scan_run_id(options);
    store.with_scan_lifecycle_before_receipt(&run_id, workspace.root(), || {
        settle_native_scan(
            workspace,
            store,
            roots,
            scanners,
            options,
            cancellation,
            &run_id,
        )
    })?
}

fn settle_native_scan(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    roots: &[ScanRoot],
    scanners: &[Box<dyn ScanEngine>],
    options: &ScanRunOptions,
    cancellation: &ScanCancellation,
    run_id: &str,
) -> Result<(
    Result<NativeScanReport>,
    usize,
    crate::run_lifecycle::RunItemStatus,
)> {
    let mut output = planned_scan_outputs(roots, scanners);
    let execution = collect_scan_engine_outputs(roots, scanners, cancellation, &mut output);
    apply_scan_run_options(workspace.root(), &mut output.findings, options);
    for finding in &output.findings {
        store.insert_finding(run_id, finding)?;
    }
    let execution = execution
        .and_then(|_| ensure_scan_active(cancellation))
        .and_then(|_| index_scan_static_evidence(workspace, options, &output));
    let count = output.findings.len();
    let report = NativeScanReport {
        run: ScanRun {
            id: run_id.into(),
            target: workspace.root().into(),
            findings_count: count,
        },
        coverage: output.coverage,
    };
    Ok(native_scan_settlement(report, execution, cancellation))
}

fn native_scan_settlement(
    report: NativeScanReport,
    execution: Result<()>,
    cancellation: &ScanCancellation,
) -> (
    Result<NativeScanReport>,
    usize,
    crate::run_lifecycle::RunItemStatus,
) {
    let count = report.run.findings_count;
    match execution {
        Ok(()) => {
            let status = native_completion_status(&report.coverage);
            (Ok(report), count, status)
        }
        Err(cause) => {
            let status = native_stop_status(cancellation);
            (
                Err(NativeScanFailure {
                    report,
                    status,
                    cause,
                }
                .into()),
                count,
                status,
            )
        }
    }
}

fn native_stop_status(cancellation: &ScanCancellation) -> crate::run_lifecycle::RunItemStatus {
    use crate::run_lifecycle::RunItemStatus;
    match cancellation.disposition() {
        Some(CancellationDisposition::Canceled) => RunItemStatus::Canceled,
        Some(CancellationDisposition::Interrupted) => RunItemStatus::Interrupted,
        None => RunItemStatus::Failed,
    }
}

fn native_completion_status(coverage: &NativeScanCoverage) -> crate::run_lifecycle::RunItemStatus {
    if coverage.has_gaps() {
        crate::run_lifecycle::RunItemStatus::Partial
    } else {
        crate::run_lifecycle::RunItemStatus::Completed
    }
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
    coverage: NativeScanCoverage,
}

#[derive(Debug, Clone)]
struct ScanRoot {
    path: PathBuf,
    prefix: Option<String>,
    files: Option<Vec<String>>,
}

impl ScanRoot {
    fn workspace(root: &Path) -> Self {
        Self {
            path: root.to_path_buf(),
            prefix: None,
            files: None,
        }
    }
}

fn planned_scan_outputs(roots: &[ScanRoot], scanners: &[Box<dyn ScanEngine>]) -> ScanEngineOutputs {
    let engines = roots
        .iter()
        .flat_map(|root| {
            scanners.iter().map(|scanner| NativeEngineCoverage {
                engine: scanner.id().into(),
                scope: root.prefix.clone(),
                findings_count: 0,
                scan_errors: Vec::new(),
                disposition: NativeEngineDisposition::NotStarted,
            })
        })
        .collect();
    ScanEngineOutputs {
        coverage: NativeScanCoverage {
            engines,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn collect_scan_engine_outputs(
    roots: &[ScanRoot],
    scanners: &[Box<dyn ScanEngine>],
    cancellation: &ScanCancellation,
    output: &mut ScanEngineOutputs,
) -> Result<()> {
    for (root_index, root) in roots.iter().enumerate() {
        for (scanner_index, scanner) in scanners.iter().enumerate() {
            ensure_scan_active(cancellation)?;
            let index = root_index * scanners.len() + scanner_index;
            collect_scan_engine_output(root, scanner.as_ref(), cancellation, output, index)?;
        }
    }
    Ok(())
}

fn scan_roots(root: &Path, options: &ScanRunOptions) -> Result<Vec<ScanRoot>> {
    if options.paths.is_empty() {
        return Ok(vec![ScanRoot::workspace(root)]);
    }
    let (directories, files): (Vec<_>, Vec<_>) = resolve_scan_scopes(root, &options.paths)?
        .into_iter()
        .partition(|scope| scope.is_directory);
    let mut roots = minimal_directory_roots(directories)?;
    let files = files
        .into_iter()
        .filter(|file| {
            !roots
                .iter()
                .any(|parent| file.path.starts_with(&parent.path))
        })
        .map(|file| file.relative)
        .collect::<Vec<_>>();
    if !files.is_empty() {
        // Exact membership: the engine reads these files, never their parent.
        roots.push(ScanRoot {
            path: root.to_path_buf(),
            prefix: None,
            files: Some(files),
        });
    }
    Ok(roots)
}

/// A file scope is never widened: engines that cannot read exact files refuse
/// it with the same explanation the shared scope guard gives.
fn ensure_file_scopes_supported(
    scanners: &[Box<dyn ScanEngine>],
    roots: &[ScanRoot],
) -> Result<()> {
    let Some((root, file)) = roots
        .iter()
        .find_map(|root| root.files.as_ref()?.first().map(|file| (root, file)))
    else {
        return Ok(());
    };
    let unsupported = scanners
        .iter()
        .filter(|scanner| !scanner.supports_exact_files())
        .map(|scanner| scanner.id())
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        return Ok(());
    }
    let scope = ScanScope {
        path: root.path.join(file),
        relative: file.clone(),
        is_directory: false,
    };
    require_directory_scope(&scope, &unsupported.join(", "))
}

fn minimal_directory_roots(directories: Vec<ScanScope>) -> Result<Vec<ScanRoot>> {
    let mut roots = directories
        .into_iter()
        .map(scan_root)
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

fn scan_root(scope: ScanScope) -> Result<ScanRoot> {
    require_directory_scope(&scope, "Native scanners")?;
    Ok(ScanRoot {
        path: scope.path,
        prefix: Some(scope.relative),
        files: None,
    })
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

fn collect_scan_engine_output(
    root: &ScanRoot,
    scanner: &dyn ScanEngine,
    cancellation: &ScanCancellation,
    output: &mut ScanEngineOutputs,
    index: usize,
) -> Result<()> {
    let result = scan_root_artifacts(root, scanner, cancellation).and_then(|mut result| {
        rewrite_scoped_findings(root, scanner, &mut result.findings)?;
        ensure_exact_observation_paths(root, &result.findings)?;
        Ok(result)
    });
    let mut result = result.map_err(|error| {
        let coverage = &mut output.coverage.engines[index];
        coverage.disposition = native_engine_stop_disposition(cancellation);
        coverage.scan_errors = vec![format!("{error:#}")];
        error
    })?;
    let coverage = &mut output.coverage.engines[index];
    coverage.disposition = if cancellation.is_cancelled() && !result.scan_errors.is_empty() {
        native_engine_stop_disposition(cancellation)
    } else {
        NativeEngineDisposition::Complete
    };
    coverage.findings_count = result.findings.len();
    coverage.scan_errors = result.scan_errors;
    output.findings.append(&mut result.findings);
    output
        .codeql_sarif_documents
        .append(&mut result.codeql_sarif_documents);
    Ok(())
}

fn validate_exact_engine_contract(scanners: &[Box<dyn ScanEngine>]) -> Result<()> {
    for scanner in scanners {
        anyhow::ensure!(
            scanner.supports_exact_files(),
            "{} does not support exact source membership",
            scanner.id()
        );
    }
    Ok(())
}

fn exact_file_root(root: &Path, files: &[String]) -> Result<Vec<ScanRoot>> {
    anyhow::ensure!(
        !files.is_empty(),
        "exact source membership must not be empty"
    );
    let scopes = resolve_scan_scopes(root, files)?;
    anyhow::ensure!(
        scopes.iter().all(|scope| !scope.is_directory),
        "exact source membership must contain regular files only"
    );
    Ok(vec![ScanRoot {
        path: root.into(),
        prefix: None,
        files: Some(scopes.into_iter().map(|scope| scope.relative).collect()),
    }])
}

fn scan_root_artifacts(
    root: &ScanRoot,
    scanner: &dyn ScanEngine,
    cancellation: &ScanCancellation,
) -> Result<ScanEngineOutput> {
    match &root.files {
        Some(files) => scanner.scan_exact_files(&root.path, files, cancellation),
        None => scanner.scan_artifacts(&root.path, cancellation),
    }
}

fn ensure_exact_observation_paths(root: &ScanRoot, findings: &[Finding]) -> Result<()> {
    let Some(files) = &root.files else {
        return Ok(());
    };
    for finding in findings {
        anyhow::ensure!(
            files.contains(&finding.file_path),
            "engine observation outside accepted file membership: {}",
            finding.file_path
        );
    }
    Ok(())
}

fn native_engine_stop_disposition(cancellation: &ScanCancellation) -> NativeEngineDisposition {
    match cancellation.disposition() {
        Some(CancellationDisposition::Canceled) => NativeEngineDisposition::Canceled,
        Some(CancellationDisposition::Interrupted) => NativeEngineDisposition::Interrupted,
        None => NativeEngineDisposition::Failed,
    }
}

const MAX_AGGREGATE_SCAN_ERRORS: usize = 3;
const MAX_AGGREGATE_SCAN_ERROR_CHARS: usize = 240;

/// Legacy callers receive only ScanRun, without coverage. They retain findings
/// in a partial ledger run and receive an error rather than a clean result.
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

fn rewrite_scoped_findings(
    root: &ScanRoot,
    scanner: &dyn ScanEngine,
    findings: &mut [Finding],
) -> Result<()> {
    for finding in findings {
        let file_path = prefixed_finding_path(root, &finding.file_path)?;
        scanner.rebind_scoped_finding(finding, file_path);
    }
    Ok(())
}

fn prefixed_finding_path(root: &ScanRoot, path: &str) -> Result<String> {
    let candidate = Path::new(path);
    let relative = if candidate.is_absolute() {
        candidate.strip_prefix(&root.path).with_context(|| {
            format!("Scanner reported a finding outside its scan scope: {path:?}")
        })?
    } else {
        candidate
    };
    let relative = normalized_scan_path(&relative.to_string_lossy())?;
    if candidate.is_absolute() {
        return Ok(root
            .prefix
            .as_deref()
            .map_or_else(|| relative.clone(), |prefix| format!("{prefix}/{relative}")));
    }
    Ok(prefix_relative_finding(root.prefix.as_deref(), relative))
}

fn prefix_relative_finding(prefix: Option<&str>, relative: String) -> String {
    let Some(prefix) = prefix else {
        return relative;
    };
    if relative == prefix || relative.starts_with(&format!("{prefix}/")) {
        relative
    } else {
        format!("{prefix}/{relative}")
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
    index_grounded_codeql_sarif_documents_as_static_evidence(
        &evidence_store,
        workspace.root(),
        &output.codeql_sarif_documents,
    )?;
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
    match error
        .path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
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

        fn scan(&self, _target: &Path, _cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
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
    fn legacy_aggregate_scan_reports_coverage_failure_after_retaining_observations() {
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
        let retained = store.list_findings(10).unwrap();
        assert_eq!(retained.len(), 1);
        let run_id = store.latest_run_id().unwrap().unwrap();
        assert_eq!(
            store.run_status(&run_id).unwrap().as_deref(),
            Some("partial")
        );
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
