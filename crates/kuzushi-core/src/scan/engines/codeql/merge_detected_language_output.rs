use super::*;
use crate::scan::domain::scanner_binary_available;

pub(crate) fn merge_detected_language_output(
    result: Result<ScanEngineOutput>,
    language: &str,
    cancel: &ScanCancellation,
    output: &mut ScanEngineOutput,
    errors: &mut Vec<String>,
) -> Result<()> {
    match result {
        Ok(language_output) => merge_scan_engine_output(output, language_output),
        Err(error) if cancel.is_cancelled() => Err(error),
        Err(error) => record_detected_language_error(errors, language, error),
    }
}

pub(crate) fn merge_scan_engine_output(
    output: &mut ScanEngineOutput,
    mut language_output: ScanEngineOutput,
) -> Result<()> {
    output.findings.append(&mut language_output.findings);
    output
        .codeql_sarif_documents
        .append(&mut language_output.codeql_sarif_documents);
    Ok(())
}

pub(crate) fn record_detected_language_error(
    errors: &mut Vec<String>,
    language: &str,
    error: anyhow::Error,
) -> Result<()> {
    errors.push(format!("{language}: {error}"));
    Ok(())
}

impl ScanEngine for CodeqlScanner {
    fn id(&self) -> &'static str {
        "codeql"
    }

    fn preflight(&self) -> Result<()> {
        let binary = resolve_codeql_binary(self.binary.as_deref())?;
        if scanner_binary_available(&binary) {
            return Ok(());
        }
        anyhow::bail!(
            "codeql: could not find CodeQL CLI {:?}. Install it with `gh extension install github/gh-codeql && gh codeql install-stub`, download it from https://github.com/github/codeql-cli-binaries/releases, or pass {{\"binary\":\"/path/to/codeql\"}}. Next: run codeql:scan {{\"binary\":\"/path/to/codeql\",\"language\":\"javascript\"}} or task block codeql.",
            binary
        )
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, cancellation)
    }

    fn scan_artifacts(
        &self,
        target: &Path,
        cancellation: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        self.scan_with_artifacts(target, cancellation)
    }
}

pub(crate) fn validate_codeql_scan_target(target: &Path, cancel: &ScanCancellation) -> Result<()> {
    if cancel.is_cancelled() {
        anyhow::bail!("codeql scan cancelled");
    }
    if !target.is_dir() {
        anyhow::bail!("codeql: target is not a directory: {}", target.display());
    }
    Ok(())
}

pub(crate) fn codeql_repo_name(target: &Path) -> String {
    target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo")
        .to_string()
}

pub(crate) fn codeql_multi_language_output(
    output: ScanEngineOutput,
    errors: Vec<String>,
) -> Result<ScanEngineOutput> {
    if output.findings.is_empty() && !errors.is_empty() {
        anyhow::bail!(
            "codeql: all language analyses failed: {}",
            errors.join("; ")
        );
    }
    Ok(output)
}

#[derive(Debug, Clone)]
pub(crate) struct CodeqlDatabase {
    pub(crate) db_path: PathBuf,
    pub(crate) language: String,
}
