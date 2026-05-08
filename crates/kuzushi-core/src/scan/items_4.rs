use super::prelude::*;
use super::*;

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

pub(crate) fn remove_stale_codeql_database(db_path: &Path) -> Result<()> {
    if !db_path.exists() {
        return Ok(());
    }
    if db_path.is_dir() {
        fs::remove_dir_all(db_path)
            .with_context(|| format!("codeql: could not remove stale {}", db_path.display()))
    } else {
        fs::remove_file(db_path)
            .with_context(|| format!("codeql: could not remove stale {}", db_path.display()))
    }
}

pub(crate) fn create_codeql_database_parent(db_path: &Path) -> Result<()> {
    let Some(parent) = db_path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent)
        .with_context(|| format!("codeql: could not create {}", parent.display()))
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
