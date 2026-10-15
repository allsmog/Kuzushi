use super::*;

pub(in crate::scan) fn resolve_codeql_suite(
    configured_suite: Option<&str>,
    language: &str,
) -> Result<String> {
    let Some(suite) = configured_suite.and_then(non_empty_string) else {
        return Ok(format!(
            "codeql/{language}-queries:codeql-suites/{language}-security-and-quality.qls"
        ));
    };
    if suite.contains('/') || suite.contains(':') || suite.contains('.') {
        return Ok(suite.to_string());
    }
    Ok(format!(
        "codeql/{language}-queries:codeql-suites/{suite}.qls"
    ))
}

pub(in crate::scan) fn resolve_repo_path(repo_root: &Path, candidate: &str) -> PathBuf {
    let path = PathBuf::from(candidate);
    if path.is_absolute() {
        return path;
    }
    repo_root.join(path)
}
