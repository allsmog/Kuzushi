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

pub(in crate::scan) fn is_codeql_database_dir(db_path: &Path) -> bool {
    if !regular_directory(db_path) {
        return false;
    }
    if regular_file(&db_path.join("codeql-database.yml")) {
        return true;
    }
    fs::read_dir(db_path)
        .map(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry
                    .file_type()
                    .map(|file_type| file_type.is_dir() && !file_type.is_symlink())
                    .unwrap_or(false)
                    && regular_file(&entry.path().join("codeql-database.yml"))
            })
        })
        .unwrap_or(false)
}

fn regular_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
}

fn regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_file() && !metadata.file_type().is_symlink())
}
