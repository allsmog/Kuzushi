use super::*;

pub(in crate::scan) fn detect_language_from_database(
    binary: &str,
    db_path: &Path,
    cancel: &ScanCancellation,
) -> Result<Option<String>> {
    let scanner = CodeqlScanner {
        binary: Some(binary.to_string()),
        ..CodeqlScanner::default()
    };
    let args = vec![
        "database".to_string(),
        "resolve".to_string(),
        "languages".to_string(),
        db_path.display().to_string(),
        "--format=json".to_string(),
    ];
    let output = scanner.run_codeql_command(binary, &args, None, cancel)?;
    let stdout =
        String::from_utf8(output.stdout).context("codeql emitted non-UTF8 language JSON")?;
    Ok(parse_codeql_language_list(&stdout).into_iter().next())
}
