use super::*;

pub(in crate::scan) fn detect_codeql_language(
    target: &Path,
    binary: &str,
    cancel: &ScanCancellation,
) -> Result<String> {
    if let Some(language) = detect_codeql_language_from_heuristics(target) {
        return Ok(language);
    }

    let scanner = CodeqlScanner {
        binary: Some(binary.to_string()),
        ..CodeqlScanner::default()
    };
    for args in [
        vec![
            "resolve".to_string(),
            "languages".to_string(),
            "--format=json".to_string(),
        ],
        vec!["resolve".to_string(), "languages".to_string()],
    ] {
        if let Ok(output) = scanner.run_codeql_command(binary, &args, None, cancel) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(language) = parse_codeql_language_list(&stdout).into_iter().next() {
                return Ok(language);
            }
        }
    }

    anyhow::bail!("Unable to determine CodeQL language automatically. Pass {{\"language\":\"javascript\"}} or another supported CodeQL language to codeql:scan.");
}

pub(in crate::scan) fn detect_all_codeql_languages(
    target: &Path,
    binary: &str,
    cancel: &ScanCancellation,
) -> Result<Vec<String>> {
    let top_level = top_level_entry_names(target);
    let mut languages = codeql_languages_from_markers(target, CODEQL_ALL_MARKER_RULES);
    push_codeql_language_from_top_level(&top_level, &mut languages);

    if languages.is_empty() {
        languages.push(detect_codeql_language(target, binary, cancel)?);
    }

    languages.sort();
    languages.dedup();
    Ok(languages)
}

pub(in crate::scan) fn detect_codeql_language_from_heuristics(target: &Path) -> Option<String> {
    codeql_language_from_markers(target, CODEQL_HEURISTIC_MARKER_RULES)
        .or_else(|| codeql_language_from_top_level(&top_level_entry_names(target)))
}
