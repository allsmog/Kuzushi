use super::*;

pub(in crate::scan) fn detect_codeql_language(
    target: &Path,
    binary: &str,
    cancel: &ScanCancellation,
    scanner: &CodeqlScanner,
) -> Result<String> {
    if let Some(language) = detect_codeql_language_from_heuristics(target) {
        return Ok(language);
    }

    for args in [
        vec![
            "resolve".to_string(),
            "languages".to_string(),
            "--format=json".to_string(),
        ],
        vec!["resolve".to_string(), "languages".to_string()],
    ] {
        if let Some(language) = resolve_language_query(scanner, binary, &args, cancel)? {
            return Ok(language);
        }
    }

    anyhow::bail!("Unable to determine CodeQL language automatically. Pass {{\"language\":\"javascript\"}} or another supported CodeQL language to codeql:scan.");
}

fn resolve_language_query(
    scanner: &CodeqlScanner,
    binary: &str,
    args: &[String],
    cancel: &ScanCancellation,
) -> Result<Option<String>> {
    let output = scanner.run_codeql_raw_output(binary, args, None, cancel)?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_codeql_language_list(&stdout).into_iter().next())
}

pub(in crate::scan) fn detect_all_codeql_languages(
    target: &Path,
    binary: &str,
    cancel: &ScanCancellation,
    scanner: &CodeqlScanner,
) -> Result<Vec<String>> {
    let top_level = top_level_entry_names(target);
    let mut languages = codeql_languages_from_markers(target, CODEQL_ALL_MARKER_RULES);
    push_codeql_language_from_top_level(&top_level, &mut languages);

    if languages.is_empty() {
        languages.push(detect_codeql_language(target, binary, cancel, scanner)?);
    }

    languages.sort();
    languages.dedup();
    Ok(languages)
}

pub(in crate::scan) fn detect_codeql_language_from_heuristics(target: &Path) -> Option<String> {
    codeql_language_from_markers(target, CODEQL_HEURISTIC_MARKER_RULES)
        .or_else(|| codeql_language_from_top_level(&top_level_entry_names(target)))
}
