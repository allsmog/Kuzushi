use super::*;

pub(in crate::scan) fn codeql_languages_from_markers(
    target: &Path,
    rules: &[CodeqlMarkerRule],
) -> Vec<String> {
    rules
        .iter()
        .filter(|rule| has_any_codeql_marker(target, rule.markers))
        .map(|rule| rule.language.to_string())
        .collect()
}

pub(in crate::scan) fn codeql_language_from_markers(
    target: &Path,
    rules: &[CodeqlMarkerRule],
) -> Option<String> {
    rules
        .iter()
        .find(|rule| has_any_codeql_marker(target, rule.markers))
        .map(|rule| rule.language.to_string())
}

pub(in crate::scan) fn has_any_codeql_marker(target: &Path, markers: &[&str]) -> bool {
    markers.iter().any(|marker| target.join(marker).exists())
}

pub(in crate::scan) fn top_level_entry_names(target: &Path) -> Vec<String> {
    fs::read_dir(target)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(in crate::scan) fn push_codeql_language_from_top_level(
    top_level: &[String],
    languages: &mut Vec<String>,
) {
    if codeql_top_level_has_csharp(top_level)
        && !languages.iter().any(|language| language == "csharp")
    {
        languages.push("csharp".to_string());
    }
}

pub(in crate::scan) fn codeql_language_from_top_level(top_level: &[String]) -> Option<String> {
    if codeql_top_level_has_csharp(top_level) {
        return Some("csharp".to_string());
    }
    top_level_source_language(top_level)
}

pub(in crate::scan) fn codeql_top_level_has_csharp(top_level: &[String]) -> bool {
    top_level
        .iter()
        .any(|name| name.ends_with(".sln") || name.ends_with(".csproj"))
}

pub(in crate::scan) fn top_level_source_language(top_level: &[String]) -> Option<String> {
    top_level
        .iter()
        .find_map(|name| codeql_language_for_source_file(name))
}

pub(in crate::scan) fn codeql_language_for_source_file(name: &str) -> Option<String> {
    if name.ends_with(".go") {
        return Some("go".to_string());
    }
    if name.ends_with(".py") {
        return Some("python".to_string());
    }
    None
}
