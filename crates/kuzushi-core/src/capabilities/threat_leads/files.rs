use super::patterns::LeadPattern;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

const MAX_CANDIDATE_FILES_PER_THREAT: usize = 12;

pub(super) use crate::workspace::inventory::SourcePrefix as IndexedFile;

pub(super) fn candidate_files(
    pattern: &LeadPattern,
    affected_files: &[String],
    files: &[IndexedFile],
) -> Vec<Value> {
    let mut scored = files
        .iter()
        .filter_map(|file| scored_candidate(pattern, affected_files, file))
        .collect::<Vec<_>>();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1["path"].as_str().cmp(&b.1["path"].as_str()))
    });
    scored
        .into_iter()
        .take(MAX_CANDIDATE_FILES_PER_THREAT)
        .map(|(_, value)| value)
        .collect()
}

fn scored_candidate(
    pattern: &LeadPattern,
    affected_files: &[String],
    file: &IndexedFile,
) -> Option<(usize, Value)> {
    let affected_bonus = affected_files
        .iter()
        .any(|pattern| path_matches_pattern(&file.relative, pattern));
    let evidence = evidence_terms(file, pattern);
    let score = evidence.len() + usize::from(affected_bonus);
    (score > 0).then(|| {
        (
            score,
            json!({
                "path": file.relative,
                "classification": classify_path(&file.relative),
                "evidence": evidence,
            }),
        )
    })
}

fn evidence_terms(file: &IndexedFile, pattern: &LeadPattern) -> Vec<Value> {
    let lower = file.text.to_ascii_lowercase();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for term in pattern.source_terms.iter().chain(pattern.sink_terms) {
        if lower.contains(&term.to_ascii_lowercase()) && seen.insert(*term) {
            out.push(json!({"term": term, "kind": evidence_kind(term, pattern)}));
        }
    }
    out
}

fn evidence_kind(term: &str, pattern: &LeadPattern) -> &'static str {
    if pattern.source_terms.contains(&term) {
        "source"
    } else {
        "sink"
    }
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().trim_start_matches("./");
    if pattern.is_empty() {
        return false;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix.trim_end_matches('/'));
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix.trim_end_matches('/'));
    }
    wildcard_path_match(path, pattern)
        || path == pattern
        || path.starts_with(&format!("{pattern}/"))
}

fn wildcard_path_match(path: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return false;
    }
    let mut rest = path;
    for part in pattern.split('*').filter(|part| !part.is_empty()) {
        let Some(index) = rest.find(part) else {
            return false;
        };
        rest = &rest[index + part.len()..];
    }
    true
}

fn classify_path(path: &str) -> &'static str {
    if path_in_section(path, "examples") {
        "example-code"
    } else if path_in_section(path, "tests") {
        "test-code"
    } else if is_documentation(path) {
        "documentation"
    } else {
        "production-code"
    }
}

fn path_in_section(path: &str, section: &str) -> bool {
    path.starts_with(&format!("{section}/")) || path.contains(&format!("/{section}/"))
}

fn is_documentation(path: &str) -> bool {
    path_in_section(path, "docs") || path.ends_with(".md")
}

pub(super) fn is_lead_source_path(relative: &str) -> bool {
    let path = Path::new(relative);
    !path
        .components()
        .any(|part| should_skip_path(&part.as_os_str().to_string_lossy()))
        && (is_interesting_extension(path) || is_interesting_filename(path))
}

fn is_interesting_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "c" | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hpp"
            | "rs"
            | "go"
            | "js"
            | "ts"
            | "py"
            | "rb"
            | "php"
            | "java"
            | "sh"
            | "yml"
            | "yaml"
            | "cmake"
            | "txt"
            | "md"
    )
}

fn is_interesting_filename(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "CMakeLists.txt" | "configure" | "configure.ac" | "Makefile"
            )
        })
}

fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
            | "build"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loose_markdown_is_documentation_while_examples_and_tests_keep_their_role() {
        assert_eq!(classify_path("README.md"), "documentation");
        assert_eq!(classify_path("docs/examples/reader.rs"), "example-code");
        assert_eq!(classify_path("tests/README.md"), "test-code");
        assert_eq!(classify_path("src/reader.rs"), "production-code");
    }

    #[test]
    fn path_patterns_match_simple_globs() {
        assert!(path_matches_pattern(
            "docs/examples/ftp-wildcard.c",
            "docs/*"
        ));
        assert!(path_matches_pattern(
            ".github/workflows/ci.yml",
            ".github/workflows/*.yml"
        ));
        assert!(!path_matches_pattern("src/tool.c", "docs/*"));
    }
}
