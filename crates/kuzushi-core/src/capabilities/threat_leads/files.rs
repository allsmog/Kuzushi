use super::patterns::LeadPattern;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_SCAN_FILES: usize = 6000;
const MAX_FILE_BYTES: u64 = 512 * 1024;
const MAX_CANDIDATE_FILES_PER_THREAT: usize = 12;

#[derive(Debug, Clone)]
pub(super) struct IndexedFile {
    pub(super) relative: String,
    text: String,
}

pub(super) fn collect_scan_files(target: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_scan_files_inner(target, target, &mut out)?;
    out.sort();
    out.truncate(MAX_SCAN_FILES);
    Ok(out)
}

fn collect_scan_files_inner(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if should_skip_path(&name) {
            continue;
        }
        collect_entry(root, path, entry.metadata()?, out)?;
        if out.len() >= MAX_SCAN_FILES {
            break;
        }
    }
    Ok(())
}

fn collect_entry(
    root: &Path,
    path: PathBuf,
    metadata: fs::Metadata,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    if metadata.is_dir() {
        collect_scan_files_inner(root, &path, out)?;
    } else if metadata.is_file()
        && metadata.len() <= MAX_FILE_BYTES
        && is_interesting_source_path(root, &path)
    {
        out.push(path);
    }
    Ok(())
}

pub(super) fn index_files(root: &Path, files: &[PathBuf]) -> Vec<IndexedFile> {
    files
        .iter()
        .filter_map(|path| {
            let text = fs::read_to_string(path).ok()?;
            let relative = path.strip_prefix(root).ok()?.display().to_string();
            Some(IndexedFile {
                relative: relative.replace('\\', "/"),
                text,
            })
        })
        .collect()
}

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
    if path.starts_with("docs/examples/") || path.contains("/examples/") {
        "example-code"
    } else if path.starts_with("tests/") || path.contains("/tests/") {
        "test-code"
    } else if path.starts_with("docs/") {
        "documentation"
    } else {
        "production-code"
    }
}

fn is_interesting_source_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    if relative.display().to_string().replace('\\', "/").starts_with(".kuzushi/") {
        return false;
    }
    is_interesting_extension(path) || is_interesting_filename(path)
}

fn is_interesting_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "rs" | "go" | "js" | "ts" | "py" | "rb"
            | "php" | "java" | "sh" | "yml" | "yaml" | "cmake" | "txt" | "md"
    )
}

fn is_interesting_filename(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "CMakeLists.txt" | "configure" | "configure.ac" | "Makefile"))
}

fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".kuzushi" | ".next" | ".turbo" | "coverage" | "dist" | "native"
            | "node_modules" | "target" | "build"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_patterns_match_simple_globs() {
        assert!(path_matches_pattern("docs/examples/ftp-wildcard.c", "docs/*"));
        assert!(path_matches_pattern(
            ".github/workflows/ci.yml",
            ".github/workflows/*.yml"
        ));
        assert!(!path_matches_pattern("src/tool.c", "docs/*"));
    }
}
