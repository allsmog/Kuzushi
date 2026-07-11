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
    let canonical_root = fs::canonicalize(target)
        .with_context(|| format!("Could not resolve {}", target.display()))?;
    let mut canonical_files = Vec::new();
    collect_scan_files_inner(&canonical_root, &canonical_root, &mut canonical_files)?;
    let mut out = logical_scan_paths(target, &canonical_root, canonical_files);
    out.sort();
    out.truncate(MAX_SCAN_FILES);
    Ok(out)
}

fn logical_scan_paths(target: &Path, canonical_root: &Path, paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .filter_map(|path| {
            path.strip_prefix(canonical_root)
                .ok()
                .map(|relative| target.join(relative))
        })
        .collect()
}

fn collect_scan_files_inner(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = crate::bounded_file::read_dir_within(root, dir)
        .with_context(|| format!("Could not read {}", dir.display()))?;
    for entry in entries {
        let Some((path, file_type)) = visible_scan_entry(entry?)? else {
            continue;
        };
        collect_entry(root, path, file_type, out)?;
        if out.len() >= MAX_SCAN_FILES {
            break;
        }
    }
    Ok(())
}

fn visible_scan_entry(entry: fs::DirEntry) -> Result<Option<(PathBuf, fs::FileType)>> {
    let file_type = entry.file_type()?;
    let name = entry.file_name();
    if should_skip_path(&name.to_string_lossy()) || file_type.is_symlink() {
        return Ok(None);
    }
    Ok(Some((entry.path(), file_type)))
}

fn collect_entry(
    root: &Path,
    path: PathBuf,
    file_type: fs::FileType,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    if file_type.is_dir() {
        return collect_scan_files_inner(root, &path, out);
    }
    if scan_file_is_eligible(root, &path, file_type)? {
        out.push(path);
    }
    Ok(())
}

fn scan_file_is_eligible(root: &Path, path: &Path, file_type: fs::FileType) -> Result<bool> {
    if !file_type.is_file() || !is_interesting_source_path(root, path) {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path)?;
    Ok(metadata.file_type().is_file() && metadata.len() <= MAX_FILE_BYTES)
}

pub(super) fn index_files(root: &Path, files: &[PathBuf]) -> Vec<IndexedFile> {
    files
        .iter()
        .filter_map(|path| {
            let text =
                crate::bounded_file::read_utf8_text_within(root, path, MAX_FILE_BYTES as usize)
                    .ok()?;
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
    if relative
        .display()
        .to_string()
        .replace('\\', "/")
        .starts_with(".kuzushi/")
    {
        return false;
    }
    is_interesting_extension(path) || is_interesting_filename(path)
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

    #[cfg(unix)]
    #[test]
    fn scan_and_index_skip_symlinks_outside_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let outside = temp.path().join("outside");
        fs::create_dir_all(target.join("src")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(target.join("src/safe.rs"), "fn safe() {}\n").unwrap();
        fs::write(outside.join("secret.rs"), "OUTSIDE_THREAT_LEAD_TOKEN\n").unwrap();
        symlink(&outside, target.join("linked-dir")).unwrap();
        symlink(outside.join("secret.rs"), target.join("linked.rs")).unwrap();

        let mut files = collect_scan_files(&target).unwrap();
        assert_eq!(files, vec![target.join("src/safe.rs")]);
        files.push(target.join("linked.rs"));
        let indexed = index_files(&target, &files);

        assert_eq!(indexed.len(), 1);
        assert!(!indexed[0].text.contains("OUTSIDE_THREAT_LEAD_TOKEN"));
    }
}
