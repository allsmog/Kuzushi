use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::static_evidence::static_content_hash;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceSpan {
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet: String,
    pub content_hash: String,
}

pub fn extract_source_span(
    repo_root: impl AsRef<Path>,
    file_path: impl AsRef<Path>,
    start_line: u32,
    end_line: u32,
) -> Result<SourceSpan> {
    if start_line == 0 || end_line == 0 {
        bail!("source span line numbers are 1-based and must be greater than zero");
    }
    if start_line > end_line {
        bail!("source span start line {start_line} is after end line {end_line}");
    }

    let repo_root = canonical_repo_root(repo_root.as_ref())?;
    let requested_path = resolve_requested_path(&repo_root, file_path.as_ref())?;
    let canonical_file = requested_path
        .canonicalize()
        .with_context(|| format!("source file {} does not exist", requested_path.display()))?;

    if !canonical_file.starts_with(&repo_root) {
        bail!(
            "source span path {} resolves outside repository root {}",
            canonical_file.display(),
            repo_root.display()
        );
    }
    if !canonical_file.is_file() {
        bail!(
            "source span path {} is not a file",
            canonical_file.display()
        );
    }

    let bytes = fs::read(&canonical_file)
        .with_context(|| format!("failed to read source file {}", canonical_file.display()))?;
    if looks_binaryish(&bytes) {
        bail!(
            "source file {} appears binary or non-text and cannot be cited",
            display_repo_relative(&repo_root, &canonical_file)
        );
    }

    let text = std::str::from_utf8(&bytes).with_context(|| {
        format!(
            "source file {} is not valid UTF-8 text",
            display_repo_relative(&repo_root, &canonical_file)
        )
    })?;
    let lines: Vec<&str> = text.lines().collect();
    let line_count = u32::try_from(lines.len()).unwrap_or(u32::MAX);
    if end_line > line_count {
        bail!(
            "source span end line {end_line} exceeds file line count {line_count} for {}",
            display_repo_relative(&repo_root, &canonical_file)
        );
    }

    let start_index = usize::try_from(start_line - 1).unwrap_or(usize::MAX);
    let end_index = usize::try_from(end_line).unwrap_or(usize::MAX);
    let snippet = lines[start_index..end_index].join("\n");
    let content_hash = static_content_hash(&snippet);
    Ok(SourceSpan {
        file_path: display_repo_relative(&repo_root, &canonical_file),
        start_line,
        end_line,
        snippet,
        content_hash,
    })
}

fn canonical_repo_root(repo_root: &Path) -> Result<PathBuf> {
    let canonical = repo_root
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", repo_root.display()))?;
    if !canonical.is_dir() {
        bail!("repository root {} is not a directory", canonical.display());
    }
    Ok(canonical)
}

fn resolve_requested_path(repo_root: &Path, file_path: &Path) -> Result<PathBuf> {
    if file_path.as_os_str().is_empty() {
        bail!("source span file path is required");
    }
    if file_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!(
            "source span path {} must not contain parent traversal",
            file_path.display()
        );
    }
    Ok(if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        repo_root.join(file_path)
    })
}

fn display_repo_relative(repo_root: &Path, file_path: &Path) -> String {
    file_path
        .strip_prefix(repo_root)
        .unwrap_or(file_path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn looks_binaryish(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.contains(&0) {
        return true;
    }
    let control_count = bytes
        .iter()
        .filter(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0c))
        .count();
    control_count * 10 > bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_span_extracts_repo_relative_snippet_and_hash() {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("routes.ts"),
            "import express from 'express'\napp.get('/a', handler)\napp.post('/b', save)\n",
        )
        .unwrap();

        let span = extract_source_span(temp.path(), "src/routes.ts", 2, 3).unwrap();

        assert_eq!(span.file_path, "src/routes.ts");
        assert_eq!(span.start_line, 2);
        assert_eq!(span.end_line, 3);
        assert_eq!(span.snippet, "app.get('/a', handler)\napp.post('/b', save)");
        assert_eq!(span.content_hash, static_content_hash(&span.snippet));
    }

    #[test]
    fn source_span_accepts_absolute_paths_under_repo_root() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("main.rs");
        fs::write(&file, "fn main() {}\n").unwrap();

        let span = extract_source_span(temp.path(), &file, 1, 1).unwrap();

        assert_eq!(span.file_path, "main.rs");
        assert_eq!(span.snippet, "fn main() {}");
    }

    #[test]
    fn source_span_rejects_missing_files() {
        let temp = tempfile::tempdir().unwrap();

        let error = extract_source_span(temp.path(), "missing.rs", 1, 1)
            .unwrap_err()
            .to_string();

        assert!(error.contains("does not exist"), "{error}");
    }

    #[test]
    fn source_span_rejects_binaryish_files() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("blob.bin"), b"abc\0def").unwrap();

        let error = extract_source_span(temp.path(), "blob.bin", 1, 1)
            .unwrap_err()
            .to_string();

        assert!(error.contains("binary or non-text"), "{error}");
    }

    #[test]
    fn source_span_rejects_bad_line_ranges() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("app.py"), "one\ntwo\n").unwrap();

        let zero = extract_source_span(temp.path(), "app.py", 0, 1)
            .unwrap_err()
            .to_string();
        let reversed = extract_source_span(temp.path(), "app.py", 2, 1)
            .unwrap_err()
            .to_string();
        let too_long = extract_source_span(temp.path(), "app.py", 1, 3)
            .unwrap_err()
            .to_string();

        assert!(zero.contains("1-based"), "{zero}");
        assert!(reversed.contains("after end line"), "{reversed}");
        assert!(too_long.contains("exceeds file line count"), "{too_long}");
    }

    #[test]
    fn source_span_rejects_traversal_and_out_of_repo_paths() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "secret\n").unwrap();

        let traversal = extract_source_span(temp.path(), "../outside.rs", 1, 1)
            .unwrap_err()
            .to_string();
        let outside = extract_source_span(temp.path(), outside.path(), 1, 1)
            .unwrap_err()
            .to_string();

        assert!(traversal.contains("parent traversal"), "{traversal}");
        assert!(outside.contains("outside repository root"), "{outside}");
    }
}
