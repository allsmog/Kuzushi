use super::prelude::*;
use super::*;

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

pub(crate) fn canonical_repo_root(repo_root: &Path) -> Result<PathBuf> {
    let canonical = repo_root
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", repo_root.display()))?;
    if !canonical.is_dir() {
        bail!("repository root {} is not a directory", canonical.display());
    }
    Ok(canonical)
}
