use super::*;
use crate::findings::ReviewCapturedFileState;
use crate::workspace::{capture_source_file_from_tree, read_captured_file, ReviewSourceTree};

pub(super) fn selected_paths(input: &Value) -> Result<Vec<String>> {
    let Some(value) = input.get("sourceEvidenceFiles") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .context("sourceEvidenceFiles must be a list of exact paths")?;
    anyhow::ensure!(
        items.len() <= MAX_REVIEW_SUPPORTING_FILES,
        "Select at most 16 supporting files"
    );
    let mut seen = BTreeSet::new();
    let mut paths = Vec::new();
    for item in items {
        let path = item
            .as_str()
            .context("Supporting file paths must be text")?;
        validate_path(path)?;
        anyhow::ensure!(
            seen.insert(path),
            "Supporting files contain a duplicate path"
        );
        paths.push(path.to_string());
    }
    Ok(paths)
}

fn validate_path(path: &str) -> Result<()> {
    use std::path::Component;
    anyhow::ensure!(
        !path.is_empty() && path.len() <= 4096,
        "Supporting paths must contain 1 to 4096 bytes"
    );
    anyhow::ensure!(
        !path.contains('\\') && !path.chars().any(char::is_control),
        "Supporting paths must use forward slashes and contain no control characters"
    );
    let parsed = Path::new(path);
    anyhow::ensure!(
        parsed
            .components()
            .all(|part| matches!(part, Component::Normal(_))),
        "Supporting files must be exact repository-relative paths without traversal"
    );
    anyhow::ensure!(
        parsed.components().collect::<PathBuf>().to_string_lossy() == path,
        "Supporting file paths must be normalized"
    );
    Ok(())
}

pub(super) fn capture(
    ctx: &ToolExecutionContext<'_>,
    finding: &Finding,
    tree: &ReviewSourceTree,
    paths: &[String],
    source: &mut ReviewSourceObservation,
    remaining: &mut usize,
) -> Result<()> {
    if !eligible(source.binding) {
        return Ok(());
    }
    let workspace = ctx
        .workspace
        .context("Supporting source requires a workspace")?;
    let primary = persistence::relative_finding_path(workspace, finding)?;
    for path in paths.iter().filter(|path| **path != primary) {
        anyhow::ensure!(!ctx.is_cancelled(), "Source evidence preparation cancelled");
        let file = capture_file(workspace, tree, path, *remaining)?;
        let text = read_captured_file(workspace, &file)?;
        *remaining = remaining.saturating_sub(text.as_ref().map_or(0, String::len));
        source
            .supporting_files
            .push(ReviewSupportingFile { file, text });
    }
    Ok(())
}

fn capture_file(
    workspace: &WorkspaceTarget,
    tree: &ReviewSourceTree,
    path: &str,
    remaining: usize,
) -> Result<ReviewCapturedFile> {
    if remaining == 0 {
        return Ok(ReviewCapturedFile {
            path: path.into(),
            state: ReviewCapturedFileState::TooLarge,
            blob_hash: None,
            byte_count: None,
        });
    }
    capture_source_file_from_tree(workspace, path, tree, remaining)
}

pub(super) fn validate(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    tree: &ReviewSourceTree,
    source: &ReviewSourceObservation,
    paths: &[String],
) -> Result<usize> {
    let expected = expected_paths(workspace, finding, source.binding, paths)?;
    let actual = source
        .supporting_files
        .iter()
        .map(|file| file.file.path.as_str())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        actual == expected,
        "Frozen supporting-file selection changed"
    );
    let mut included = 0;
    for source in &source.supporting_files {
        persistence::validate_captured_file(tree, &source.file, source.text.as_deref())?;
        included += source.text.as_ref().map_or(0, String::len);
    }
    Ok(included)
}

fn expected_paths<'a>(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    binding: ReviewSourceBinding,
    paths: &'a [String],
) -> Result<Vec<&'a str>> {
    if !eligible(binding) {
        return Ok(Vec::new());
    }
    let primary = persistence::relative_finding_path(workspace, finding)?;
    Ok(paths
        .iter()
        .filter(|path| **path != primary)
        .map(String::as_str)
        .collect())
}

fn eligible(binding: ReviewSourceBinding) -> bool {
    matches!(
        binding,
        ReviewSourceBinding::MatchingRecordedSnapshot | ReviewSourceBinding::ByteLimitReached
    )
}
