use super::*;
use crate::workspace::source_snapshot::SourceSnapshot;
use crate::workspace::{capture_cited_file_from_tree, read_captured_file, ReviewSourceTree};

pub(crate) fn freeze(
    input: &mut Value,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if !validate_policy(input)? {
        return Ok(());
    }
    let root = ctx
        .workspace
        .context("Source evidence requires a workspace")?
        .root();
    let snapshot = SourceSnapshot::capture(ctx, "campaign:review-study", root)?;
    if let Some(document) = inspect(root, input, findings)? {
        anyhow::ensure!(
            document.tree_hash == snapshot.hashes().1,
            "Frozen Review source changed; prepare a new draft"
        );
        return Ok(());
    }
    let document = capture_document(input, findings, ctx, &snapshot)?;
    snapshot.ensure_current(ctx, "campaign:review-study", root)?;
    input["sourceEvidenceRef"] = json!(persistence::save(root, &document)?);
    Ok(())
}

fn capture_document(
    input: &Value,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
    snapshot: &SourceSnapshot,
) -> Result<ReviewSourceEvidence> {
    let workspace = ctx
        .workspace
        .context("Source evidence requires a workspace")?;
    let max_bytes = byte_limit(input)?;
    let mut remaining = max_bytes;
    let mut observations = Vec::new();
    let tree = ReviewSourceTree::load(workspace, snapshot.hashes().1)?;
    let mut recorded = RecordedSources::new(workspace);
    for finding in findings {
        anyhow::ensure!(!ctx.is_cancelled(), "Source evidence preparation cancelled");
        anyhow::ensure!(
            finding.file_path.len() <= 4096,
            "Cited source path exceeds the 4096-byte receipt limit"
        );
        let binding = recorded.binding(finding, snapshot.hashes().1);
        let source = capture_observation(workspace, finding, &tree, binding, remaining)?;
        remaining = remaining.saturating_sub(source.text.as_ref().map_or(0, String::len));
        observations.push(source);
    }
    Ok(ReviewSourceEvidence {
        schema_version: 1,
        target: workspace
            .root()
            .canonicalize()?
            .to_string_lossy()
            .into_owned(),
        snapshot_hash: snapshot.hashes().0.into(),
        tree_hash: snapshot.hashes().1.into(),
        max_bytes,
        included_bytes: max_bytes - remaining,
        observations,
    })
}

fn capture_observation(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    tree: &ReviewSourceTree,
    binding: ReviewSourceBinding,
    remaining: usize,
) -> Result<ReviewSourceObservation> {
    let mut source = ReviewSourceObservation {
        generation_id: finding
            .id
            .context("Source evidence needs an exact finding generation")?,
        path: finding.file_path.clone(),
        binding,
        file: None,
        text: None,
    };
    if binding != ReviewSourceBinding::MatchingRecordedSnapshot {
        return Ok(source);
    }
    if remaining == 0 {
        source.binding = ReviewSourceBinding::ByteLimitReached;
        return Ok(source);
    }
    let file = capture_cited_file_from_tree(workspace, finding, tree, remaining)?;
    source.text = read_captured_file(workspace, &file)?;
    source.path = file.path.clone();
    source.file = Some(file);
    Ok(source)
}
