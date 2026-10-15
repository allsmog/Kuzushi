//! Explicit source capture and human review, with no discovery or provider work.
use crate::content_store::{ContentStore, ObjectKind};
use crate::findings::{finding_stable_fp, Finding, ReviewDecision, ReviewSourceCapture};
use crate::identity::Blake3Hash;
use crate::storage_v3::writer_actor::{DecisionCommand, StorageWriterActor, WriterCommand};
use crate::{ToolExecutionContext, WorkspaceTarget};
use anyhow::{Context, Result};
use serde::Serialize;

const CAPTURE_PREFIX: &str = "review-source:";
const MAX_CAPTURE_BYTES: usize = 32 * 1024;
mod cited_file;
mod manual_dispatch;
pub use cited_file::{read_captured_review_code, MAX_REVIEW_SOURCE_BYTES};
pub use manual_dispatch::execute_source_review_action;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceReviewSourceCapture {
    pub source_ref: String,
    pub source: ReviewSourceCapture,
}

pub fn capture_review_source(
    ctx: &ToolExecutionContext<'_>,
    finding: &Finding,
) -> Result<WorkspaceReviewSourceCapture> {
    capture_review_source_with_limit(ctx, finding, MAX_REVIEW_SOURCE_BYTES)
}

pub fn capture_review_source_with_limit(
    ctx: &ToolExecutionContext<'_>,
    finding: &Finding,
    limit: usize,
) -> Result<WorkspaceReviewSourceCapture> {
    let workspace = ctx
        .workspace
        .context("Source review requires an active target")?;
    let watermark = capture_read_watermark(workspace, finding)?;
    let git = crate::workspace::target_git_metadata(workspace.root());
    let snapshot = super::super::source_snapshot::SourceSnapshot::capture(
        ctx,
        "findings:review-source",
        workspace.root(),
    )?;
    let mut source = captured_source(workspace, finding, snapshot.hashes(), git, watermark)?;
    source.cited_file = Some(cited_file::capture_cited_file(
        workspace,
        finding,
        &source.tree_hash,
        limit,
    )?);
    snapshot.ensure_current(ctx, "findings:review-source", workspace.root())?;
    ensure_git_matches(workspace, &source)?;
    ensure_not_cancelled(ctx)?;
    let object =
        ContentStore::open(workspace.objects_dir())?.put_json(ObjectKind::Blob, &source)?;
    Ok(WorkspaceReviewSourceCapture {
        source_ref: format!("{CAPTURE_PREFIX}{}", object.hash),
        source,
    })
}

fn captured_source(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    hashes: (&str, &str),
    source_git: Option<crate::RunTargetGitMetadata>,
    read_watermark: u64,
) -> Result<ReviewSourceCapture> {
    Ok(ReviewSourceCapture {
        schema_version: 1,
        target_identity: target_identity(workspace),
        finding_id: finding
            .id
            .context("Source review requires a recorded finding")?,
        stable_fp: finding_stable_fp(finding),
        read_watermark,
        snapshot_hash: hashes.0.into(),
        tree_hash: hashes.1.into(),
        source_git,
        captured_at: crate::findings::now_isoish(),
        cited_file: None,
    })
}

fn capture_read_watermark(workspace: &WorkspaceTarget, finding: &Finding) -> Result<u64> {
    let store = crate::FindingStore::open_read_only(workspace.findings_db_path())?;
    store.with_projection_snapshot(|store| {
        let latest = store
            .get_finding_by_fingerprint(&finding.fingerprint)?
            .context("Source review finding is unavailable")?;
        anyhow::ensure!(
            latest.id == finding.id,
            "Finding generation changed; reload before source review"
        );
        Ok(store.projection_meta()?.applied_seq)
    })
}

pub fn read_decision_reviewed_source(
    workspace: &WorkspaceTarget,
    decision_id: i64,
) -> Result<Option<ReviewSourceCapture>> {
    let store = crate::FindingStore::open_read_only(workspace.findings_db_path())?;
    let source = store.reviewed_source_for_decision(decision_id)?;
    if let Some(source) = &source {
        anyhow::ensure!(
            source.target_identity == target_identity(workspace),
            "Recorded source belongs to another target"
        );
    }
    Ok(source)
}

pub fn read_review_source_capture(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    reference: &str,
) -> Result<WorkspaceReviewSourceCapture> {
    let hash = Blake3Hash::new(
        reference
            .strip_prefix(CAPTURE_PREFIX)
            .context("Expected a saved review-source reference")?
            .into(),
    )?;
    let bytes = ContentStore::open(workspace.objects_dir())?
        .get_blob_bounded(&hash, MAX_CAPTURE_BYTES)?
        .context("Source capture is missing or exceeds its read limit")?;
    let source: ReviewSourceCapture = serde_json::from_slice(&bytes)?;
    validate_subject(workspace, finding, &source)?;
    Ok(WorkspaceReviewSourceCapture {
        source_ref: reference.into(),
        source,
    })
}

fn validate_subject(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    source: &ReviewSourceCapture,
) -> Result<()> {
    anyhow::ensure!(
        source.schema_version == 1,
        "Unsupported source capture version"
    );
    anyhow::ensure!(
        source.target_identity == target_identity(workspace),
        "Source capture belongs to another target"
    );
    anyhow::ensure!(
        Some(source.finding_id) == finding.id && source.stable_fp == finding_stable_fp(finding),
        "Source capture belongs to another finding generation"
    );
    Ok(())
}

pub fn decide_on_review_source(
    ctx: &ToolExecutionContext<'_>,
    finding: &Finding,
    decision: &ReviewDecision,
    reference: &str,
) -> Result<i64> {
    anyhow::ensure!(
        decision.author == crate::findings::TriageAuthor::Human,
        "Captured-source decisions require an explicit human review"
    );
    anyhow::ensure!(
        !decision.rationale.trim().is_empty(),
        "Source review requires a reason"
    );
    let workspace = ctx
        .workspace
        .context("Source review requires an active target")?;
    let capture = read_review_source_capture(workspace, finding, reference)?;
    ensure_capture_current(ctx, &capture.source)?;
    let write = super::record_review_decision::review_decision_write(
        finding,
        decision,
        capture.source.finding_id,
        capture.source.read_watermark,
        None,
    );
    let receipt = StorageWriterActor::commit_blocking(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        WriterCommand::Decision(DecisionCommand::ReviewDecisionOnSource {
            decision: write,
            source: capture.source,
        }),
    )?;
    receipt
        .projected_review_decision_id
        .context("Saved decision has no projected id")
}

fn ensure_capture_current(
    ctx: &ToolExecutionContext<'_>,
    source: &ReviewSourceCapture,
) -> Result<()> {
    let workspace = ctx
        .workspace
        .context("Source review requires an active target")?;
    let current = super::super::source_snapshot::inspect_current_source_hash(
        ctx,
        "findings:review-source",
        workspace.root(),
    )?;
    anyhow::ensure!(
        current == source.tree_hash,
        "Source content changed; capture and review it again before deciding"
    );
    ensure_git_matches(workspace, source)?;
    ensure_not_cancelled(ctx)
}

fn ensure_git_matches(workspace: &WorkspaceTarget, source: &ReviewSourceCapture) -> Result<()> {
    anyhow::ensure!(
        crate::workspace::target_git_metadata(workspace.root()) == source.source_git,
        "Git source changed; capture and review it again before deciding"
    );
    Ok(())
}

fn ensure_not_cancelled(ctx: &ToolExecutionContext<'_>) -> Result<()> {
    anyhow::ensure!(!ctx.is_cancelled(), "Source review was canceled");
    Ok(())
}

fn target_identity(workspace: &WorkspaceTarget) -> String {
    crate::workflow_attempts::canonical_target_identity(workspace.root())
}
