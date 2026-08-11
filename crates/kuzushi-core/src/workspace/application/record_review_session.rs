use crate::storage_v3::writer_actor::{
    DecisionCommand, ReviewSessionWrite, StorageWriterActor, WriterCommand,
};
use crate::workspace::WorkspaceTarget;
use anyhow::Result;

/// Appends one prospective review session and returns the committed sequence.
///
/// Sessions ride the decision lane so a session and the verdict that follows it
/// stay in causal order in the log.
pub fn record_review_session_started(
    workspace: &WorkspaceTarget,
    write: ReviewSessionWrite,
) -> Result<u64> {
    let receipt = StorageWriterActor::commit_blocking(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        WriterCommand::Decision(DecisionCommand::ReviewSessionStarted(write)),
    )?;
    Ok(receipt.committed_seq)
}
