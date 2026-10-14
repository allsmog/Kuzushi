//! Relationships use the same prepared module boundary in shell and headless use.
use super::*;
use crate::findings::{FindingRelationship, FindingRelationshipPage, FindingRelationshipState};

pub fn load_finding_relationships(
    workspace: &WorkspaceTarget,
    finding_id: Option<i64>,
    offset: usize,
) -> Result<FindingRelationshipPage> {
    let store = crate::FindingStore::open_read_only(workspace.findings_db_path())?;
    store.finding_relationships(finding_id, 50, offset)
}

#[derive(Debug, Clone)]
pub struct FindingRelationshipReviewRequest {
    pub id: String,
    pub state: FindingRelationshipState,
    pub note: String,
    pub expected_revision: u64,
}

#[derive(Debug, Clone)]
pub struct FindingRelationshipBatchReviewRequest {
    pub relationships: Vec<FindingRelationship>,
    pub state: FindingRelationshipState,
    pub note: String,
}

pub fn record_finding_relationship_batch_review(
    workspace: &WorkspaceTarget,
    config: &crate::V2Config,
    request: &FindingRelationshipBatchReviewRequest,
) -> Result<Vec<FindingRelationship>> {
    let input = serde_json::json!({"relationships":request.relationships,"state":request.state,"note":request.note});
    let output = execute_review(workspace, config, "findings:relationship-batch", input)?;
    serde_json::from_value(output["data"]["records"].clone())
        .context("relationship batch produced malformed output")
}

pub fn record_finding_relationship_review(
    workspace: &WorkspaceTarget,
    config: &crate::V2Config,
    request: &FindingRelationshipReviewRequest,
) -> Result<FindingRelationship> {
    let input = serde_json::json!({"id":request.id,"state":request.state,"note":request.note,"expectedRevision":request.expected_revision});
    let output = execute_review(workspace, config, "findings:relationship", input)?;
    serde_json::from_value(output["data"].clone())
        .context("relationship review produced malformed output")
}

fn execute_review(
    workspace: &WorkspaceTarget,
    config: &crate::V2Config,
    name: &str,
    input: serde_json::Value,
) -> Result<serde_json::Value> {
    let store = crate::FindingStore::open(workspace.findings_db_path())?;
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let ctx = crate::ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry.prepare_dispatch_input(name, input, &ctx, None)?;
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}
