use super::*;
use std::collections::BTreeMap;

pub(super) struct RecordedSources<'a> {
    workspace: &'a WorkspaceTarget,
    trees: BTreeMap<String, Option<String>>,
}

impl<'a> RecordedSources<'a> {
    pub(super) fn new(workspace: &'a WorkspaceTarget) -> Self {
        Self {
            workspace,
            trees: BTreeMap::new(),
        }
    }

    pub(super) fn binding(&mut self, finding: &Finding, tree: &str) -> ReviewSourceBinding {
        match self.tree_for(finding) {
            Some(recorded) if recorded == tree => ReviewSourceBinding::MatchingRecordedSnapshot,
            Some(_) => ReviewSourceBinding::RecordedSourceChanged,
            None => ReviewSourceBinding::RecordedSourceUnavailable,
        }
    }

    fn tree_for(&mut self, finding: &Finding) -> Option<&str> {
        let run = finding.scan_id.as_ref()?;
        let workspace = self.workspace;
        self.trees
            .entry(run.clone())
            .or_insert_with(|| recorded_tree(workspace, run))
            .as_deref()
    }
}

fn recorded_tree(workspace: &WorkspaceTarget, run: &str) -> Option<String> {
    use crate::workflow_attempts::{
        canonical_target_identity, referenced_run_content_identity, TargetContentIdentity,
    };
    let summary =
        crate::run_artifacts::load_run_summary_without_repair(workspace.root(), run).ok()?;
    if canonical_target_identity(&summary.target) != canonical_target_identity(workspace.root()) {
        return None;
    }
    match referenced_run_content_identity(workspace.root(), &[run.into()]) {
        TargetContentIdentity::IndexedSnapshot {
            tree_hash: Some(tree),
            ..
        } => Some(tree.to_string()),
        _ => None,
    }
}
