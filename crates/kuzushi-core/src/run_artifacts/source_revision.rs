//! Read-only source identity carried by persisted run artifacts.
use super::RunTargetGitMetadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSourceRevision {
    pub git: Option<RunTargetGitMetadata>,
    /// Hash of the indexed source content, not a claim of repository coverage.
    pub tree_hash: Option<String>,
    pub snapshot_hash: Option<String>,
}

impl RunSourceRevision {
    /// Missing legacy content hashes remain unknown, even with a clean SHA.
    pub fn from_artifacts(summary: Option<&Value>, result: Option<&Value>) -> Self {
        let git = summary.and_then(|value| value.get("targetGit").or_else(|| value.get("target_git")))
            .and_then(|value| serde_json::from_value(value.clone()).ok());
        Self {
            git,
            tree_hash: result.and_then(|value| content_hash(value, "/data/treeHash")),
            snapshot_hash: result.and_then(|value| content_hash(value, "/data/snapshotHash")),
        }
    }

    pub fn label(&self) -> String {
        let content = self.tree_hash.as_deref().unwrap_or("unknown");
        let Some(git) = &self.git else { return format!("Git revision unknown · content:{content}"); };
        let branch = git.branch.as_deref().unwrap_or("detached");
        let state = if git.dirty { "dirty" } else { "clean" };
        format!("{} ({branch}, {state}) · content:{content}", git.sha)
    }
}

fn content_hash(value: &Value, pointer: &str) -> Option<String> {
    let hash = value.pointer(pointer)?.as_str()?;
    (hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())).then(|| hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn same_sha_with_different_dirty_content_has_distinct_source_identity() {
        let summary = json!({"targetGit": {"sha": "same-sha", "branch": "main", "dirty": true}});
        let before = json!({"data": {"treeHash": "a".repeat(64)}});
        let after = json!({"data": {"treeHash": "b".repeat(64)}});
        let left = RunSourceRevision::from_artifacts(Some(&summary), Some(&before));
        let right = RunSourceRevision::from_artifacts(Some(&summary), Some(&after));
        assert_eq!(left.git, right.git);
        assert_ne!(left, right);
        assert_ne!(left.label(), right.label());
    }

    #[test]
    fn missing_or_malformed_hashes_do_not_imply_an_exact_source_revision() {
        let malformed = json!({"data": {"treeHash": "", "snapshotHash": "not-a-hash"}});
        let revision = RunSourceRevision::from_artifacts(None, Some(&malformed));
        assert_eq!(revision, RunSourceRevision::default());
        assert!(revision.label().contains("content:unknown"));
    }
}
