use std::path::{Path, PathBuf};

use crate::artifact_kb::{artifact_knowledge_prompt_context, ArtifactKnowledgePromptContext};
use crate::config::V2Config;
use crate::findings::FindingStore;
use crate::run_artifacts::TraceHandle;
use crate::workspace::WorkspaceTarget;

pub struct ToolExecutionContext<'a> {
    pub config: &'a V2Config,
    pub workspace: Option<&'a WorkspaceTarget>,
    pub findings_store: Option<&'a FindingStore>,
    /// Optional handle for emitting reasoning trace steps. `None` in non-shell
    /// contexts (kuzushi run, evals) — producers should treat absence as a no-op.
    pub trace: Option<&'a TraceHandle>,
}

impl<'a> ToolExecutionContext<'a> {
    pub fn run_id(&self) -> Option<String> {
        self.run_artifact_location().map(|(_, run_id)| run_id)
    }

    pub fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        self.trace
            .and_then(|trace| trace.run_artifact_location())
    }

    pub fn artifact_knowledge_context(
        &self,
        target: &Path,
        query: &str,
        limit: usize,
    ) -> ArtifactKnowledgePromptContext {
        if let Some(workspace) = self
            .workspace
            .filter(|workspace| workspace.root() == target)
        {
            return artifact_knowledge_prompt_context(workspace, query, limit);
        }

        match WorkspaceTarget::new(target) {
            Ok(workspace) => artifact_knowledge_prompt_context(&workspace, query, limit),
            Err(error) => ArtifactKnowledgePromptContext {
                db_path: crate::workspace::workspace_artifact_kb_db_path(target)
                    .display()
                    .to_string(),
                missing_db: false,
                query: query.to_string(),
                status: format!("unavailable: {error}"),
                snippets: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;

    #[test]
    fn traced_context_exposes_run_artifact_location() {
        let tmp = tempfile::tempdir().unwrap();
        let config = V2Config::default();
        let trace = TraceHandle::jsonl(tmp.path(), "run-context");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: Some(&trace),
        };

        let (target, run_id) = ctx.run_artifact_location().unwrap();

        assert_eq!(target, tmp.path());
        assert_eq!(run_id, "run-context");
        assert_eq!(ctx.run_id().as_deref(), Some("run-context"));
    }

    #[test]
    fn untraced_context_has_no_run_id() {
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };

        assert!(ctx.run_id().is_none());
        assert!(ctx.run_artifact_location().is_none());
    }

    #[test]
    fn unavailable_artifact_knowledge_context_uses_workspace_kb_path() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("missing-target");
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };

        let context = ctx.artifact_knowledge_context(&target, "anything", 3);

        assert_eq!(
            context.db_path,
            crate::workspace::workspace_artifact_kb_db_path(&target)
                .display()
                .to_string()
        );
        assert!(context.status.contains("unavailable:"));
        assert!(context.snippets.is_empty());
    }
}
