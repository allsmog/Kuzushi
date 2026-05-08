use std::path::Path;

use crate::artifact_kb::{artifact_knowledge_prompt_context, ArtifactKnowledgePromptContext};
use crate::config::V2Config;
use crate::findings::FindingStore;
use crate::workspace::WorkspaceTarget;

pub struct ToolExecutionContext<'a> {
    pub config: &'a V2Config,
    pub workspace: Option<&'a WorkspaceTarget>,
    pub findings_store: Option<&'a FindingStore>,
}

impl<'a> ToolExecutionContext<'a> {
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
                db_path: target
                    .join(".kuzushi")
                    .join("v2")
                    .join("artifact-kb.sqlite3")
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
