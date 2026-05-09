use super::*;

#[derive(Debug, Clone)]
pub(crate) struct CarliniInput {
    pub(crate) model: Option<String>,
    pub(crate) max_findings: usize,
    pub(crate) max_actors: usize,
    pub(crate) runs_per_actor: usize,
    pub(crate) prompt_context: String,
    pub(crate) debug_inline_threats: bool,
    pub(crate) prompt_override: Option<String>,
    pub(crate) attachments_block: Option<String>,
    pub(crate) kb_context: ArtifactKnowledgePromptContext,
}
