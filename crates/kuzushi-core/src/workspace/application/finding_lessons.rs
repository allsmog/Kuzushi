//! Shell lesson writes use the same descriptor and prepared dispatch as headless use.
use super::*;

pub fn load_finding_lessons(
    workspace: &WorkspaceTarget,
    offset: usize,
) -> Result<crate::findings::FindingLessonPage> {
    if !workspace.findings_db_path().exists() {
        return Ok(crate::findings::FindingLessonPage {
            rows: vec![],
            offset,
            has_more: false,
        });
    }
    crate::FindingStore::open_read_only(workspace.findings_db_path())?.finding_lessons(50, offset)
}

pub fn execute_lesson_action(
    workspace: &WorkspaceTarget,
    config: &crate::V2Config,
    name: &str,
    input: serde_json::Value,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        matches!(
            name,
            "findings:lesson-save" | "findings:lesson-review" | "threat-model:reuse-lessons"
        ),
        "Unsupported lesson action"
    );
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
    let prepared = registry
        .prepare_dispatch_input(name, input, &ctx, None)?
        .authorize_interactive_with_delegated_tools(&[]);
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}
/// Read the exact historical source bundle retained for a lesson draft.
pub fn read_lesson_source_evidence(root: &Path, reference: &str) -> Result<serde_json::Value> {
    crate::capabilities::finding_lessons::read_source_evidence(root, reference)
}
