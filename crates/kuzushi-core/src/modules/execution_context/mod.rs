use std::path::{Path, PathBuf};
use std::collections::BTreeSet;

use crate::artifact_kb::{artifact_knowledge_prompt_context, ArtifactKnowledgePromptContext};
use crate::config::V2Config;
use crate::findings::FindingStore;
use crate::run_artifacts::TraceHandle;
use crate::scan::ScanCancellation;
use crate::workspace::WorkspaceTarget;

/// Opaque authorization state for one prepared operation.
///
/// Callers may request interactive authorization, but a request is not a
/// grant. Only `PreparedToolInput` can bind a grant to the prepared tool,
/// canonical input, workspace, descriptor, and registry fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionAuthorization {
    state: AuthorizationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum AuthorizationState {
    #[default]
    Automated,
    InteractiveRequest,
    Bound(AuthorizationGrant),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) enum AuthorizationKind {
    ExplicitHeadless,
    Interactive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizationGrant {
    kind: AuthorizationKind,
    operation_binding: [u8; 32],
    delegated_tools: BTreeSet<String>,
}

impl ExecutionAuthorization {
    /// Request authorization from an interactive confirmation surface.
    /// Dispatch does not accept this request until a `PreparedToolInput`
    /// consumes and binds it.
    pub fn interactive_request() -> Self {
        Self {
            state: AuthorizationState::InteractiveRequest,
        }
    }

    pub(in crate::modules) fn bind(
        kind: AuthorizationKind,
        operation_binding: [u8; 32],
        delegated_tools: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            state: AuthorizationState::Bound(AuthorizationGrant {
                kind,
                operation_binding,
                delegated_tools: delegated_tools.into_iter().collect(),
            }),
        }
    }

    pub(in crate::modules) fn bind_request(
        self,
        operation_binding: [u8; 32],
    ) -> anyhow::Result<Self> {
        self.bind_request_with_delegated_tools(operation_binding, std::iter::empty())
    }

    pub(in crate::modules) fn bind_request_with_delegated_tools(
        self,
        operation_binding: [u8; 32],
        delegated_tools: impl IntoIterator<Item = String>,
    ) -> anyhow::Result<Self> {
        match self.state {
            AuthorizationState::Automated => Ok(Self::default()),
            AuthorizationState::InteractiveRequest => Ok(Self::bind(
                AuthorizationKind::Interactive,
                operation_binding,
                delegated_tools,
            )),
            AuthorizationState::Bound(_) => {
                anyhow::bail!("an authorization grant cannot be rebound to another operation")
            }
        }
    }

    pub(in crate::modules) fn delegated_grant(
        &self,
        tool_name: &str,
        operation_binding: [u8; 32],
    ) -> Option<Self> {
        let AuthorizationState::Bound(grant) = &self.state else {
            return None;
        };
        grant.delegated_tools.contains(tool_name).then(|| {
            Self::bind(grant.kind, operation_binding, std::iter::empty())
        })
    }

    pub(in crate::modules) fn is_explicit_for(&self, operation_binding: &[u8; 32]) -> bool {
        matches!(
            &self.state,
            AuthorizationState::Bound(grant)
                if &grant.operation_binding == operation_binding
        )
    }

    pub(in crate::modules) fn is_interactive_for(
        &self,
        operation_binding: &[u8; 32],
    ) -> bool {
        matches!(
            &self.state,
            AuthorizationState::Bound(AuthorizationGrant {
                kind: AuthorizationKind::Interactive,
                operation_binding: binding,
                ..
            }) if binding == operation_binding
        )
    }
}

pub struct ToolExecutionContext<'a> {
    pub config: &'a V2Config,
    pub workspace: Option<&'a WorkspaceTarget>,
    pub findings_store: Option<&'a FindingStore>,
    /// Optional handle for emitting reasoning trace steps. `None` in non-shell
    /// contexts (kuzushi run, evals) — producers should treat absence as a no-op.
    pub trace: Option<&'a TraceHandle>,
    /// Shared cancellation capability for scanners, bridges, and nested tools.
    pub cancellation: Option<&'a ScanCancellation>,
    /// Authorization proof consumed by descriptor policy at dispatch.
    pub authorization: ExecutionAuthorization,
}

impl<'a> ToolExecutionContext<'a> {
    pub fn run_id(&self) -> Option<String> {
        self.run_artifact_location().map(|(_, run_id)| run_id)
    }

    pub fn ensure_active(&self) -> anyhow::Result<()> {
        if self
            .cancellation
            .is_some_and(ScanCancellation::is_cancelled)
        {
            anyhow::bail!("tool execution was cancelled")
        }
        Ok(())
    }

    pub fn with_cancellation<T>(
        &self,
        operation: impl FnOnce(&ScanCancellation) -> T,
    ) -> T {
        if let Some(cancellation) = self.cancellation {
            return operation(cancellation);
        }
        operation(&ScanCancellation::default())
    }

    pub fn run_artifact_location(&self) -> Option<(PathBuf, String)> {
        self.trace.and_then(|trace| trace.run_artifact_location())
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
cancellation: None,
authorization: Default::default(),
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
cancellation: None,
authorization: Default::default(),
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
cancellation: None,
authorization: Default::default(),
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

    #[test]
    fn shared_cancellation_is_visible_to_nested_operations() {
        let config = V2Config::default();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: Some(&cancellation),
            authorization: Default::default(),
        };

        assert!(ctx.ensure_active().unwrap_err().to_string().contains("cancelled"));
        assert!(ctx.with_cancellation(ScanCancellation::is_cancelled));
    }
}
