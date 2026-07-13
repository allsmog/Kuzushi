use kuzushi_mcp_common::ReadRootCapability;
use std::sync::Arc;

use super::health_handle::ClangdHandle;

pub(crate) struct HealthTool;
pub(crate) struct CompileCommandsTool {
    pub(crate) read_capability: ReadRootCapability,
}

pub(crate) struct DefinitionTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct ReferencesTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct TypeAtTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct AstTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct CallersTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct CalleesTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct MacroExpandTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct SemanticTokensTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct DiagnosticsTool {
    pub(crate) handle: Arc<ClangdHandle>,
}
