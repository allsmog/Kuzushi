use kuzushi_mcp_common::tool::ToolRegistry;
use std::sync::Arc;

use super::health_handle::ClangdHandle;
use super::tool_types::{
    AstTool, CalleesTool, CallersTool, CompileCommandsTool, DefinitionTool, DiagnosticsTool,
    HealthTool, MacroExpandTool, ReferencesTool, SemanticTokensTool, TypeAtTool,
};

mod file_tools;
mod health_tools;
mod navigation_tools;

pub fn build_registry() -> ToolRegistry {
    let handle = Arc::new(ClangdHandle::default());
    let registry = ToolRegistry::new();
    let registry = health_tools::register_health_tools(registry);
    let registry = navigation_tools::register_navigation_tools(registry, &handle);
    file_tools::register_file_tools(registry, &handle)
}
