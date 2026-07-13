use anyhow::Result;
use kuzushi_mcp_common::tool::ToolRegistry;
use kuzushi_mcp_common::ReadRootCapability;
use std::sync::Arc;

use super::health_handle::ClangdHandle;
use super::tool_types::{
    AstTool, CalleesTool, CallersTool, CompileCommandsTool, DefinitionTool, DiagnosticsTool,
    HealthTool, MacroExpandTool, ReferencesTool, SemanticTokensTool, TypeAtTool,
};

mod file_tools;
mod health_tools;
mod navigation_tools;

pub fn build_registry() -> Result<ToolRegistry> {
    let read = ReadRootCapability::from_environment()?;
    Ok(build_registry_with_capability(read))
}

pub(crate) fn build_registry_with_capability(read: ReadRootCapability) -> ToolRegistry {
    let handle = Arc::new(ClangdHandle::new(read.clone()));
    let registry = ToolRegistry::new();
    let registry = health_tools::register_health_tools(registry, read);
    let registry = navigation_tools::register_navigation_tools(registry, &handle);
    file_tools::register_file_tools(registry, &handle)
}
