use super::*;
use kuzushi_mcp_common::tool::Tool;
use serde_json::json;

pub(super) fn register_health_tools(registry: ToolRegistry) -> ToolRegistry {
    registry
        .register(
            Tool {
                name: "clang.health".into(),
                description: "Report whether clangd and clang are available, with versions.".into(),
                input_schema: json!({"type": "object", "properties": {}}),
            },
            HealthTool,
        )
        .register(
            Tool {
                name: "clang.compile_commands".into(),
                description: "Locate or generate compile_commands.json for a repo.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath"],
                    "properties": { "repoPath": {"type": "string"} }
                }),
            },
            CompileCommandsTool,
        )
}
