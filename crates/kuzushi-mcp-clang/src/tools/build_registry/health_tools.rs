use super::*;
use kuzushi_mcp_common::tool::Tool;
use serde_json::json;

pub(super) fn register_health_tools(
    registry: ToolRegistry,
    read_capability: ReadRootCapability,
) -> ToolRegistry {
    registry
        .register(
            Tool {
                name: "clang.health".into(),
                description: "Report whether clangd and clang are available, with versions.".into(),
                input_schema: json!({"type": "object", "additionalProperties": false, "properties": {}}),
            },
            HealthTool,
        )
        .register(
            Tool {
                name: "clang.compile_commands".into(),
                description: "Locate and parse a bounded compile_commands.json in a granted repo. This read-only MCP tool never runs CMake, Make, Bear, or intercept-build.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath"],
                    "additionalProperties": false,
                    "properties": {
                        "repoPath": {"type": "string", "minLength": 1, "maxLength": 16384},
                        "compileCommandsPath": {"type":"string","minLength":1,"maxLength":16384,"description":"Optional compiler database within granted read roots; relative paths use repoPath."}
                    }
                }),
            },
            CompileCommandsTool {
                read_capability,
            },
        )
}
