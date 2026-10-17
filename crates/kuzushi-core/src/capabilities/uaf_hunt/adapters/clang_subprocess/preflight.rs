use anyhow::{Context, Result};
use serde_json::Value;

pub(super) fn require_compiler_configuration(list: &Value) -> Result<()> {
    let tools = list["tools"]
        .as_array()
        .context("mcp-clang did not return a tool list")?;
    for name in [
        "clang.definition",
        "clang.references",
        "clang.type_at",
        "clang.callers",
        "clang.callees",
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .with_context(|| format!("mcp-clang is missing {name}; rebuild the matching helper"))?;
        anyhow::ensure!(tool["inputSchema"]["properties"]["compileCommandsPath"]["type"] == "string",
            "mcp-clang {name} cannot bind the selected compiler database; rebuild the matching helper");
    }
    Ok(())
}

pub(super) fn require_ready_helper(health: &Value) -> Result<()> {
    let missing = health.get("missing").and_then(Value::as_array);
    anyhow::ensure!(health["ready"] == true && missing.is_some_and(Vec::is_empty),
        "mcp-clang is not ready for source-only navigation; check clang, clangd and the read-only process sandbox. Missing: {}",
        health.get("missing").unwrap_or(&Value::Null));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_or_legacy_navigation_is_refused_without_a_fallback() {
        assert!(require_compiler_configuration(&json!({})).is_err());
        assert!(require_compiler_configuration(&json!({"tools":[]})).is_err());
        let tools = ["clang.definition", "clang.references", "clang.type_at", "clang.callers", "clang.callees"]
            .map(|name| json!({"name":name,"inputSchema":{"properties":{"compileCommandsPath":{"type":"string"}}}}));
        let mut list = json!({"tools":tools});
        require_compiler_configuration(&list).unwrap();
        list["tools"][4]["inputSchema"]["properties"] = json!({});
        assert!(require_compiler_configuration(&list).is_err());
    }

    #[test]
    fn missing_dependencies_or_malformed_health_are_not_ready() {
        require_ready_helper(&json!({"ready":true,"missing":[]})).unwrap();
        for value in [
            json!({}),
            json!({"ready":true}),
            json!({"ready":false,"missing":[]}),
            json!({"ready":true,"missing":["clangd"]}),
        ] {
            assert!(require_ready_helper(&value).is_err());
        }
    }
}
