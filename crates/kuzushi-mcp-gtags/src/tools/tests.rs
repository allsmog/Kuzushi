#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_mcp_common::tool::ToolHandler;
    use serde_json::json;

    #[tokio::test]
    async fn registry_includes_all_seven_tools() {
        let r = build_registry();
        for name in [
            "gtags.health",
            "gtags.index",
            "gtags.definitions",
            "gtags.references",
            "gtags.symbols_in_file",
            "gtags.files_matching",
            "gtags.completion",
        ] {
            assert!(r.contains(name), "missing tool: {name}");
        }
    }

    #[tokio::test]
    async fn definitions_tool_reports_backend_unavailable_when_global_missing() {
        // We can't guarantee global is missing on every CI host, but
        // when it is, this is the contract: a structured anyhow Error
        // whose Display starts with "BackendUnavailable:". On hosts that
        // *do* have global installed, the tool will instead succeed
        // (returning an empty match list for an unknown symbol) and we
        // exit early without asserting anything.
        if kuzushi_mcp_common::doctor::which("global").is_some() {
            return;
        }
        let tool = DefinitionsTool;
        let err = tool
            .call(json!({"symbol": "no_such_symbol_zzz"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().starts_with("BackendUnavailable:"),
            "expected BackendUnavailable, got: {err}"
        );
    }

    #[tokio::test]
    async fn missing_required_argument_is_actionable() {
        let tool = DefinitionsTool;
        // Skip the binary-availability gate by checking the error path
        // explicitly when `global` is present.
        if kuzushi_mcp_common::doctor::which("global").is_none() {
            return;
        }
        let err = tool.call(json!({})).await.unwrap_err();
        assert!(err.to_string().contains("symbol"));
    }

    #[tokio::test]
    async fn argument_validation_runs_before_binary_checks_for_gtags_tools() {
        let index_err = IndexTool.call(json!({})).await.unwrap_err();
        assert!(index_err.to_string().contains("repoPath"));

        let files_err = FilesMatchingTool.call(json!({})).await.unwrap_err();
        assert!(files_err.to_string().contains("pattern"));

        let completion_err = CompletionTool.call(json!({})).await.unwrap_err();
        assert!(completion_err.to_string().contains("prefix"));
    }
}
