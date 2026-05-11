#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::tools::availability::locate_joern_binary;
    use kuzushi_mcp_common::tool::ToolHandler;
    use serde_json::{json, Value};

    /// Test-side equivalent of `ensure_joern_available`: matches the
    /// same lookup logic the production code uses (PATH +
    /// KUZUSHI_JOERN_BIN + hardcoded fallbacks). Otherwise tests that
    /// skip when "joern is missing" silently miss the case where
    /// joern is at /opt/joern/joern-cli but not on PATH — which is
    /// how every Linux container with the joern-cli debian package
    /// is configured.
    fn joern_locatable() -> bool {
        locate_joern_binary("joern").is_some() || locate_joern_binary("joern-parse").is_some()
    }

    #[test]
    fn registry_includes_all_planned_tools() {
        let r = build_registry();
        for name in [
            "joern.health",
            "joern.parse",
            "joern.query",
            "joern.callers_of",
            "joern.callees_of",
            "joern.reaching_def",
            "joern.taint_paths",
            "joern.unsafe_blocks",
            "joern.ffi_boundaries",
            "joern.method_at",
            "joern.cpg_size",
        ] {
            assert!(r.contains(name), "missing tool: {name}");
        }
    }

    #[test]
    fn parse_and_method_at_helpers_validate_arguments_and_shape_output() {
        assert_eq!(
            parse_repo_path(&json!({"repoPath": "/repo"})).unwrap(),
            std::path::PathBuf::from("/repo")
        );
        assert!(parse_repo_path(&json!({})).is_err());

        let request = method_at_request(&json!({"file": "/repo/a.c", "line": 7})).unwrap();
        assert_eq!(request.file, "/repo/a.c");
        assert_eq!(request.line, 7);
        assert!(method_at_request(&json!({"file": "/repo/a.c"})).is_err());

        let object = method_at_json(
            MethodAtRequest {
                file: "/repo/a.c".to_string(),
                line: 7,
            },
            "{\"name\":\"main\"}".to_string(),
        );
        assert_eq!(object["method"]["name"], "main");

        let raw = method_at_json(
            MethodAtRequest {
                file: "/repo/a.c".to_string(),
                line: 8,
            },
            "not-json".to_string(),
        );
        assert_eq!(raw["method"], "not-json");
    }

    #[test]
    fn query_json_helpers_preserve_json_and_raw_text_payloads() {
        assert_eq!(
            parse_raw_json_or_string("{\"ok\":true}".to_string()),
            json!({"ok": true})
        );
        assert_eq!(
            parse_raw_json_or_string("plain".to_string()),
            Value::String("plain".to_string())
        );

        let callers = function_query_json("main".to_string(), "callers", "[\"f\"]".to_string());
        assert_eq!(callers["fn"], "main");
        assert_eq!(callers["callers"], json!(["f"]));
    }

    #[tokio::test]
    async fn callers_of_reports_backend_unavailable_when_joern_missing() {
        if joern_locatable() {
            return;
        }
        let tool = CallersOfTool;
        let err = tool.call(json!({"fn": "main"})).await.unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn parse_and_method_at_report_backend_unavailable_when_joern_missing() {
        if joern_locatable() {
            return;
        }
        let parse = ParseTool;
        let err = parse
            .call(json!({"repoPath": "/tmp/repo"}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));

        let method_at = MethodAtTool;
        let err = method_at
            .call(json!({"file": "/tmp/repo/a.c", "line": 7}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn stubs_marker_struct_still_returns_not_yet_implemented() {
        // Kept for any future tool we register as a stub before wiring.
        let tool = NotYetImplemented("future.tool");
        let err = tool.call(json!({})).await.unwrap_err();
        assert!(err.to_string().starts_with("NotYetImplemented:"));
    }

    #[tokio::test]
    async fn taint_paths_reports_backend_unavailable_when_joern_missing() {
        if joern_locatable() {
            return;
        }
        let tool = TaintPathsTool;
        let err = tool
            .call(json!({"source": "argv", "sink": "system"}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn taint_paths_requires_source_and_sink() {
        if !joern_locatable() {
            return;
        }
        let tool = TaintPathsTool;
        let err = tool.call(json!({"source": "argv"})).await.unwrap_err();
        assert!(err.to_string().contains("sink"));
    }

    #[tokio::test]
    async fn reaching_def_requires_var_file_and_line() {
        if !joern_locatable() {
            return;
        }
        let tool = ReachingDefTool;
        let err = tool.call(json!({"file": "/r/a.c"})).await.unwrap_err();
        assert!(err.to_string().contains("line"));
    }

    #[tokio::test]
    async fn unsafe_blocks_accepts_optional_file() {
        // Schema check only — both valid and invalid args go through the
        // joern probe; this exercises the schema-validation arm.
        if joern_locatable() {
            return;
        }
        let tool = UnsafeBlocksTool;
        let err = tool.call(json!({})).await.unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
        let err = tool.call(json!({"file": "/r/lib.rs"})).await.unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }
}
