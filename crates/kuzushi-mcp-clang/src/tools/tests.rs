#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn registry_includes_all_planned_tools() {
        let r = build_registry();
        for name in [
            "clang.health",
            "clang.compile_commands",
            "clang.definition",
            "clang.references",
            "clang.type_at",
            "clang.ast",
            "clang.callers",
            "clang.callees",
            "clang.macro_expand",
            "clang.semantic_tokens",
            "clang.diagnostics",
        ] {
            assert!(r.contains(name), "missing tool: {name}");
        }
    }

    #[tokio::test]
    async fn definition_tool_reports_backend_unavailable_when_clangd_missing() {
        if which("clangd").is_some() {
            return;
        }
        let tool = DefinitionTool {
            handle: Arc::new(ClangdHandle::default()),
        };
        let err = tool
            .call(json!({"repoPath":"/tmp","file":"x.c","line":1,"column":1}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn callers_reports_backend_unavailable_when_clangd_missing() {
        if which("clangd").is_some() {
            return;
        }
        let tool = CallersTool {
            handle: Arc::new(ClangdHandle::default()),
        };
        let err = tool
            .call(json!({"repoPath":"/tmp","file":"x.c","line":1,"column":1}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn callees_reports_backend_unavailable_when_clangd_missing() {
        if which("clangd").is_some() {
            return;
        }
        let tool = CalleesTool {
            handle: Arc::new(ClangdHandle::default()),
        };
        let err = tool
            .call(json!({"repoPath":"/tmp","file":"x.c","line":1,"column":1}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn diagnostics_reports_backend_unavailable_when_clangd_missing() {
        if which("clangd").is_some() {
            return;
        }
        let tool = DiagnosticsTool {
            handle: Arc::new(ClangdHandle::default()),
        };
        let err = tool
            .call(json!({"repoPath":"/tmp","file":"x.c"}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn position_tools_validate_required_arguments_before_opening_files() {
        let handle = Arc::new(ClangdHandle::default());
        for err in [
            DefinitionTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            ReferencesTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            TypeAtTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            AstTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            MacroExpandTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
        ] {
            assert!(
                err.to_string().starts_with("BackendUnavailable:")
                    || err.to_string().contains("missing required argument")
            );
        }
    }

    #[tokio::test]
    async fn file_tools_validate_required_arguments_before_opening_files() {
        let handle = Arc::new(ClangdHandle::default());
        for err in [
            SemanticTokensTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            DiagnosticsTool { handle }
                .call(json!({}))
                .await
                .unwrap_err(),
        ] {
            assert!(
                err.to_string().starts_with("BackendUnavailable:")
                    || err.to_string().contains("missing required argument")
            );
        }
    }

    #[test]
    fn position_request_requires_column_unless_defaulted() {
        let args = json!({"repoPath":"/repo","file":"src/a.cc","line":7});
        assert!(PositionRequest::from_args(&args).is_err());

        let request = PositionRequest::from_args_with_default_column(&args, 1).unwrap();
        assert_eq!(request.file.repo, PathBuf::from("/repo"));
        assert_eq!(request.file.file, PathBuf::from("/repo/src/a.cc"));
        assert_eq!(request.line, 7);
        assert_eq!(request.column, 1);
    }

    #[test]
    fn lsp_locations_are_projected_to_schema_shapes() {
        let raw = json!([{
            "uri":"file:///repo/a.c",
            "range":{
                "start":{"line":2,"character":4},
                "end":{"line":2,"character":9}
            }
        }]);

        let positions = position_locations(&raw);
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].line, 3);
        assert_eq!(positions[0].column, Some(5));

        let ranges = range_locations(&raw);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start.line, 3);
        assert_eq!(ranges[0].end.column, Some(5));
    }

    #[test]
    fn call_hierarchy_response_helpers_ignore_non_arrays() {
        let mut calls = vec![json!({"name":"existing"})];
        extend_with_json_array(&mut calls, &json!({"not":"array"}));
        assert_eq!(calls.len(), 1);

        extend_with_json_array(&mut calls, &json!([{"name":"next"}]));
        assert_eq!(
            calls,
            vec![json!({"name":"existing"}), json!({"name":"next"})]
        );
        assert!(json_array(&json!({"not":"array"})).is_empty());
    }

    #[test]
    fn clang_language_id_maps_c_and_cpp_extensions() {
        assert_eq!(clang_language_id(std::path::Path::new("main.c")), "c");
        assert_eq!(clang_language_id(std::path::Path::new("main.h")), "c");
        assert_eq!(clang_language_id(std::path::Path::new("main.cpp")), "cpp");
        assert_eq!(clang_language_id(std::path::Path::new("main.hh")), "cpp");
        assert_eq!(clang_language_id(std::path::Path::new("README")), "cpp");
    }

    #[test]
    fn extract_first_code_fence_handles_clangd_markdown_hover() {
        // Realistic clangd hover for a macro: wraps the expansion in a
        // ```c ... ``` block.
        let hover = json!({
            "contents": {
                "kind": "markdown",
                "value": "Macro `MAX(x, y)`\n\n```c\n((x) > (y) ? (x) : (y))\n```\n"
            }
        });
        let extracted = extract_first_code_fence(&hover);
        assert_eq!(extracted.as_deref(), Some("((x) > (y) ? (x) : (y))"));
    }

    #[test]
    fn extract_first_code_fence_returns_none_when_no_fence() {
        let hover = json!({
            "contents": {"kind": "markdown", "value": "no code here"}
        });
        assert!(extract_first_code_fence(&hover).is_none());
    }

    #[test]
    fn extract_first_code_fence_handles_plain_string_contents() {
        let hover = json!({ "contents": "```\nplain\n```" });
        assert_eq!(extract_first_code_fence(&hover).as_deref(), Some("plain"));
    }
}
