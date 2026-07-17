#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_mcp_common::doctor::which;
    use kuzushi_mcp_common::tool::ToolHandler;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn registry_includes_all_planned_tools() {
        let root = tempfile::tempdir().unwrap();
        let read =
            kuzushi_mcp_common::ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
        let r = build_registry_with_capability(read);
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
                    || err
                        .to_string()
                        .contains("could not open authorized MCP path")
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
                    || err
                        .to_string()
                        .contains("could not open authorized MCP path")
            );
        }
    }

    #[test]
    fn position_request_requires_column_unless_defaulted() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("src")).unwrap();
        std::fs::write(root.path().join("src/a.cc"), "int a;\n").unwrap();
        let handle = ClangdHandle::new(
            kuzushi_mcp_common::ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
        );
        let args = json!({"repoPath":root.path(),"file":"src/a.cc","line":7});
        assert!(PositionRequest::from_args(&args, &handle).is_err());

        let request = PositionRequest::from_args_with_default_column(&args, 1, &handle).unwrap();
        assert_eq!(
            request.file.repo.path(),
            root.path().canonicalize().unwrap()
        );
        assert_eq!(
            request.file.file,
            root.path().canonicalize().unwrap().join("src/a.cc")
        );
        assert_eq!(request.line, 7);
        assert_eq!(request.column, 1);
    }

    #[test]
    fn file_request_rejects_absolute_and_parent_child_paths() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.c");
        std::fs::write(&source, "int value;\n").unwrap();
        let handle = ClangdHandle::new(
            kuzushi_mcp_common::ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
        );

        for child in [source.display().to_string(), "../source.c".to_string()] {
            let error =
                FileRequest::from_args(&json!({"repoPath": root.path(), "file": child}), &handle)
                    .err()
                    .expect("escaping child must fail");
            assert!(
                error.to_string().contains("absolute MCP child")
                    || error.to_string().contains("contains '.' or '..'"),
                "{error:#}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_request_rejects_a_symlink_child() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("source.c"), "int value;\n").unwrap();
        symlink(root.path().join("source.c"), root.path().join("link.c")).unwrap();
        let handle = ClangdHandle::new(
            kuzushi_mcp_common::ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
        );

        assert!(FileRequest::from_args(
            &json!({"repoPath": root.path(), "file": "link.c"}),
            &handle,
        )
        .is_err());
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
