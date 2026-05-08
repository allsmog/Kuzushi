#[cfg(test)]
mod tests {
    use super::super::*;

    #[tokio::test]
    async fn empty_facade_reports_no_live_backends() {
        let facade = IndexFacade::new();
        assert!(facade.live_backends().is_empty());
    }

    #[tokio::test]
    async fn definitions_with_no_backends_errors_actionably() {
        let mut facade = IndexFacade::new();
        let err = facade
            .definitions("foo", Path::new("/tmp"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no backend"));
    }

    #[tokio::test]
    async fn callers_of_errors_when_no_backend_live() {
        let mut facade = IndexFacade::new();
        let err = facade.callers_of("foo", None).await.unwrap_err();
        assert!(err.to_string().contains("no backend"));
    }

    #[test]
    fn backend_call_builders_encode_supported_routes_only() {
        let repo = Path::new("/repo");
        let def = definition_call(Backend::Gtags, "parse", repo).unwrap();
        assert_eq!(def.tool, "gtags.definitions");
        assert_eq!(def.args["symbol"], serde_json::json!("parse"));
        assert!(definition_call(Backend::Clang, "parse", repo).is_none());

        let pos = FilePosition {
            repo: std::path::PathBuf::from("/repo"),
            file: "src/a.c".to_string(),
            line: 10,
            column: 3,
        };
        let callers = callers_call(Backend::Clang, "parse", Some(&pos)).unwrap();
        assert_eq!(callers.tool, "clang.callers");
        assert_eq!(callers.args["line"], serde_json::json!(10));
        assert!(callers_call(Backend::Gtags, "parse", Some(&pos)).is_none());

        let callees = callees_call(Backend::Joern, "parse", None).unwrap();
        assert_eq!(callees.tool, "joern.callees_of");
        assert_eq!(callees.args["fn"], serde_json::json!("parse"));
    }

    #[test]
    fn symbol_matches_tolerates_missing_or_malformed_payloads() {
        assert!(symbol_matches(&serde_json::json!({})).is_empty());
        assert!(symbol_matches(&serde_json::json!({"matches": {"bad": true}})).is_empty());
    }

    #[tokio::test]
    async fn taint_paths_reports_backend_unavailable_without_joern() {
        let mut facade = IndexFacade::new();
        let err = facade
            .taint_paths("argv", "system", None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("BackendUnavailable"));
        assert!(err.to_string().contains("joern"));
    }

    #[tokio::test]
    async fn unsafe_blocks_reports_backend_unavailable_without_joern() {
        let mut facade = IndexFacade::new();
        let err = facade.unsafe_blocks(None).await.unwrap_err();
        assert!(err.to_string().contains("joern"));
    }

    #[tokio::test]
    async fn ffi_boundaries_reports_backend_unavailable_without_joern() {
        let mut facade = IndexFacade::new();
        let err = facade.ffi_boundaries().await.unwrap_err();
        assert!(err.to_string().contains("joern"));
    }

    #[tokio::test]
    async fn type_at_reports_backend_unavailable_without_clang() {
        let mut facade = IndexFacade::new();
        let pos = FilePosition {
            repo: std::path::PathBuf::from("/tmp"),
            file: "x.c".to_string(),
            line: 1,
            column: 1,
        };
        let err = facade.type_at(&pos).await.unwrap_err();
        assert!(err.to_string().contains("clangd"));
    }

    #[tokio::test]
    async fn ast_reports_backend_unavailable_without_clang() {
        let mut facade = IndexFacade::new();
        let pos = FilePosition {
            repo: std::path::PathBuf::from("/tmp"),
            file: "x.c".to_string(),
            line: 1,
            column: 1,
        };
        let err = facade.ast(&pos).await.unwrap_err();
        assert!(err.to_string().contains("clangd"));
    }
}
