#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::json;

    #[test]
    fn merges_options_with_deterministic_scope_and_specificity_precedence() {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "limit",
            json!("global-all"),
        );
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("semgrep:scan".to_string()),
            "limit",
            json!("global-tool"),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("semgrep:scan".to_string()),
            "limit",
            json!("workspace-tool"),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Module("semgrep".to_string()),
            "limit",
            json!("session-module"),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("semgrep:scan".to_string()),
            "config",
            json!("p/ci"),
        );

        let input = store
            .effective_tool_input("semgrep:scan", json!({"limit": "explicit"}))
            .unwrap();

        assert_eq!(input["limit"], json!("explicit"));
        assert_eq!(input["config"], json!("p/ci"));
    }

    #[test]
    fn applies_session_values_over_persistent_values_without_explicit_input() {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::Module("sast".to_string()),
            "triage",
            json!(true),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(false),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Module("sast".to_string()),
            "triage",
            json!(true),
        );

        let input = store.effective_tool_input("sast:scan", json!({})).unwrap();

        assert_eq!(input["triage"], json!(true));
    }

    #[test]
    fn persistent_store_writes_only_when_save_is_explicit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".kuzushi/v2/options.json");
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(true),
        );

        assert!(!path.exists());
        store.save_to_path(&path).unwrap();
        assert!(path.exists());

        let loaded = ToolOptionStore::load_from_path(&path).unwrap();
        assert_eq!(loaded, store);
    }

    #[test]
    fn rejects_non_object_explicit_input_when_stored_options_would_merge() {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(true),
        );

        let error = store
            .effective_tool_input("sast:scan", json!(["not", "object"]))
            .unwrap_err();
        assert!(error.to_string().contains("require a JSON object input"));
    }
}
