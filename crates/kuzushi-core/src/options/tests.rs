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
    fn reports_effective_stored_value_scope_with_same_precedence_as_input_merge() {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::Tool("threat-model:build".to_string()),
            "model",
            json!("global-model"),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("threat-model:build".to_string()),
            "model",
            json!("workspace-model"),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Module("threat-model".to_string()),
            "model",
            json!("session-model"),
        );

        let input = store
            .effective_tool_input("threat-model:build", json!({}))
            .unwrap();

        assert_eq!(input["model"], json!("session-model"));
        assert_eq!(
            store.effective_stored_value_scope("threat-model:build", "model"),
            Some(OptionScope::Session)
        );
        assert_eq!(
            store.effective_stored_value_scope("threat-model:build", "missing"),
            None
        );
    }

    #[test]
    fn persistent_store_writes_only_when_save_is_explicit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".kuzushi/v3/options.json");
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
    fn persistent_store_loads_only_global_and_workspace_scopes() {
        let tmp = tempfile::tempdir().unwrap();
        let global_path = tmp.path().join("home/.kuzushi/v3/options.json");
        let workspace_path = tmp.path().join("repo/.kuzushi/v3/options.json");

        let mut global = ToolOptionStore::new();
        global.set_value(
            OptionScope::Global,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(true),
        );
        global.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            json!(false),
        );
        global.save_to_path(&global_path).unwrap();

        let mut workspace = ToolOptionStore::new();
        workspace.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("sast:scan".to_string()),
            "verify",
            json!(true),
        );
        workspace.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "autoPatch",
            json!(true),
        );
        workspace.save_to_path(&workspace_path).unwrap();

        let loaded = ToolOptionStore::load_persistent(&global_path, Some(&workspace_path)).unwrap();
        let input = loaded.effective_tool_input("sast:scan", json!({})).unwrap();

        assert_eq!(input["triage"], json!(true));
        assert_eq!(input["verify"], json!(true));
        assert_eq!(input.get("autoPatch"), None);
    }

    #[test]
    fn persistent_store_saves_global_and_workspace_scopes_separately() {
        let tmp = tempfile::tempdir().unwrap();
        let global_path = tmp.path().join("home/.kuzushi/v3/options.json");
        let workspace_path = tmp.path().join("repo/.kuzushi/v3/options.json");
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "triage",
            json!(true),
        );
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("sast:scan".to_string()),
            "verify",
            json!(true),
        );
        store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "autoPatch",
            json!(true),
        );

        store
            .save_persistent(&global_path, Some(&workspace_path))
            .unwrap();
        let global = ToolOptionStore::load_from_path(&global_path).unwrap();
        let workspace = ToolOptionStore::load_from_path(&workspace_path).unwrap();

        assert_eq!(
            global.effective_tool_input("sast:scan", json!({})).unwrap(),
            json!({"triage": true})
        );
        assert_eq!(
            workspace
                .effective_tool_input("sast:scan", json!({}))
                .unwrap(),
            json!({"verify": true})
        );
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
