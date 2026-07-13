#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::findings::{Finding, Severity};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// In-memory recorder runtime: captures the last request's model so we
    /// can assert what the router substituted.
    struct RecorderRuntime {
        last_query_model: Mutex<Option<String>>,
        last_triage_model: Mutex<Option<String>>,
    }

    impl RecorderRuntime {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                last_query_model: Mutex::new(None),
                last_triage_model: Mutex::new(None),
            })
        }
    }

    #[async_trait]
    impl AgentRuntime for RecorderRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            *self.last_query_model.lock().unwrap() = Some(request.model.clone());
            Ok(AgentQueryResponse {
                text: "ok".to_string(),
                structured: None,
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
            *self.last_triage_model.lock().unwrap() = Some(request.model.clone());
            Ok(TriageOutcome {
                verdict: crate::findings::TriageVerdict::NeedsReview,
                confidence: 0.0,
                rationale: "test".to_string(),
                cost_usd: 0.0,
                cost_usd_exact: true,
            })
        }
    }

    fn synthetic_finding() -> Finding {
        Finding::new_tool(
            "test",
            "rule",
            "src/foo.rs",
            10,
            Some(10),
            Severity::High,
            "msg",
        )
    }

    fn write_models_toml(home: &Path, body: &str) -> PathBuf {
        let dir = home.join(".kuzushi");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("models.toml");
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn empty_router_returns_none_for_all_roles() {
        let r = AgentRouter::empty();
        for role in [
            AgentRole::Triage,
            AgentRole::DeepAuditor,
            AgentRole::FullModeMulti,
        ] {
            assert!(
                r.pick(role, 0).is_none(),
                "role {role:?} unexpectedly mapped"
            );
        }
        assert!(r.default_model().is_none());
    }

    #[test]
    fn loads_routes_from_home_models_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        write_models_toml(
            &home,
            r#"
default_model = "anthropic:claude-sonnet-4-6"

[roles.classifier_gate]
primary = "anthropic:claude-haiku-4-5"

[roles.deep_auditor]
primary = "anthropic:claude-opus-4-7"

[concurrency]
"anthropic:claude-haiku-4-5" = 80
"anthropic:claude-opus-4-7"  = 60
"#,
        );
        let r = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap();

        assert_eq!(r.default_model(), Some("anthropic:claude-sonnet-4-6"));
        assert_eq!(
            r.pick(AgentRole::ClassifierGate, 0),
            Some("anthropic:claude-haiku-4-5")
        );
        assert_eq!(r.pick(AgentRole::ClassifierGate, 1), None);

        assert_eq!(
            r.pick(AgentRole::DeepAuditor, 0),
            Some("anthropic:claude-opus-4-7")
        );
        assert_eq!(r.pick(AgentRole::DeepAuditor, 1), None);

        assert_eq!(r.concurrency_cap("anthropic:claude-haiku-4-5"), Some(80));
        assert_eq!(r.concurrency_cap("anthropic:claude-opus-4-7"), Some(60));
    }

    #[test]
    fn project_local_models_toml_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let target = tmp.path().join("project");
        write_models_toml(
            &home,
            r#"
[roles.deep_auditor]
primary = "anthropic:home-model"
"#,
        );
        write_models_toml(
            &target,
            r#"
[roles.deep_auditor]
primary = "openai:project-model"
"#,
        );
        let err = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        })
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("project models file"), "{message}");
        assert!(message.contains("not trusted"), "{message}");
    }

    #[test]
    fn rejects_unknown_role_key() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        write_models_toml(
            &home,
            r#"
[roles.fictional_role]
primary = "x"
"#,
        );
        let err = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("fictional_role"), "{}", err);
    }

    #[test]
    fn rejects_model_fallbacks_without_explicit_consent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        write_models_toml(
            &home,
            r#"
[roles.deep_auditor]
primary = "anthropic:claude-opus-4-7"
fallbacks = ["openai:o3"]
"#,
        );
        let err = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("model fallbacks"), "{err}");
    }

    #[test]
    fn rejects_invalid_default_model() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        write_models_toml(
            &home,
            r#"
default_model = "gpt-5.5"
"#,
        );
        let err = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("default_model"), "{message}");
        assert!(message.contains("provider:model"), "{message}");
    }

    #[test]
    fn rejects_invalid_role_model() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        write_models_toml(
            &home,
            r#"
[roles.deep_auditor]
primary = "gpt-5.5"
"#,
        );
        let err = AgentRouter::load(&ConfigPaths {
            home_dir: home,
            target_dir: None,
        })
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("roles.deep_auditor.primary"), "{message}");
        assert!(message.contains("provider:model"), "{message}");
    }

    #[test]
    fn routed_runtime_substitutes_model_for_role() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router.routes.insert(
            AgentRole::DeepAuditor,
            ModelRoute::new("anthropic:claude-opus-4-7"),
        );
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("anthropic:claude-sonnet-4-6".to_string()),
        );

        // The caller sends ctx.config.model (the operator default). The
        // router must replace it with the role-specific model.
        let response = routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new(
                    "anthropic:claude-sonnet-4-6",
                    PathBuf::from("/tmp"),
                    "sys",
                    "user",
                ),
            )
            .unwrap();
        assert_eq!(response.text, "ok");
        assert_eq!(
            inner.last_query_model.lock().unwrap().as_deref(),
            Some("anthropic:claude-opus-4-7"),
            "router should have substituted the role-specific model"
        );
    }

    #[test]
    fn explicit_non_default_model_wins_over_role_map() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router
            .routes
            .insert(AgentRole::DeepAuditor, ModelRoute::new("openai:role-model"));
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("openai:operator-default".to_string()),
        );

        // Caller passed an explicit per-task model that's NOT the operator default.
        // That should win over the role map.
        routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new(
                    "anthropic:per-task-override",
                    PathBuf::from("/tmp"),
                    "sys",
                    "user",
                ),
            )
            .unwrap();
        assert_eq!(
            inner.last_query_model.lock().unwrap().as_deref(),
            Some("anthropic:per-task-override")
        );
    }

    #[test]
    fn errors_when_no_model_resolvable() {
        let inner = RecorderRuntime::new();
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(AgentRouter::empty()),
            None, // no operator default
        );

        let err = routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new("", PathBuf::from("/tmp"), "sys", "user"),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("no model configured"), "{err}");
        assert!(err.contains("deep_auditor"), "{err}");
    }

    #[test]
    fn legacy_query_blocking_passes_through_unchanged() {
        let inner = RecorderRuntime::new();
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(AgentRouter::empty()),
            Some("openai:operator-default".to_string()),
        );
        // No role — calls the AgentRuntime trait method directly.
        routed
            .query_blocking(AgentQueryRequest::new(
                "openai:explicit-legacy",
                PathBuf::from("/tmp"),
                "sys",
                "user",
            ))
            .unwrap();
        assert_eq!(
            inner.last_query_model.lock().unwrap().as_deref(),
            Some("openai:explicit-legacy"),
            "legacy path must not rewrite the model"
        );
    }

    #[test]
    fn option_store_override_takes_precedence_over_role_map() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router.routes.insert(
            AgentRole::DeepAuditor,
            ModelRoute::new("anthropic:toml-model"),
        );

        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "MODEL_DEEP_AUDITOR",
            serde_json::Value::String("openai:setg-model".to_string()),
        );

        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("openai:operator-default".to_string()),
        )
        .with_option_store(&store);

        routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new(
                    "openai:operator-default",
                    PathBuf::from("/tmp"),
                    "sys",
                    "user",
                ),
            )
            .unwrap();
        assert_eq!(
            inner.last_query_model.lock().unwrap().as_deref(),
            Some("openai:setg-model"),
            "operator-set MODEL_DEEP_AUDITOR must beat models.toml"
        );
    }

    #[test]
    fn invalid_option_store_override_errors_without_falling_back() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router.routes.insert(
            AgentRole::DeepAuditor,
            ModelRoute::new("anthropic:toml-model"),
        );

        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Global,
            OptionTarget::All,
            "MODEL_DEEP_AUDITOR",
            serde_json::Value::String("gpt-5.5".to_string()),
        );

        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("openai:operator-default".to_string()),
        )
        .with_option_store(&store);

        let err = routed
            .query_for_role(
                AgentRole::DeepAuditor,
                AgentQueryRequest::new(
                    "openai:operator-default",
                    PathBuf::from("/tmp"),
                    "sys",
                    "user",
                ),
            )
            .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("deep_auditor"), "{message}");
        assert!(message.contains("provider:model"), "{message}");
        assert!(
            inner.last_query_model.lock().unwrap().is_none(),
            "invalid override must not fall back to the valid TOML route"
        );
    }

    #[test]
    fn option_store_keys_are_uppercased_role_keys() {
        assert_eq!(
            AgentRole::DeepAuditor.option_store_key(),
            "MODEL_DEEP_AUDITOR"
        );
        assert_eq!(
            AgentRole::ClassifierGate.option_store_key(),
            "MODEL_CLASSIFIER_GATE"
        );
        assert_eq!(AgentRole::Triage.option_store_key(), "MODEL_TRIAGE");
    }

    #[test]
    fn triage_routing_works_too() {
        let inner = RecorderRuntime::new();
        let mut router = AgentRouter::empty();
        router
            .routes
            .insert(AgentRole::Triage, ModelRoute::new("openai:triage-model"));
        let routed = RoutedRuntime::new(
            inner.clone(),
            Arc::new(router),
            Some("openai:operator-default".to_string()),
        );
        routed
            .triage_for_role(
                AgentRole::Triage,
                TriageRequest {
                    model: "openai:operator-default".to_string(),
                    cwd: PathBuf::from("/tmp"),
                    finding: synthetic_finding(),
                    prompt_template: None,
                },
            )
            .unwrap();
        assert_eq!(
            inner.last_triage_model.lock().unwrap().as_deref(),
            Some("openai:triage-model")
        );
    }
}
