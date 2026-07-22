#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::findings::{Finding, Severity};
    use crate::runtime::{
        AgentQueryControl, ModelTokenUsage, Observed, SubagentRole, TracedRuntime,
    };
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

    #[derive(Default)]
    struct ObservedRecorderRuntime {
        query_system_prompts: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl AgentRuntime for ObservedRecorderRuntime {
        fn query_observed_blocking(
            &self,
            request: AgentQueryRequest,
        ) -> Result<Observed<AgentQueryResponse>> {
            self.query_system_prompts
                .lock()
                .unwrap()
                .push(request.system_prompt);
            Ok(Observed::new(
                AgentQueryResponse::default(),
                ModelTokenUsage::from_reported_options(Some(7), None),
            ))
        }

        fn query_observed_blocking_controlled(
            &self,
            _request: AgentQueryRequest,
            control: AgentQueryControl,
        ) -> Result<Observed<AgentQueryResponse>> {
            control.ensure_active()?;
            Ok(Observed::new(
                AgentQueryResponse::default(),
                ModelTokenUsage::reported(0, 0),
            ))
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("legacy triage path must not serve an observed request")
        }

        fn triage_finding_observed_blocking(
            &self,
            _request: TriageRequest,
        ) -> Result<Observed<TriageOutcome>> {
            Ok(Observed::without_usage(TriageOutcome::default()))
        }

        fn supports_tools(&self) -> bool {
            true
        }

        fn next_step_observed_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            _history: &[LoopHistoryEntry],
        ) -> Result<Observed<AgentLoopStep>> {
            Ok(Observed::new(
                AgentLoopStep::Final {
                    text: "done".to_string(),
                    structured: None,
                    cost_usd: None,
                },
                ModelTokenUsage::reported(5, 2),
            ))
        }
    }

    struct FailingObservedRuntime;

    #[async_trait]
    impl AgentRuntime for FailingObservedRuntime {
        fn query_observed_blocking(
            &self,
            _request: AgentQueryRequest,
        ) -> Result<Observed<AgentQueryResponse>> {
            anyhow::bail!("could not parse response: raw-model-response-sentinel")
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not used by the wrapper error test")
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
            Ok(TriageOutcome { first_link: None, refute_reason: None,
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

    fn observed_query_request(system_prompt: &str) -> AgentQueryRequest {
        AgentQueryRequest::new(
            "openai:observed-model",
            PathBuf::from("/tmp"),
            system_prompt,
            "operator prompt",
        )
    }

    fn observed_triage_request() -> TriageRequest {
        TriageRequest {
            model: "openai:observed-model".to_string(),
            cwd: PathBuf::from("/tmp"),
            finding: synthetic_finding(),
            prompt_template: None,
        }
    }

    fn observed_tool_loop_request() -> AgentToolLoopRequest {
        AgentToolLoopRequest {
            model: "openai:observed-model".to_string(),
            cwd: PathBuf::from("/tmp"),
            system_prompt: "system".to_string(),
            prompt: "operator prompt".to_string(),
            tools: Vec::new(),
            max_steps: 1,
            runtime_options: None,
            temperature: None,
        }
    }

    fn routed_runtime(inner: Arc<dyn AgentRuntime>) -> RoutedRuntime<'static> {
        RoutedRuntime::new(
            inner,
            Arc::new(AgentRouter::empty()),
            Some("openai:observed-model".to_string()),
        )
    }

    fn emit_traced_usage_variants(traced: &TracedRuntime<'_>) {
        traced
            .query_observed_blocking(observed_query_request("partial system"))
            .unwrap();
        traced
            .query_observed_blocking_controlled(
                observed_query_request("zero system"),
                AgentQueryControl::default(),
            )
            .unwrap();
        traced
            .triage_finding_observed_blocking(observed_triage_request())
            .unwrap();
    }

    type PersistedModelFinish = (Option<u64>, Option<u64>, Option<String>);

    fn persisted_model_finishes(target: &Path, run_id: &str) -> Vec<PersistedModelFinish> {
        crate::run_lifecycle::read_run_items(target, run_id)
            .unwrap()
            .unwrap()
            .items
            .iter()
            .filter_map(|item| match &item.item {
                crate::run_lifecycle::RunItemV1::ModelCallFinished {
                    usage, error_class, ..
                } => Some((
                    usage.input_tokens,
                    usage.output_tokens,
                    error_class.as_ref().map(|value| value.as_str().to_string()),
                )),
                _ => None,
            })
            .collect()
    }

    fn persisted_model_error_class(target: &Path, run_id: &str) -> Option<String> {
        persisted_model_finishes(target, run_id)
            .into_iter()
            .find_map(|(_, _, error_class)| error_class)
    }

    fn assert_artifact_excludes(target: &Path, run_id: &str, artifact: &str, secret: &str) {
        let persisted = std::fs::read_to_string(crate::run_artifacts::run_artifact_path(
            target, run_id, artifact,
        ))
        .unwrap();
        assert!(!persisted.contains(secret));
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
    fn observed_query_control_and_triage_usage_survive_both_wrappers() {
        let inner = Arc::new(ObservedRecorderRuntime::default());
        let routed = routed_runtime(inner);

        let query = routed
            .query_observed_blocking(observed_query_request("query system"))
            .unwrap();
        assert_eq!(query.usage.observed_counts(), (Some(7), None));

        let controlled = routed
            .query_observed_blocking_controlled(
                observed_query_request("controlled system"),
                AgentQueryControl::default(),
            )
            .unwrap();
        assert_eq!(controlled.usage.observed_counts(), (Some(0), Some(0)));
        assert!(controlled.usage.is_complete());

        let triage = routed
            .triage_finding_observed_blocking(observed_triage_request())
            .unwrap();
        assert_eq!(triage.usage.observed_counts(), (None, None));
        assert!(triage.usage.is_unavailable());
    }

    #[test]
    fn observed_step_and_subagent_usage_survive_both_wrappers() {
        let inner = Arc::new(ObservedRecorderRuntime::default());
        let routed = routed_runtime(inner.clone());

        let step = routed
            .next_step_observed_blocking(&observed_tool_loop_request(), &[])
            .unwrap();
        assert_eq!(step.usage.observed_counts(), (Some(5), Some(2)));

        let subagent = routed
            .spawn_subagent_observed_blocking(
                SubagentRole::UnsafeBlockReasoner,
                observed_query_request("caller system"),
            )
            .unwrap();
        assert_eq!(subagent.usage.observed_counts(), (Some(7), None));
        let prompts = inner.query_system_prompts.lock().unwrap();
        let subagent_prompt = prompts.last().unwrap();
        assert!(
            subagent_prompt.starts_with(SubagentRole::UnsafeBlockReasoner.system_prompt_prefix())
        );
        assert!(subagent_prompt.ends_with("caller system"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_observed_methods_preserve_partial_and_unavailable_usage() {
        let routed = routed_runtime(Arc::new(ObservedRecorderRuntime::default()));

        let query = routed
            .query_observed(observed_query_request("async system"))
            .await
            .unwrap();
        let triage = routed
            .triage_finding_observed(observed_triage_request())
            .await
            .unwrap();

        assert_eq!(query.usage.observed_counts(), (Some(7), None));
        assert_eq!(triage.usage.observed_counts(), (None, None));
    }

    #[test]
    fn traced_wrapper_chain_persists_zero_partial_and_unavailable_usage() {
        let target = tempfile::tempdir().unwrap();
        let run_id = crate::run_artifacts::new_run_id("observed-wrapper-chain");
        let observation =
            crate::run_lifecycle::RunObservationHandle::jsonl(target.path(), &run_id).unwrap();
        let routed = routed_runtime(Arc::new(ObservedRecorderRuntime::default()));
        let traced = TracedRuntime::new(&routed, observation.trace_handle());

        emit_traced_usage_variants(&traced);
        observation.flush().unwrap();

        assert_eq!(
            persisted_model_finishes(target.path(), &run_id),
            vec![
                (
                    Some(7),
                    None,
                    Some("usage_incomplete_lower_bound".to_string())
                ),
                (Some(0), Some(0), None),
                (None, None, None),
            ]
        );
    }

    #[test]
    fn traced_wrapper_chain_persists_only_sanitized_error_metadata() {
        let target = tempfile::tempdir().unwrap();
        let run_id = crate::run_artifacts::new_run_id("observed-wrapper-error");
        let observation =
            crate::run_lifecycle::RunObservationHandle::jsonl(target.path(), &run_id).unwrap();
        let routed = routed_runtime(Arc::new(FailingObservedRuntime));
        let traced = TracedRuntime::new(&routed, observation.trace_handle());

        let error = traced
            .query_observed_blocking(observed_query_request("system"))
            .unwrap_err();
        assert!(error.to_string().contains("raw-model-response-sentinel"));
        observation.flush().unwrap();
        drop(traced);
        drop(observation);

        assert_eq!(
            persisted_model_error_class(target.path(), &run_id).as_deref(),
            Some("invalid_response")
        );

        for artifact in ["items.jsonl", "trace.jsonl"] {
            assert_artifact_excludes(
                target.path(),
                &run_id,
                artifact,
                "raw-model-response-sentinel",
            );
        }
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
