use super::*;
use crate::semantic_cache::{cache_entry_now, execution_query_cache_key, SemanticCache};
use std::cell::RefCell;

pub(crate) struct CachedStructuredJson<T> {
    pub(crate) costed: CostedStructuredJson<T>,
    pub(crate) from_cache: bool,
}

/// [`query_required_structured_json_with_cost`] behind the semantic cache:
/// an identical closed-world request replays its stored response for free
/// instead of paying for the model call again.
///
/// Only requests with the default (tool-free, MCP-free) policy consult the
/// cache — once an agent can read the workspace, the response is no longer a
/// function of the request bytes. A stored value the caller's current
/// `validate` rejects is stale (the schema or parser moved on) and falls
/// through to a live call that overwrites it.
pub(crate) fn query_cached_structured_json_with_cost<T>(
    cache: Option<&SemanticCache>,
    runtime: &dyn AgentRuntime,
    request: AgentQueryRequest,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
) -> Result<CachedStructuredJson<T>> {
    let key = cache.and_then(|_| {
        execution_query_cache_key(
            runtime,
            &request,
            &contract.tool_name,
            &contract.schema_name,
            &contract.schema,
        )
    });
    if let Some(hit) = cached_hit(cache, key.as_ref(), &validate) {
        return Ok(hit);
    }

    let raw = RefCell::new(None);
    let task = contract.tool_name.clone();
    let model = request.model.clone();
    let costed = query_required_structured_json_with_cost(runtime, request, contract, |value| {
        *raw.borrow_mut() = Some(value.clone());
        validate(value)
    })?;
    if let (Some(cache), Some(key), Some(value)) = (cache, &key, raw.into_inner()) {
        // Best-effort: a cache write failure must never fail a paid,
        // successful call.
        let _ = cache.put(key, &cache_entry_now(task, model, costed.cost_usd, value));
    }
    Ok(CachedStructuredJson {
        costed,
        from_cache: false,
    })
}

/// A stored value the current `validate` still accepts replays for free.
fn cached_hit<T>(
    cache: Option<&SemanticCache>,
    key: Option<&crate::identity::Blake3Hash>,
    validate: &impl Fn(Value) -> Result<T>,
) -> Option<CachedStructuredJson<T>> {
    let entry = cache?.get(key?)?;
    let value = validate(entry.value).ok()?;
    Some(CachedStructuredJson {
        costed: CostedStructuredJson {
            value,
            cost_usd: 0.0,
            cost_usd_exact: true,
            estimated_cost_usd: None,
        },
        from_cache: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::TriageOutcome;
    use crate::runtime::{AgentQueryResponse, AgentToolPolicy, TriageRequest};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingRuntime {
        calls: AtomicUsize,
        value: Value,
        revision: AtomicUsize,
    }

    impl AgentRuntime for CountingRuntime {
        fn semantic_cache_identity(
            &self,
            _request: &AgentQueryRequest,
        ) -> Option<crate::identity::Blake3Hash> {
            let revision = self.revision.load(Ordering::SeqCst);
            (revision > 0)
                .then(|| crate::identity::hash_parts("test-runtime", &[&revision.to_be_bytes()]))
        }

        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AgentQueryResponse {
                text: self.value.to_string(),
                structured: Some(self.value.clone()),
                cost_usd: 0.5,
                cost_usd_reported: true,
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("not used by cached-query tests")
        }
    }

    fn contract() -> StructuredJsonContract {
        StructuredJsonContract::new("cache-test", "CacheTest", json!({"type": "array"}))
    }

    fn request() -> AgentQueryRequest {
        AgentQueryRequest::new(
            "test-model".to_string(),
            std::path::PathBuf::from("."),
            "sys".to_string(),
            "prompt".to_string(),
        )
    }

    #[test]
    fn second_identical_call_replays_from_cache_at_zero_cost() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SemanticCache::open_at(tmp.path()).unwrap();
        let runtime = CountingRuntime {
            calls: AtomicUsize::new(0),
            revision: AtomicUsize::new(1),
            value: json!([1, 2]),
        };

        let first = query_cached_structured_json_with_cost(
            Some(&cache),
            &runtime,
            request(),
            contract(),
            Ok,
        )
        .unwrap();
        assert!(!first.from_cache);
        assert_eq!(first.costed.cost_usd, 0.5);

        let second = query_cached_structured_json_with_cost(
            Some(&cache),
            &runtime,
            request(),
            contract(),
            Ok,
        )
        .unwrap();
        assert!(second.from_cache);
        assert_eq!(second.costed.value, json!([1, 2]));
        assert_eq!(second.costed.cost_usd, 0.0);
        assert!(second.costed.cost_usd_exact);
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn requests_with_a_tool_policy_never_touch_the_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SemanticCache::open_at(tmp.path()).unwrap();
        let runtime = CountingRuntime {
            calls: AtomicUsize::new(0),
            revision: AtomicUsize::new(1),
            value: json!([]),
        };
        let open_world = || {
            request().with_tool_policy(AgentToolPolicy {
                profile: "explore".to_string(),
                ..AgentToolPolicy::default()
            })
        };

        for _ in 0..2 {
            let result = query_cached_structured_json_with_cost(
                Some(&cache),
                &runtime,
                open_world(),
                contract(),
                Ok,
            )
            .unwrap();
            assert!(!result.from_cache);
        }
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn each_generation_setting_and_runtime_revision_forces_a_live_call() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SemanticCache::open_at(tmp.path()).unwrap();
        let runtime = CountingRuntime {
            calls: AtomicUsize::new(0),
            revision: AtomicUsize::new(1),
            value: json!([]),
        };
        let query = |request| {
            query_cached_structured_json_with_cost(Some(&cache), &runtime, request, contract(), Ok)
                .unwrap()
                .from_cache
        };
        assert!(!query(request()));
        assert!(query(request()));
        let changes: [fn(&mut AgentQueryRequest); 6] = [
            |r| r.thinking_level = Some("high".into()),
            |r| r.max_output_tokens = Some(700),
            |r| r.temperature = Some(0.3),
            |r| {
                r.runtime_options = Some(crate::runtime::AgentRuntimeOptions {
                    max_model_turns: Some(2),
                    ..Default::default()
                })
            },
            |r| {
                r.runtime_options = Some(crate::runtime::AgentRuntimeOptions {
                    observed_spend_stop_usd: Some(0.8),
                    ..Default::default()
                })
            },
            |r| r.model = "other-model".into(),
        ];
        for change in changes {
            let mut changed = request();
            change(&mut changed);
            assert!(!query(changed.clone()));
            assert!(query(changed));
        }
        runtime.revision.store(2, Ordering::SeqCst);
        assert!(!query(request()));
        assert!(query(request()));
        runtime.revision.store(0, Ordering::SeqCst);
        assert!(!query(request()));
        assert!(!query(request()));
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn transport_diagnostics_and_credentials_do_not_enter_cache_identity_or_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SemanticCache::open_at(tmp.path()).unwrap();
        let runtime = CountingRuntime {
            calls: AtomicUsize::new(0),
            revision: AtomicUsize::new(1),
            value: json!([]),
        };
        let query = |request| {
            query_cached_structured_json_with_cost(Some(&cache), &runtime, request, contract(), Ok)
                .unwrap()
        };
        assert!(!query(request()).from_cache);
        let diagnostic = request().with_runtime_options(crate::runtime::AgentRuntimeOptions {
            bridge_verbose: Some(true),
            bridge_log_path: Some("synthetic-secret-log-path".into()),
            mcp_environment: [("API_KEY".into(), "synthetic-secret-token".into())].into(),
            mcp_tool_timeout_ms: Some(20),
            ..Default::default()
        });
        assert!(query(diagnostic).from_cache);
        let contract = contract();
        let key = execution_query_cache_key(
            &runtime,
            &request(),
            &contract.tool_name,
            &contract.schema_name,
            &contract.schema,
        )
        .unwrap();
        let metadata = serde_json::to_string(&cache.get(&key).unwrap()).unwrap();
        assert!(!metadata.contains("synthetic-secret"));
    }

    #[test]
    fn stale_entries_the_validator_rejects_fall_through_to_a_live_call() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = SemanticCache::open_at(tmp.path()).unwrap();
        let runtime = CountingRuntime {
            calls: AtomicUsize::new(0),
            revision: AtomicUsize::new(1),
            value: json!([3]),
        };
        let contract = contract();
        let key = execution_query_cache_key(
            &runtime,
            &request(),
            &contract.tool_name,
            &contract.schema_name,
            &contract.schema,
        )
        .unwrap();
        cache
            .put(
                &key,
                &cache_entry_now("cache-test", "test-model", 0.1, json!("legacy shape")),
            )
            .unwrap();
        let validate = |value: Value| {
            value
                .as_array()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("expected an array"))
        };

        let result = query_cached_structured_json_with_cost(
            Some(&cache),
            &runtime,
            request(),
            contract,
            validate,
        )
        .unwrap();

        assert!(!result.from_cache);
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
        // The live value replaced the stale entry.
        assert_eq!(cache.get(&key).unwrap().value, json!([3]));
    }
}
