use super::*;

fn request() -> TriageRequest {
    TriageRequest {
        model: "openai:gpt-5.5".into(),
        cwd: PathBuf::from("/owned"),
        finding: Finding::new_tool(
            "audit",
            "note",
            "note.md",
            1,
            None,
            Severity::Low,
            "Owned observation",
        ),
        prompt_template: None,
    }
}

fn identity() -> Option<crate::identity::Blake3Hash> {
    Some(crate::identity::hash_parts(
        "triage-runtime-test",
        &[b"owned-test-v1"],
    ))
}

#[test]
fn cache_requires_source_identity_and_the_entire_review_question() {
    let original = request();
    assert!(key(&original, None, identity()).unwrap().is_none());
    let first = key(&original, Some("first-source"), identity()).unwrap();
    assert!(key(&original, Some("first-source"), None)
        .unwrap()
        .is_none());
    let other_runtime = Some(crate::identity::hash_parts(
        "triage-runtime-test",
        &[b"owned-test-v2"],
    ));
    assert_ne!(
        first,
        key(&original, Some("first-source"), other_runtime).unwrap()
    );
    assert_ne!(
        first,
        key(&original, Some("second-source"), identity()).unwrap()
    );
    let mut changed = original.clone();
    changed.finding.message = "Changed evidence under the same fingerprint".into();
    assert_eq!(changed.finding.fingerprint, original.finding.fingerprint);
    assert_ne!(
        first,
        key(&changed, Some("first-source"), identity()).unwrap()
    );
    changed = original;
    changed.prompt_template = Some("Accepted context changed".into());
    assert_ne!(
        first,
        key(&changed, Some("first-source"), identity()).unwrap()
    );
}

#[test]
fn discarding_a_source_removes_its_outcomes_and_eviction_entries_only() {
    let mut cache = RuntimeCache::default();
    let first = key(&request(), Some("first-source"), identity())
        .unwrap()
        .unwrap();
    let second = key(&request(), Some("second-source"), identity())
        .unwrap()
        .unwrap();
    cache.insert(first.clone(), TriageOutcome::default());
    cache.insert(second.clone(), TriageOutcome::default());
    cache.discard_source("first-source");
    assert!(cache.get(&first).is_none());
    assert!(cache.get(&second).is_some());
    assert_eq!(cache.order.len(), 1);
}

#[test]
fn incomplete_runs_and_errors_cannot_leave_reusable_outcomes() {
    for result in [
        Ok(json!({"status":"partial"})),
        Ok(json!({"status":"failed"})),
        Err(anyhow::anyhow!("review stopped")),
    ] {
        let source = uuid::Uuid::new_v4().to_string();
        let cache_key = key(&request(), Some(&source), identity()).unwrap();
        remember(cache_key.clone(), TriageOutcome::default());
        assert!(reusable_outcome(cache_key.as_ref(), false).is_some());
        discard_unverified_run(&source, &result);
        assert!(reusable_outcome(cache_key.as_ref(), false).is_none());
    }
}

#[test]
fn completed_runs_keep_reusable_outcomes_but_explicit_retriage_bypasses_them() {
    let source = uuid::Uuid::new_v4().to_string();
    let cache_key = key(&request(), Some(&source), identity()).unwrap();
    remember(cache_key.clone(), TriageOutcome::default());
    discard_unverified_run(&source, &Ok(json!({"status":"completed"})));
    assert!(reusable_outcome(cache_key.as_ref(), false).is_some());
    assert!(reusable_outcome(cache_key.as_ref(), true).is_none());
}

#[test]
fn cache_capacity_remains_bounded_after_source_discard_and_replacement() {
    let mut cache = RuntimeCache::default();
    for index in 0..=CACHE_CAPACITY {
        cache.insert(
            CacheKey {
                source_snapshot: "source".into(),
                request_hash: index.to_string(),
                runtime_identity: "test-runtime".into(),
            },
            TriageOutcome::default(),
        );
    }
    assert_eq!(cache.entries.len(), CACHE_CAPACITY);
    assert_eq!(cache.order.len(), CACHE_CAPACITY);
    cache.discard_source("source");
    assert!(cache.entries.is_empty());
    assert!(cache.order.is_empty());
}

#[test]
fn opaque_runtime_executes_each_review_even_when_source_and_request_match() {
    struct OpaqueRuntime(std::sync::atomic::AtomicUsize);
    impl AgentRuntime for OpaqueRuntime {
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(TriageOutcome {
                cost_usd_exact: true,
                ..Default::default()
            })
        }
    }
    let runtime = OpaqueRuntime(std::sync::atomic::AtomicUsize::new(0));
    let request = request();
    let config = TriageExecutionConfig::new(request.cwd.clone(), request.model.clone())
        .with_source_snapshot("owned-known-source".into());
    let input = TriageRunInput::from_tool_input(&json!({}), &request.cwd).unwrap();
    for _ in 0..2 {
        let outcome = call_triage_runtime(&runtime, &config, &input, &request.finding).unwrap();
        assert!(!outcome.cached);
    }
    assert_eq!(runtime.0.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn runtime_handles_and_tracing_preserve_the_specific_triage_attestation() {
    struct AttestedRuntime;
    impl AgentRuntime for AttestedRuntime {
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("Identity inspection must not execute review")
        }
        fn triage_semantic_cache_identity(
            &self,
            _: &TriageRequest,
        ) -> Option<crate::identity::Blake3Hash> {
            identity()
        }
    }
    let runtime = AttestedRuntime;
    let handle = crate::agent_router::RuntimeHandle::Borrowed(&runtime);
    let target = tempfile::tempdir().unwrap();
    let observation =
        crate::run_lifecycle::RunObservationHandle::jsonl(target.path(), "cache-identity").unwrap();
    let traced = crate::runtime::TracedRuntime::new(
        &handle,
        observation.trace_handle().for_module("triage"),
    );
    assert_eq!(
        traced.triage_semantic_cache_identity(&request()),
        identity()
    );
}
