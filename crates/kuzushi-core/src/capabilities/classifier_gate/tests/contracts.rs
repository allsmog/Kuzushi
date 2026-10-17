use super::super::*;
use crate::agent_router::{AgentRouter, RoutedRuntime};
use crate::findings::{Finding, Severity, TriageOutcome};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct FixtureRuntime {
    response: Value,
    text: String,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
}

impl AgentRuntime for FixtureRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.requests.lock().unwrap().push(request);
        Ok(AgentQueryResponse {
            structured: Some(self.response.clone()),
            text: self.text.clone(),
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("Owned classifier fixture cannot perform further review")
    }
}

fn fixture(response: Value) -> (FixtureRuntime, RoutedRuntime<'static>) {
    let runtime = FixtureRuntime {
        response,
        text: "{\"score\":0.9}".into(),
        requests: Default::default(),
    };
    let routed = RoutedRuntime::new(
        Arc::new(runtime.clone()),
        Arc::new(AgentRouter::empty()),
        Some("openai:gpt-4.1".into()),
    );
    (runtime, routed)
}

fn finding() -> Finding {
    Finding::new_tool(
        "owned",
        "metadata",
        "owned.txt",
        1,
        None,
        Severity::Low,
        "Owned inert metadata; no vulnerability claimed",
    )
}

#[test]
fn malformed_or_out_of_range_scores_never_become_samples_or_followup_work() {
    for response in [
        json!({}),
        json!({"likely":true}),
        json!({"score":null}),
        json!({"score":"0.4"}),
        json!({"score":-0.1}),
        json!({"score":1.1}),
    ] {
        let (runtime, routed) = fixture(response);
        let gate = LikelyVulnClassifier::new(&routed, Default::default()).unwrap();
        let opinion = gate.assess(&finding(), Path::new(".")).unwrap();
        assert_eq!(opinion, ClassifierAssessment::ParseDegraded);
        assert_eq!(gate.samples_seen(), 0);
        assert!(gate.should_deep_audit(opinion));
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn request_uses_only_bounded_metadata_and_one_model_turn() {
    let (runtime, routed) = fixture(json!({"score":0.0,"likely":true}));
    let gate = LikelyVulnClassifier::new(&routed, Default::default()).unwrap();
    assert_eq!(
        gate.assess(&finding(), Path::new(".")).unwrap().score(),
        Some(0.0)
    );
    let requests = runtime.requests.lock().unwrap();
    let request = &requests[0];
    assert!(request.tool_policy.tools.is_empty());
    assert!(!request.tool_policy.mcps);
    assert_eq!(
        request.runtime_options.as_ref().unwrap().max_model_turns,
        Some(1)
    );
    assert_eq!(request.max_output_tokens, Some(512));
    assert_eq!(request.model, "openai:gpt-4.1");
    assert!(request.prompt.contains("Owned inert metadata"));
}

#[test]
fn oversized_metadata_and_invalid_percentiles_refuse_before_a_request() {
    let (runtime, routed) = fixture(json!({"score":0.5}));
    let gate = LikelyVulnClassifier::new(&routed, Default::default()).unwrap();
    let mut subject = finding();
    subject.message = "x".repeat(64 * 1024);
    assert!(gate
        .assess(&subject, Path::new("."))
        .unwrap_err()
        .to_string()
        .contains("64 KiB"));
    for p in [0.0, 1.0, -0.1, 1.1, f32::NAN, f32::INFINITY] {
        assert!(LikelyVulnClassifier::new(
            &routed,
            ClassifierConfig {
                target_percentile: p,
                ..Default::default()
            }
        )
        .is_err());
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn percentile_histories_are_isolated_and_survive_reload() {
    use super::super::persistence::{load_quantile, save_quantile};
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("index.sqlite3");
    let mut p80 = QuantileEstimator::new(0.8);
    p80.observe(0.0);
    save_quantile(&db, &p80).unwrap();
    let mut p90 = load_quantile(&db, 0.9).unwrap();
    assert_eq!(p90.count, 0);
    assert_eq!(p90.p, 0.9);
    p90.observe(1.0);
    save_quantile(&db, &p90).unwrap();
    assert_eq!(load_quantile(&db, 0.8).unwrap().estimate(), 0.0);
    assert_eq!(load_quantile(&db, 0.9).unwrap().estimate(), 1.0);
}

fn legacy_state(db: &Path, bytes: &[u8]) {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch(
        "create table kuzushi_state(key text primary key, value blob, updated_at integer not null)",
    )
    .unwrap();
    conn.execute(
        "insert into kuzushi_state values (?1, ?2, 0)",
        rusqlite::params![super::super::domain::STATE_KEY, bytes],
    )
    .unwrap();
}

#[test]
fn matching_legacy_state_is_reused_without_rewriting_its_bytes() {
    use super::super::persistence::{load_quantile, save_quantile};
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("index.sqlite3");
    let mut q = QuantileEstimator::new(0.8);
    for _ in 0..60 {
        q.observe(0.5);
    }
    let bytes = serde_json::to_vec(&q).unwrap();
    legacy_state(&db, &bytes);
    assert_eq!(load_quantile(&db, 0.8).unwrap().count, 60);
    assert_eq!(load_quantile(&db, 0.9).unwrap().count, 0);
    save_quantile(&db, &q).unwrap();
    let retained: Vec<u8> = rusqlite::Connection::open(&db)
        .unwrap()
        .query_row(
            "select value from kuzushi_state where key=?",
            [super::super::domain::STATE_KEY],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, bytes);
}

#[test]
fn malformed_or_oversized_state_is_not_silently_reset() {
    use super::super::persistence::load_quantile;
    for bytes in [b"{}".to_vec(), vec![b' '; 4097], b"not json".to_vec()] {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("index.sqlite3");
        legacy_state(&db, &bytes);
        assert!(load_quantile(&db, 0.8).is_err());
        let retained: Vec<u8> = rusqlite::Connection::open(&db)
            .unwrap()
            .query_row("select value from kuzushi_state", [], |row| row.get(0))
            .unwrap();
        assert_eq!(retained, bytes);
    }
}

#[test]
fn failed_state_write_refuses_completion_and_preserves_the_sample_count() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("index.sqlite3");
    let (runtime, routed) = fixture(json!({"score":0.5}));
    let gate = LikelyVulnClassifier::new(
        &routed,
        ClassifierConfig {
            state_db: Some(db.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    rusqlite::Connection::open(&db).unwrap().execute_batch("create trigger refuse_sample before insert on kuzushi_state begin select raise(abort,'owned state write failure'); end").unwrap();
    assert!(gate
        .assess(&finding(), root.path())
        .unwrap_err()
        .to_string()
        .contains("retain classifier sample"));
    assert_eq!(gate.samples_seen(), 0);
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}
