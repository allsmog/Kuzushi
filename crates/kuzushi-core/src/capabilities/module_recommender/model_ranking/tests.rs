use super::*;
use crate::runtime::{AgentQueryResponse, TriageRequest};
use std::sync::Mutex;

fn request() -> RecommenderRequest {
    RecommenderRequest {
        target: "/tmp/owned-ranking".into(),
        max_recommendations: 2,
        available_tools: ["context:build".to_string()].into(),
        tools_missing_binaries: Default::default(),
        signals: RepositorySignals::default(),
        components: Vec::new(),
    }
}

struct RankingRuntime {
    text: &'static str,
    fail: bool,
    requests: Mutex<Vec<AgentQueryRequest>>,
}

impl RankingRuntime {
    fn new(text: &'static str) -> Self {
        Self {
            text,
            fail: false,
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl AgentRuntime for RankingRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.requests.lock().unwrap().push(request);
        anyhow::ensure!(!self.fail, "Owned intercepted ranking failure");
        Ok(AgentQueryResponse {
            text: self.text.into(),
            cost_usd: 0.4,
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::TriageOutcome> {
        anyhow::bail!("No finding triage in ranking tests")
    }
}

fn config() -> crate::V2Config {
    crate::V2Config {
        model: Some("openai:test".into()),
        ..Default::default()
    }
}

fn context(config: &crate::V2Config) -> ToolExecutionContext<'_> {
    ToolExecutionContext {
        config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

#[test]
fn default_ranking_is_deterministic_even_with_a_configured_model_and_runtime() {
    let runtime = RankingRuntime::new("invalid unused response");
    let config = config();
    let ctx = context(&config);
    let ranking =
        ModelRanking::resolve(&ctx, Some(&runtime), &json!({}), Path::new("/tmp")).unwrap();
    assert!(matches!(
        ranking.rank(&request()).unwrap(),
        ModelRankingOutcome::Deterministic
    ));
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn explicit_ranking_requires_selected_model_and_runtime() {
    let mut config = config();
    config.model = None;
    let ctx = context(&config);
    assert!(ModelRanking::resolve(
        &ctx,
        None,
        &json!({"useModelRanking":true}),
        Path::new("/tmp")
    )
    .is_err());
    config.model = Some("openai:test".into());
    let ctx = context(&config);
    let ranking = ModelRanking::resolve(
        &ctx,
        None,
        &json!({"useModelRanking":true}),
        Path::new("/tmp"),
    )
    .unwrap();
    assert!(ranking.rank(&request()).is_err());
}

#[test]
fn ranking_success_is_one_tool_free_request_with_exact_model_and_reported_cost() {
    let runtime = RankingRuntime::new(
        r#"[{"tool":"context:build","priority":"high","reason":"Refresh accepted facts"}]"#,
    );
    let config = config();
    let ctx = context(&config);
    let ranking = ModelRanking::resolve(
        &ctx,
        Some(&runtime),
        &json!({"useModelRanking":true,"maxOutputTokens":1024,"thinkingLevel":"medium"}),
        Path::new("/tmp"),
    )
    .unwrap();
    let ModelRankingOutcome::Ranked(outcome) = ranking.rank(&request()).unwrap() else {
        panic!("Expected explicit ranking")
    };
    assert_eq!(outcome.cost.exact_usd(), Some(0.4));
    assert_eq!(outcome.model, "openai:test");
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].model, "openai:test");
    assert_eq!(requests[0].max_output_tokens, Some(1024));
    assert_eq!(requests[0].thinking_level.as_deref(), Some("medium"));
    assert_eq!(
        requests[0]
            .runtime_options
            .as_ref()
            .unwrap()
            .max_model_turns,
        Some(1)
    );
    assert!(requests[0].tool_policy.tools.is_empty());
    assert!(!requests[0].tool_policy.mcps);
}

#[test]
fn runtime_failure_stays_failed_without_deterministic_substitution() {
    let mut runtime = RankingRuntime::new("");
    runtime.fail = true;
    let config = config();
    let ctx = context(&config);
    let ranking = ModelRanking::resolve(
        &ctx,
        Some(&runtime),
        &json!({"useModelRanking":true}),
        Path::new("/tmp"),
    )
    .unwrap();
    assert!(ranking
        .rank(&request())
        .unwrap_err()
        .to_string()
        .contains("no deterministic substitution"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn invalid_output_is_not_repaired_or_replaced_with_rules() {
    for text in [
        "invalid",
        "[]",
        r#"[{"tool":"not-installed:tool","priority":"high"}]"#,
    ] {
        let runtime = RankingRuntime::new(text);
        let config = config();
        let ctx = context(&config);
        let ranking = ModelRanking::resolve(
            &ctx,
            Some(&runtime),
            &json!({"useModelRanking":true}),
            Path::new("/tmp"),
        )
        .unwrap();
        assert!(ranking.rank(&request()).is_err());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn output_limits_and_truncation_are_honest() {
    let valid = r#"[{"tool":"context:build","priority":"medium","reason":"Owned"}]"#;
    assert!(checked_tool_picks(valid, true, &request()).is_err());
    assert!(checked_tool_picks(&"x".repeat(32769), false, &request()).is_err());
    let mut capped = request();
    capped.max_recommendations = 1;
    let excess = r#"[{"tool":"context:build"},{"tool":"context:build"}]"#;
    assert!(checked_tool_picks(excess, false, &capped).is_err());
}

#[test]
fn parse_compatibility_accepts_fences_and_deduplicates_installed_picks() {
    let picks =
        parse_tool_picks(r#"```json [{"tool":"context:build"},{"tool":"context:build"}] ```"#)
            .unwrap();
    assert_eq!(build_model_recommendations(&picks, &request()).len(), 1);
}

#[test]
fn input_output_ceiling_is_validated_before_a_request() {
    let config = config();
    let ctx = context(&config);
    for limit in [-1, 0, 4097] {
        assert!(ModelRanking::resolve(
            &ctx,
            None,
            &json!({"useModelRanking":true,"maxOutputTokens":limit}),
            Path::new("/tmp")
        )
        .is_err());
    }
}
