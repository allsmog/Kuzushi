#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::config::ConfigPaths;
    use crate::findings::{Finding, Severity, TriageOutcome, TriageVerdict};
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
    use anyhow::Result;
    use std::path::Path;
    use std::sync::Arc;

    /// Mock runtime that returns a canned classifier score for every query.
    struct CannedRuntime {
        score: f32,
        likely: bool,
    }
    impl AgentRuntime for CannedRuntime {
        fn query_blocking(&self, _req: AgentQueryRequest) -> Result<AgentQueryResponse> {
            Ok(AgentQueryResponse {
                text: String::new(),
                structured: Some(serde_json::json!({
                    "likely": self.likely,
                    "score": self.score,
                    "reason": "test"
                })),
                ..Default::default()
            })
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
    }

    fn synth_finding(rule: &str) -> Finding {
        Finding::new_tool(
            "semgrep",
            rule,
            "src/foo.c",
            10,
            Some(15),
            Severity::Medium,
            "candidate",
        )
    }

    fn router_with_classifier_role(model: &str) -> AgentRouter {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".kuzushi");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("models.toml"),
            format!("[roles.classifier_gate]\nprimary = \"{model}\"\n"),
        )
        .unwrap();
        let r = AgentRouter::load(&ConfigPaths {
            home_dir: tmp.path().to_path_buf(),
            target_dir: None,
        })
        .unwrap();
        let _ = tmp;
        r
    }

    fn routed(score: f32, likely: bool) -> RoutedRuntime<'static> {
        let inner: Arc<dyn AgentRuntime> = Arc::new(CannedRuntime { score, likely });
        RoutedRuntime::new(
            inner,
            Arc::new(router_with_classifier_role("anthropic:claude-haiku-4-5")),
            None,
        )
    }

    #[test]
    fn quantile_estimator_p80_converges_to_correct_value() {
        let mut q = QuantileEstimator::new(0.80);
        // Uniform 0..1 stream — 80th percentile should approach 0.8.
        for i in 0..1000 {
            q.observe((i as f32) / 999.0);
        }
        let est = q.estimate();
        assert!((est - 0.8).abs() < 0.05, "expected ~0.8, got {est}");
    }

    #[test]
    fn cold_start_uses_floor_until_min_samples() {
        let runtime = routed(0.7, true);
        let cfg = ClassifierConfig {
            cold_start_min_count: 5,
            cold_start_floor: 0.5,
            ..Default::default()
        };
        let gate = LikelyVulnClassifier::new(&runtime, cfg).unwrap();
        // Score 4 findings — still in cold-start.
        for i in 0..4 {
            let f = synth_finding(&format!("rule-{i}"));
            let _ = gate.assess(&f, Path::new(".")).unwrap();
        }
        assert_eq!(gate.samples_seen(), 4);
        // 0.7 ≥ 0.5 → graduates.
        assert!(gate.should_deep_audit(ClassifierAssessment::Scored(0.7)));
        // 0.4 < 0.5 → rejected.
        assert!(!gate.should_deep_audit(ClassifierAssessment::Scored(0.4)));
        // Threshold should still be the floor.
        assert!((gate.current_threshold() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn quantile_state_persists_across_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("index.sqlite3");
        // First gate observes 60 samples at increasing scores.
        {
            let runtime = routed(0.5, true);
            let cfg = ClassifierConfig {
                cold_start_min_count: 10,
                state_db: Some(db.clone()),
                ..Default::default()
            };
            let gate = LikelyVulnClassifier::new(&runtime, cfg).unwrap();
            for i in 0..60 {
                let f = synth_finding(&format!("rule-{i}"));
                let _ = gate.assess(&f, Path::new(".")).unwrap();
            }
            assert_eq!(gate.samples_seen(), 60);
        }
        // Second gate, reopened on the same DB, must see the persisted
        // 60-sample state.
        let runtime = routed(0.5, true);
        let cfg = ClassifierConfig {
            cold_start_min_count: 10,
            state_db: Some(db.clone()),
            ..Default::default()
        };
        let gate = LikelyVulnClassifier::new(&runtime, cfg).unwrap();
        assert_eq!(gate.samples_seen(), 60);
    }

    #[test]
    fn skip_outcome_records_threshold_in_rationale() {
        let runtime = routed(0.7, true);
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let outcome = gate.skip_outcome(0.3);
        assert_eq!(outcome.verdict, TriageVerdict::NeedsReview);
        assert!(outcome.rationale.contains("score=0.30"));
        assert!(outcome.rationale.contains("threshold="));
    }

    #[test]
    fn explicit_zero_score_is_preserved_even_with_a_legacy_likely_flag() {
        struct Q;
        impl AgentRuntime for Q {
            fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
                Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(serde_json::json!({
                        "likely": true, "score": 0.0, "reason": "no score"
                    })),
                    ..Default::default()
                })
            }
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let inner: Arc<dyn AgentRuntime> = Arc::new(Q);
        let runtime = RoutedRuntime::new(
            inner,
            Arc::new(router_with_classifier_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let s = scored(&gate);
        assert_eq!(s, 0.0);
    }

    /// A runtime whose answer the classifier gate cannot read.
    fn routed_unparseable() -> RoutedRuntime<'static> {
        struct Q;
        impl AgentRuntime for Q {
            fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
                Ok(AgentQueryResponse {
                    text: "I don't know what to say".to_string(),
                    structured: None,
                    ..Default::default()
                })
            }
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let inner: Arc<dyn AgentRuntime> = Arc::new(Q);
        RoutedRuntime::new(
            inner,
            Arc::new(router_with_classifier_role("anthropic:claude-haiku-4-5")),
            None,
        )
    }

    #[test]
    fn unparseable_response_is_degraded_rather_than_a_neutral_score() {
        let runtime = routed_unparseable();
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let assessment = gate.assess(&synth_finding("r"), Path::new(".")).unwrap();

        // A response the gate could not read is not a score.
        assert_eq!(assessment, ClassifierAssessment::ParseDegraded);
        assert_eq!(assessment.score(), None);
        assert_eq!(gate.observed_score_count_for_test(), 0);
        // The old neutral 0.5 sat *below* the default 0.6 cold-start floor, so
        // the fallback meant to protect a real bug rejected it instead.
        assert!(!gate.should_deep_audit(ClassifierAssessment::Scored(0.5)));
        assert!(gate.should_deep_audit(assessment));
    }

    #[test]
    fn loose_json_in_text_is_parsed() {
        struct Q;
        impl AgentRuntime for Q {
            fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
                Ok(AgentQueryResponse {
                    text: "Sure: ```json\n{\"likely\":true,\"score\":0.92,\"reason\":\"obvious\"}\n```"
                        .to_string(),
                    structured: None,
                    ..Default::default()
                })
            }
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let inner: Arc<dyn AgentRuntime> = Arc::new(Q);
        let runtime = RoutedRuntime::new(
            inner,
            Arc::new(router_with_classifier_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let s = scored(&gate);
        assert!((s - 0.92).abs() < 1e-6, "got {s}");
    }

    /// The score-only API stays source-compatible for downstream Rust callers,
    /// but the deprecated `score` reports an unreadable response as an error
    /// rather than the neutral `0.5` it used to manufacture.
    #[test]
    #[allow(deprecated)]
    fn deprecated_score_api_still_compiles_and_refuses_to_invent_a_score() {
        let runtime = routed(0.7, true);
        let gate = LikelyVulnClassifier::new(&runtime, ClassifierConfig::default()).unwrap();
        let s = gate.score(&synth_finding("r"), Path::new(".")).unwrap();
        assert!((s - 0.7).abs() < 1e-6, "got {s}");
        // A bare Score still reaches the assessment-taking gate.
        assert!(gate.should_deep_audit(0.7));
        assert!(!gate.should_deep_audit(0.4));

        let unreadable = routed_unparseable();
        let gate = LikelyVulnClassifier::new(&unreadable, ClassifierConfig::default()).unwrap();
        let err = gate
            .score(&synth_finding("r"), Path::new("."))
            .expect_err("an unreadable response must not surface as a score");
        assert!(err.to_string().contains("no usable verdict"), "{err}");
    }

    fn scored(gate: &LikelyVulnClassifier<'_>) -> Score {
        gate.assess(&synth_finding("r"), Path::new("."))
            .unwrap()
            .score()
            .expect("classifier returned a parseable score")
    }
}

#[path = "tests/contracts.rs"]
mod contracts;
