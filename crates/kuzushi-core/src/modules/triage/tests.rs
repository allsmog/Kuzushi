#[cfg(test)]
mod tests {
    use super::super::*;

    fn finding_with(severity: Severity, tool: &str, message: &str) -> Finding {
        Finding::new_tool(tool, "rule", "src/lib.rs", 1, None, severity, message)
    }

    #[test]
    fn prefilter_score_scales_with_severity() {
        assert!(
            prefilter_score(&finding_with(Severity::Critical, "semgrep", "plain"))
                > prefilter_score(&finding_with(Severity::Low, "semgrep", "plain"))
        );
    }

    #[test]
    fn prefilter_score_bumps_for_attacker_keywords() {
        let plain = finding_with(Severity::Medium, "semgrep", "plain bug");
        let attacker = finding_with(
            Severity::Medium,
            "semgrep",
            "attacker controls SQL injection",
        );
        assert!(prefilter_score(&attacker) > prefilter_score(&plain));
    }

    #[test]
    fn prefilter_score_bumps_for_curated_tools() {
        let semgrep = finding_with(Severity::Medium, "semgrep", "plain");
        let codeql = finding_with(Severity::Medium, "codeql", "plain");
        assert!(prefilter_score(&codeql) > prefilter_score(&semgrep));
    }

    #[test]
    fn prefilter_score_unknown_severity_is_low() {
        let unknown = finding_with(Severity::Unknown, "other", "plain");
        assert_eq!(prefilter_score(&unknown), 1);
    }

    #[test]
    fn prefilter_score_is_deterministic() {
        let finding = finding_with(
            Severity::High,
            "codeql",
            "attacker controls buffer overflow",
        );
        assert_eq!(prefilter_score(&finding), prefilter_score(&finding));
    }

    #[test]
    fn triage_run_input_parses_aliases_limits_and_prompt_files() {
        let temp = tempfile::tempdir().unwrap();
        let prompt = temp.path().join("triage.md");
        std::fs::write(&prompt, "custom triage prompt").unwrap();

        let parsed = TriageRunInput::from_tool_input(
            &json!({
                "fingerprint": " fp-1 ",
                "fingerprints": ["fp-2"],
                "batch_size": "999",
                "TRIAGE_PROMPT": "./triage.md",
                "scan_id": "scan-1",
                "concurrency": 128,
                "cost_cap_usd": 1.25,
                "prefilter_threshold": 7,
                "stage2_tier": "deep"
            }),
            temp.path(),
        )
        .unwrap();

        assert_eq!(
            parsed.fingerprints,
            Some(vec!["fp-1".to_string(), "fp-2".to_string()])
        );
        assert_eq!(parsed.batch_size, 500);
        assert_eq!(
            parsed.prompt_template,
            Some("custom triage prompt".to_string())
        );
        assert_eq!(parsed.scan_id, Some("scan-1".to_string()));
        assert_eq!(parsed.concurrency, 64);
        assert_eq!(parsed.cost_cap_usd, Some(1.25));
        assert_eq!(parsed.prefilter_threshold, 7);
        assert_eq!(parsed.stage2_tier, ModelTier::Deep);
    }

    #[test]
    fn triage_run_input_rejects_invalid_shapes() {
        let cwd = Path::new(".");
        assert!(
            TriageRunInput::from_tool_input(&json!({"fingerprints": "fp"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("fingerprints must be an array")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"fingerprints": [""]}), cwd)
                .unwrap_err()
                .to_string()
                .contains("non-empty strings")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"batchSize": 0}), cwd)
                .unwrap_err()
                .to_string()
                .contains("batchSize")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"concurrency": "many"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("concurrency")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"costCapUsd": "expensive"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("costCapUsd")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"stage2Tier": "max"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("stage2Tier")
        );
    }

    struct BareTierRuntime;

    impl AgentRuntime for BareTierRuntime {
        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("resolve_triage_model should not call triage")
        }

        fn model_for_tier(&self, _tier: ModelTier, _configured: &str) -> String {
            "claude-haiku-4-5-20251001".to_string()
        }
    }

    #[test]
    fn resolve_triage_model_rejects_tier_resolution_without_provider() {
        let config = crate::config::V2Config {
            model: Some("anthropic:claude-sonnet-4-6".to_string()),
            ..Default::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            trace: None,
        };

        let err = resolve_triage_model(&ctx, &BareTierRuntime, ModelTier::Cheap).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("triage:run resolved an invalid stage2 model"));
        assert!(message.contains("provider:model"));
    }

    struct CancelledRuntime {
        calls: std::sync::Mutex<usize>,
    }

    impl AgentRuntime for CancelledRuntime {
        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            *self.calls.lock().unwrap() += 1;
            anyhow::bail!("LangGraph bridge cancelled and was killed");
        }
    }

    #[test]
    fn triage_stage2_stops_on_runtime_cancellation() {
        let store = FindingStore::open_in_memory().unwrap();
        let runtime = CancelledRuntime {
            calls: std::sync::Mutex::new(0),
        };
        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        let config = TriageExecutionConfig::new(
            PathBuf::from("/repo"),
            "openai-codex:gpt-5.4".to_string(),
        );
        let findings = vec![
            finding_with(Severity::High, "semgrep", "sql injection"),
            finding_with(Severity::High, "semgrep", "xss"),
        ];

        let err = match run_triage_stage2(&store, &runtime, &input, &config, findings) {
            Ok(_) => panic!("cancelled triage should fail the run"),
            Err(error) => error,
        };

        assert!(format!("{err:#}").contains("triage:run cancelled"));
        assert_eq!(*runtime.calls.lock().unwrap(), 1);
    }

    #[test]
    fn triage_response_exposes_canonical_findings_snapshot() {
        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        let config = TriageExecutionConfig::new(
            PathBuf::from("/repo"),
            "anthropic:claude-sonnet-4-6".to_string(),
        );
        let stage1 = PrefilteredTriageFindings {
            total: 1,
            kept_count: 1,
            kept: Vec::new(),
            dropped: 0,
        };
        let mut stats = TriageRunStats::default();
        stats.record_persisted_outcome(
            finding_with(Severity::High, "semgrep", "sql injection"),
            TriageOutcome {
                verdict: TriageVerdict::TruePositive,
                confidence: 0.8,
                rationale: "reachable sink".to_string(),
                cost_usd: 0.01,
            },
        );

        let response = triage_response(&input, &config, &stage1, &stats, Vec::new());

        assert_eq!(response["status"], json!("completed"));
        assert_eq!(response["data"]["findings"][0]["verdict"], json!("true_positive"));
        assert!(response["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn empty_triage_response_is_skipped_not_failed() {
        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        let response = empty_triage_response(&input, vec!["missing".into()]);

        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["status"], json!("skipped"));
        assert_eq!(response["errors"], json!([]));
        assert_eq!(response["warnings"][0], json!("No findings matched triage input."));
        assert_eq!(response["data"]["findings"], json!([]));
        assert_eq!(response["costUsd"], json!(0.0));
    }
}
