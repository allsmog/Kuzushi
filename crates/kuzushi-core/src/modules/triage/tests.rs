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
    fn triage_run_input_parses_aliases_controls_and_prompt_files() {
        let temp = tempfile::tempdir().unwrap();
        let prompt = temp.path().join("triage.md");
        std::fs::write(&prompt, "custom triage prompt").unwrap();

        let parsed = TriageRunInput::from_tool_input(
            &json!({
                "fingerprint": " fp-1 ",
                "fingerprints": ["fp-2"],
                "TRIAGE_PROMPT": "./triage.md",
                "scan_id": "scan-1",
                "concurrency": 128,
                "cost_cap_usd": 1.25,
                "prefilter_threshold": 7,
                "stage2_tier": "deep",
                "model": "openai:gpt-override",
                "retriage": true
            }),
            temp.path(),
        )
        .unwrap();

        assert_eq!(
            parsed.fingerprints,
            Some(vec!["fp-1".to_string(), "fp-2".to_string()])
        );
        assert_eq!(
            parsed.prompt_template,
            Some("custom triage prompt".to_string())
        );
        assert_eq!(parsed.scan_id, Some("scan-1".to_string()));
        assert_eq!(parsed.concurrency, 64);
        assert_eq!(parsed.cost_cap_usd, Some(1.25));
        assert_eq!(parsed.prefilter_threshold, 7);
        assert_eq!(parsed.stage2_tier, ModelTier::Deep);
        assert_eq!(parsed.model.as_deref(), Some("openai:gpt-override"));
        assert!(parsed.retriage);
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

        let input = TriageRunInput::from_tool_input(
            &json!({"stage2Tier": "cheap"}),
            std::path::Path::new("."),
        )
        .unwrap();
        let err = resolve_triage_model(&ctx, &BareTierRuntime, &input).unwrap_err();
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

    struct CountingRuntime {
        calls: std::sync::Mutex<usize>,
    }

    impl AgentRuntime for CountingRuntime {
        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            *self.calls.lock().unwrap() += 1;
            Ok(true_positive_outcome())
        }
    }

    #[test]
    fn triage_stage2_stops_on_runtime_cancellation() {
        let store = FindingStore::open_in_memory().unwrap();
        let runtime = CancelledRuntime {
            calls: std::sync::Mutex::new(0),
        };
        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        let config =
            TriageExecutionConfig::new(PathBuf::from("/repo"), "openai-codex:gpt-5.4".to_string());
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
    fn select_triage_findings_defaults_to_latest_scan() {
        let store = store_with_scan_findings(&[
            ("scan-a", finding_with(Severity::High, "semgrep", "old sql")),
            (
                "scan-z",
                finding_with(Severity::High, "semgrep", "latest xss"),
            ),
        ]);
        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();

        let (findings, missing) = select_triage_findings(&store, &input).unwrap();

        assert!(missing.is_empty());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].scan_id.as_deref(), Some("scan-z"));
        assert_eq!(findings[0].message, "latest xss");
    }

    #[test]
    fn select_triage_findings_skips_existing_verdicts_unless_retriage() {
        let store = store_with_scan_findings(&[(
            "scan-z",
            finding_with(Severity::High, "semgrep", "already paid"),
        )]);
        let stored = store.list_findings_for_scan_id("scan-z").unwrap();
        store
            .record_auto_triage(stored[0].id.unwrap(), &true_positive_outcome())
            .unwrap();

        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        assert!(select_triage_findings(&store, &input).unwrap().0.is_empty());

        let retriage =
            TriageRunInput::from_tool_input(&json!({"retriage": true}), Path::new(".")).unwrap();
        assert_eq!(
            select_triage_findings(&store, &retriage).unwrap().0.len(),
            1
        );
    }

    #[test]
    fn select_triage_findings_skips_later_run_with_reviewed_identity() {
        let store = FindingStore::open_in_memory().unwrap();
        let finding = finding_with(Severity::High, "semgrep", "already paid across runs");
        store
            .record_run_started("scan-a", Path::new("/tmp/repo"), "completed")
            .unwrap();
        let first_id = store.insert_finding("scan-a", &finding).unwrap();
        store
            .record_auto_triage(first_id, &true_positive_outcome())
            .unwrap();
        store.record_run_finished("scan-a", "completed", 1).unwrap();
        store
            .record_run_started("scan-z", Path::new("/tmp/repo"), "completed")
            .unwrap();
        store.insert_finding("scan-z", &finding).unwrap();
        store.record_run_finished("scan-z", "completed", 1).unwrap();

        let latest = store.list_findings_for_scan_id("scan-z").unwrap();
        assert!(latest[0].triage.is_none(), "new row has no copied verdict");

        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();

        assert!(select_triage_findings(&store, &input).unwrap().0.is_empty());
    }

    #[test]
    fn triage_stage2_reuses_cached_outcome_without_extra_model_call_or_cost() {
        let store = store_with_scan_findings(&[(
            "scan-cache",
            finding_with(Severity::High, "semgrep", "cache me once"),
        )]);
        let finding = store
            .list_findings_for_scan_id("scan-cache")
            .unwrap()
            .remove(0);
        let runtime = CountingRuntime {
            calls: std::sync::Mutex::new(0),
        };
        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        let config = TriageExecutionConfig::new(
            PathBuf::from("/repo-cache"),
            "openai-codex:gpt-5.4".to_string(),
        );

        let first =
            run_triage_stage2(&store, &runtime, &input, &config, vec![finding.clone()]).unwrap();
        let second = run_triage_stage2(&store, &runtime, &input, &config, vec![finding]).unwrap();

        assert_eq!(*runtime.calls.lock().unwrap(), 1);
        assert_eq!(first.total_cost, 0.01);
        assert_eq!(second.total_cost, 0.0);
        assert_eq!(second.results[0]["cached"], json!(true));
    }

    #[test]
    fn persist_triage_outcome_propagates_to_same_fingerprint_siblings() {
        let finding = finding_with(Severity::High, "semgrep", "same fp");
        let store = store_with_scan_findings(&[("scan-a", finding.clone()), ("scan-z", finding)]);
        let latest = store.list_findings_for_scan_id("scan-z").unwrap().remove(0);
        let mut stats = TriageRunStats::default();

        persist_triage_outcome(
            &store,
            &mut stats,
            latest,
            runtime_outcome(true_positive_outcome()),
        );

        for scan_id in ["scan-a", "scan-z"] {
            let stored = store.list_findings_for_scan_id(scan_id).unwrap();
            assert_eq!(
                stored[0].triage.as_ref().map(|triage| triage.verdict),
                Some(TriageVerdict::TruePositive)
            );
        }
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
        assert_eq!(
            response["data"]["findings"][0]["verdict"],
            json!("true_positive")
        );
        assert!(response["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn empty_triage_response_is_skipped_not_failed() {
        let input = TriageRunInput::from_tool_input(&json!({}), Path::new(".")).unwrap();
        let response = empty_triage_response(&input, vec!["missing".into()]);

        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["status"], json!("skipped"));
        assert_eq!(response["errors"], json!([]));
        assert_eq!(
            response["warnings"][0],
            json!("No findings matched triage input.")
        );
        assert_eq!(response["data"]["findings"], json!([]));
        assert_eq!(response["costUsd"], json!(0.0));
    }

    fn store_with_scan_findings(scan_findings: &[(&str, Finding)]) -> FindingStore {
        let store = FindingStore::open_in_memory().unwrap();
        for (scan_id, finding) in scan_findings {
            store
                .record_run_started(scan_id, Path::new("/tmp/repo"), "completed")
                .unwrap();
            store.insert_finding(scan_id, finding).unwrap();
            store.record_run_finished(scan_id, "completed", 1).unwrap();
        }
        store
    }

    fn true_positive_outcome() -> TriageOutcome {
        TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "confirmed once".to_string(),
            cost_usd: 0.01,
        }
    }

    fn runtime_outcome(outcome: TriageOutcome) -> TriageRuntimeOutcome {
        TriageRuntimeOutcome {
            outcome,
            cached: false,
        }
    }
}
