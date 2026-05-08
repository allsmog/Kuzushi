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
}
