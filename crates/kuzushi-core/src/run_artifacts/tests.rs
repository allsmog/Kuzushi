#[cfg(test)]
mod tests {
    use super::super::*;
    use std::fs;

    #[test]
    fn trace_step_v2_round_trip_preserves_new_fields() {
        let step = RunTraceStep::new(7, "tool", "semgrep started")
            .with_latency_ms(Some(143))
            .with_cost_usd(Some(0.0021))
            .with_module_id("semgrep")
            .with_verb("scan")
            .with_parent_step(3)
            .with_severity("warn")
            .with_started_at_ms(1_700_000_000_000)
            .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:abc123");

        let json = serde_json::to_string(&step).unwrap();
        let parsed: RunTraceStep = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, step);
        assert!(json.contains("\"module_id\":\"semgrep\""));
        assert!(json.contains("\"parent_step\":3"));
        assert!(json.contains("\"started_at_ms\":1700000000000"));
        assert!(json.contains("\"model\":\"openai:gpt-test\""));
        assert!(json.contains("\"provider\":\"openai\""));
        assert!(json.contains("\"prompt_hash\":\"fnv1a64:abc123\""));
    }

    #[test]
    fn trace_step_v1_forward_compat_leaves_new_fields_none() {
        let v1 = "{\"n\":1,\"kind\":\"tool\",\"label\":\"context:build started\"}";
        let parsed: RunTraceStep = serde_json::from_str(v1).unwrap();

        assert_eq!(parsed.n, 1);
        assert_eq!(parsed.kind, "tool");
        assert_eq!(parsed.label, "context:build started");
        assert!(parsed.module_id.is_none());
        assert!(parsed.verb.is_none());
        assert!(parsed.parent_step.is_none());
        assert!(parsed.severity.is_none());
        assert!(parsed.started_at_ms.is_none());
        assert!(parsed.model.is_none());
        assert!(parsed.provider.is_none());
        assert!(parsed.prompt_hash.is_none());
    }

    #[test]
    fn trace_step_v2_omits_unset_optional_fields_from_serialized_form() {
        let step = RunTraceStep::new(1, "tool", "context:build started");
        let json = serde_json::to_string(&step).unwrap();

        assert!(!json.contains("module_id"));
        assert!(!json.contains("verb"));
        assert!(!json.contains("parent_step"));
        assert!(!json.contains("severity"));
        assert!(!json.contains("started_at_ms"));
        assert!(!json.contains("model"));
        assert!(!json.contains("provider"));
        assert!(!json.contains("prompt_hash"));
    }

    #[test]
    fn trace_step_can_derive_module_and_verb_from_tool_name() {
        let step =
            RunTraceStep::new(1, "tool", "semgrep:scan started").with_tool_name("semgrep:scan");

        assert_eq!(step.module_id.as_deref(), Some("semgrep"));
        assert_eq!(step.verb.as_deref(), Some("scan"));
    }

    #[test]
    fn run_summary_rolls_up_llm_audit_metadata_from_trace() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-llm-audit";
        append_run_trace_step(
            tmp.path(),
            run_id,
            &RunTraceStep::new(3, "reasoning", "query · answer")
                .with_verb("query")
                .with_latency_ms(Some(42))
                .with_cost_usd(Some(0.0042))
                .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:abc123"),
        )
        .unwrap();

        write_run_summary(
            tmp.path(),
            &RunSummary::running(run_id, "tool", Some("agentic:test".to_string()), "target")
                .complete()
                .with_cost(Some(0.0042)),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(loaded.llm_calls.len(), 1);
        assert_eq!(loaded.llm_calls[0].model, "openai:gpt-test");
        assert_eq!(loaded.llm_calls[0].provider, "openai");
        assert_eq!(loaded.llm_calls[0].prompt_hash, "fnv1a64:abc123");
        assert_eq!(loaded.llm_calls[0].cost_usd, Some(0.0042));

        let metadata = fs::read_to_string(run_dir(tmp.path(), run_id).join("run.json")).unwrap();
        assert!(metadata.contains("\"llmCalls\""));
        assert!(metadata.contains("\"promptHash\": \"fnv1a64:abc123\""));
        assert!(!metadata.contains("query · answer"));
    }

    #[test]
    fn writes_summary_artifact_and_trace_under_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = new_run_id("tool");
        let summary = RunSummary::running(
            run_id.clone(),
            "tool",
            Some("context:build".to_string()),
            tmp.path().display().to_string(),
        );

        let summary_path = write_run_summary(tmp.path(), &summary).unwrap();
        assert!(summary_path.ends_with("summary.json"));
        assert_canonical_run_files_exist(tmp.path(), &run_id);
        assert_eq!(
            fs::read_to_string(tmp.path().join(".kuzushi/latest")).unwrap(),
            format!("{run_id}\n")
        );
        let result = serde_json::json!({"ok": true});
        let artifact =
            write_run_artifact_json(tmp.path(), &run_id, "result.json", "result", &result).unwrap();
        append_run_trace_step(
            tmp.path(),
            &run_id,
            &RunTraceStep::new(1, "tool", "context:build started"),
        )
        .unwrap();
        write_run_summary(tmp.path(), &summary.complete().with_artifact(artifact)).unwrap();

        let loaded = load_run_summary(tmp.path(), &run_id).unwrap();
        assert_eq!(loaded.status, "completed");
        assert_eq!(loaded.tool.as_deref(), Some("context:build"));
        assert_eq!(loaded.artifacts.len(), 1);
        let metadata = fs::read_to_string(run_dir(tmp.path(), &run_id).join("run.json")).unwrap();
        assert!(metadata.contains("\"status\": \"completed\""));
        assert!(load_run_failures(tmp.path(), &run_id)
            .unwrap()
            .failures
            .is_empty());
        assert_eq!(
            load_run_failures(tmp.path(), &run_id).unwrap().status,
            "completed"
        );
        let manifest_artifacts = load_run_artifacts(tmp.path(), &run_id).unwrap();
        assert_manifest_has(&manifest_artifacts, "run.json");
        assert_manifest_has_canonical_run_artifacts(&manifest_artifacts);
        assert_manifest_has(&manifest_artifacts, "context.json");
        assert_manifest_has(&manifest_artifacts, "result.json");
        let trace = fs::read_to_string(run_dir(tmp.path(), &run_id).join("trace.jsonl")).unwrap();
        assert!(trace.contains("context:build started"));
    }

    fn assert_canonical_run_files_exist(target: &Path, run_id: &str) {
        let dir = run_dir(target, run_id);
        for leaf in [
            "run.json",
            "summary.json",
            "events.jsonl",
            "trace.jsonl",
            "context.json",
            "attack-surface.json",
            "threat-model.json",
            "recommendations.json",
            "findings.json",
            "proof.json",
            "failures.json",
            "report.md",
            "artifacts.json",
        ] {
            assert!(dir.join(leaf).exists(), "missing canonical artifact {leaf}");
        }
    }

    fn assert_manifest_has(artifacts: &[RunArtifact], leaf: &str) {
        assert!(
            artifacts.iter().any(|artifact| artifact.path.ends_with(leaf)),
            "manifest missing artifact {leaf}"
        );
    }

    fn assert_manifest_has_canonical_run_artifacts(artifacts: &[RunArtifact]) {
        for leaf in [
            "run.json",
            "events.jsonl",
            "trace.jsonl",
            "context.json",
            "attack-surface.json",
            "threat-model.json",
            "recommendations.json",
            "findings.json",
            "proof.json",
            "failures.json",
            "report.md",
            "artifacts.json",
        ] {
            assert_manifest_has(artifacts, leaf);
        }
    }

    #[test]
    fn writes_events_and_failure_handoff_context_under_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-failure";
        let input = write_run_artifact_json(
            tmp.path(),
            run_id,
            "input.json",
            "input",
            &serde_json::json!({"enrichment": true}),
        )
        .unwrap();
        append_run_event(
            tmp.path(),
            run_id,
            &RunEvent::new(1, "tool", "started", "context:build started")
                .with_tool("context:build")
                .with_artifact(input.clone()),
        )
        .unwrap();
        let failure = write_run_failures(
            tmp.path(),
            run_id,
            "context:build",
            "failed",
            "LLM enrichment is unsupported",
            &[input],
        )
        .unwrap();

        assert!(failure.path.ends_with("failures.json"));
        let manifest_artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has(&manifest_artifacts, "input.json");
        assert_manifest_has(&manifest_artifacts, "failures.json");
        let events = fs::read_to_string(run_dir(tmp.path(), run_id).join("events.jsonl")).unwrap();
        assert!(events.contains("\"status\":\"started\""));

        let failures =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("failures.json")).unwrap();
        assert!(failures.contains("context:build did not complete successfully"));
        assert!(failures.contains("artifact-review-only"));
        assert!(failures.contains("input.json"));

        let loaded = load_run_failures(tmp.path(), run_id).unwrap();
        let context = &loaded.failures[0].agent_thread_context;
        assert_eq!(
            context.allowed_proof_level,
            "artifact-review-only; runtime verification did not run"
        );
        assert_eq!(context.failed_stage, "context:build");
        assert_eq!(context.cause, "LLM enrichment is unsupported");
        assert!(context.missing_artifacts.contains(&"trace.jsonl".to_string()));
        assert!(context.missing_artifacts.contains(&"context.json".to_string()));
        assert!(!context
            .missing_artifacts
            .contains(&"artifacts.json".to_string()));
        assert!(context
            .recovery_options
            .iter()
            .any(|option| option.contains("context:build")));
        assert!(context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.ends_with("failures.json")));
        assert!(context
            .next_files_or_artifacts_to_inspect
            .iter()
            .any(|path| path.ends_with("result.json")));
        assert!(context.next_files_or_artifacts_to_inspect.len() <= 12);
        assert!(context.fallback_prompt.contains("context:build"));
        assert!(context.fallback_prompt.contains("artifact-review-only"));
        assert!(context.fallback_prompt.contains("Inspect next:"));
        assert!(context.fallback_prompt.contains("failures.json"));
        assert!(context
            .claims_forbidden
            .contains(&"empirical proof claim".to_string()));
        assert_forbidden_success_claims(&context.claims_forbidden);
    }

    #[test]
    fn failed_tool_run_records_result_envelope_with_fallback_context() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-failed-result";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({"target": "."}));
        record_tool_run_failed(record, "semgrep binary missing");

        let dir = run_dir(tmp.path(), run_id);
        let result_body = fs::read_to_string(dir.join("result.json")).unwrap();
        let result = serde_json::from_str::<serde_json::Value>(&result_body).unwrap();

        assert_eq!(result["ok"], serde_json::json!(false));
        assert_eq!(result["status"], serde_json::json!("failed"));
        assert_eq!(result["errors"][0], serde_json::json!("semgrep binary missing"));
        assert_eq!(
            result["fallback_context"]["failedStage"],
            serde_json::json!("semgrep:scan")
        );
        assert!(result["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|artifact| artifact["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("failures.json"))));

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "failed");
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("result.json")));
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert!(manifest
            .iter()
            .any(|artifact| artifact.path.ends_with("result.json")));
    }

    #[test]
    fn tool_run_start_records_input_summary_event_and_trace() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-start";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");

        record_tool_run_started(record, &serde_json::json!({"target": "."}));

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "running");
        assert_eq!(summary.tool.as_deref(), Some("context:build"));
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("input.json")));
        let manifest_artifacts = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert_manifest_has(&manifest_artifacts, "run.json");
        assert_manifest_has(&manifest_artifacts, "input.json");
        let events = fs::read_to_string(run_dir(tmp.path(), run_id).join("events.jsonl")).unwrap();
        assert!(events.contains("\"status\":\"started\""));
        assert!(events.contains("\"artifact\""));
        let trace = fs::read_to_string(run_dir(tmp.path(), run_id).join("trace.jsonl")).unwrap();
        assert!(trace.contains("context:build started"));
    }

    #[test]
    fn tool_run_complete_promotes_result_snapshots_to_canonical_files() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-snapshots";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "summary": "snapshots ready",
                "recommendations": [{"tool": "semgrep:scan"}],
                "data": {
                    "snapshot": {
                        "repoContext": {"languages": ["Rust"]},
                        "attackSurfaceMap": [{"kind": "Route", "path": "/login"}]
                    },
                    "document": {"methodology": "STRIDE"},
                    "findings": [{"ruleId": "demo"}],
                    "proof": {"states": ["code_cited"]},
                    "reportMarkdown": "# Snapshot Report",
                    "reportSarif": {"version": "2.1.0", "runs": []}
                }
            }),
        );

        let dir = run_dir(tmp.path(), run_id);
        assert!(fs::read_to_string(dir.join("context.json"))
            .unwrap()
            .contains("repoContext"));
        assert!(fs::read_to_string(dir.join("attack-surface.json"))
            .unwrap()
            .contains("/login"));
        assert!(fs::read_to_string(dir.join("threat-model.json"))
            .unwrap()
            .contains("STRIDE"));
        assert!(fs::read_to_string(dir.join("recommendations.json"))
            .unwrap()
            .contains("semgrep:scan"));
        assert!(fs::read_to_string(dir.join("findings.json"))
            .unwrap()
            .contains("demo"));
        assert!(fs::read_to_string(dir.join("proof.json"))
            .unwrap()
            .contains("code_cited"));
        assert!(fs::read_to_string(dir.join("report.md"))
            .unwrap()
            .contains("Snapshot Report"));
        assert!(fs::read_to_string(dir.join("report.sarif"))
            .unwrap()
            .contains("\"version\": \"2.1.0\""));

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("context.json")));
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("report.md")));
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.path.ends_with("report.sarif") && artifact.kind == "sarif"
        }));
    }

    #[test]
    fn tool_run_complete_prefers_core_findings_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-core-findings";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "dep-hygiene:check");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "data": {
                    "verification": {"verified": 0, "results": []},
                    "findings": [{"packageName": "lodash"}],
                    "coreFindings": [{
                        "fingerprint": "dep-fp",
                        "tool": "dep-hygiene",
                        "ruleId": "dep-hygiene/package-json",
                        "filePath": "package.json",
                        "startLine": 1,
                        "staticProofState": "signal_only"
                    }]
                }
            }),
        );

        let body =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("findings.json")).unwrap();
        let findings = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(findings[0]["fingerprint"], serde_json::json!("dep-fp"));
        assert_eq!(findings[0]["tool"], serde_json::json!("dep-hygiene"));
        assert!(findings[0].get("packageName").is_none());

        let proof_body =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("proof.json")).unwrap();
        let proof = serde_json::from_str::<serde_json::Value>(&proof_body).unwrap();

        assert_eq!(proof["source"], serde_json::json!("normalized-findings"));
        assert_eq!(proof["runtimeVerification"], serde_json::json!(false));
        assert_eq!(proof["countsByState"]["signal_only"], serde_json::json!(1));
        assert_eq!(
            proof["findings"][0]["staticProofState"],
            serde_json::json!("signal_only")
        );
    }

    #[test]
    fn tool_run_complete_promotes_full_module_recommendation_report() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-recommendations";
        let record = ToolRunRecord::new(
            tmp.path(),
            run_id,
            "tool",
            "module-recommender:recommend",
        );

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "summary": "2 recommendations for /repo",
                "target": "/repo",
                "signals": {
                    "sourceFiles": 12,
                    "languages": ["TypeScript"],
                    "attackSurfaceHighRisk": 2
                },
                "capabilities": {
                    "availableToolCount": 5,
                    "recommendedToolCount": 2,
                    "skippedMissingTools": []
                },
                "recommendations": [
                    {
                        "moduleId": "semgrep",
                        "tool": "semgrep:scan",
                        "priority": "high",
                        "reason": "source files are present",
                        "signals": ["12 source files"],
                        "requiresRuntime": false,
                        "nextInput": {"target": "/repo"}
                    }
                ],
                "warnings": [],
                "errors": []
            }),
        );

        let body =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("recommendations.json")).unwrap();
        let report = serde_json::from_str::<serde_json::Value>(&body).unwrap();

        assert_eq!(report["summary"], serde_json::json!("2 recommendations for /repo"));
        assert_eq!(report["signals"]["sourceFiles"], serde_json::json!(12));
        assert_eq!(
            report["capabilities"]["availableToolCount"],
            serde_json::json!(5)
        );
        assert_eq!(
            report["recommendations"][0]["tool"],
            serde_json::json!("semgrep:scan")
        );
    }

    #[test]
    fn tool_run_complete_records_output_declared_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-declared-artifacts";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "sast:scan");
        let report = tmp.path().join("report.md");
        let summary_json = tmp.path().join("summary.json");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "artifacts": [
                    {"label": "report", "path": report.display().to_string(), "kind": "markdown"}
                ],
                "data": {
                    "artifacts": {
                        "summary": summary_json.display().to_string()
                    }
                }
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.label == "report" && artifact.path == report.display().to_string()
        }));
        assert!(summary.artifacts.iter().any(|artifact| {
            artifact.label == "summary" && artifact.path == summary_json.display().to_string()
        }));
        let manifest = load_run_artifacts(tmp.path(), run_id).unwrap();
        assert!(manifest
            .iter()
            .any(|artifact| artifact.path == report.display().to_string()));
        assert!(manifest
            .iter()
            .any(|artifact| artifact.path == summary_json.display().to_string()));
    }

    #[test]
    fn tool_run_complete_records_contract_complete_result_envelope() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-result-envelope";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "context:build");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(record, &serde_json::json!({"ok": true}));

        let result =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();

        assert_eq!(output["ok"], serde_json::json!(true));
        assert_eq!(output["status"], serde_json::json!("completed"));
        assert_eq!(output["summary"], serde_json::json!("tool completed"));
        assert!(output["artifacts"].as_array().is_some());
        assert!(output["warnings"].as_array().unwrap().is_empty());
        assert!(output["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn skipped_tool_result_preserves_skipped_status_without_failure_handoff() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-skipped";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "skipped",
                "summary": "scanner disabled by task policy",
                "warnings": [],
                "errors": [],
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "skipped");
        let failures = load_run_failures(tmp.path(), run_id).unwrap();
        assert_eq!(failures.status, "skipped");
        assert!(failures.failures.is_empty());
    }

    #[test]
    fn partial_tool_result_writes_failure_handoff_and_warn_trace() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-partial";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "status": "partial",
                "summary": "semgrep binary missing",
                "warnings": ["scanner unavailable"],
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "partial");
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("failures.json")));
        assert!(summary
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("result.json")));
        let failures =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("failures.json")).unwrap();
        assert!(failures.contains("semgrep:scan did not complete successfully"));
        let result =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();
        assert_eq!(
            output["fallback_context"]["failedStage"],
            serde_json::json!("semgrep:scan")
        );
        assert!(output["fallback_context"]["claimsForbidden"]
            .as_array()
            .unwrap()
            .iter()
            .any(|claim| claim == "verified claim"));
        let trace = fs::read_to_string(run_dir(tmp.path(), run_id).join("trace.jsonl")).unwrap();
        assert!(trace.contains("\"kind\":\"tool-progress\""));
        assert!(trace.contains("\"severity\":\"warn\""));
    }

    #[test]
    fn tool_run_status_aliases_are_trimmed_and_case_insensitive() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-status-alias";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": false,
                "status": " ERROR ",
                "summary": "scanner failed",
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "failed");
        let result =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();
        assert_eq!(output["status"], serde_json::json!("failed"));
        assert_eq!(output["errors"][0], serde_json::json!("scanner failed"));
        let failures = load_run_failures(tmp.path(), run_id).unwrap();
        assert_eq!(failures.status, "failed");
        assert_eq!(
            failures.failures[0].agent_thread_context.failed_stage,
            "semgrep:scan"
        );
    }

    #[test]
    fn ok_false_tool_result_writes_failure_handoff_without_explicit_status() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "tool-ok-false";
        let record = ToolRunRecord::new(tmp.path(), run_id, "tool", "semgrep:scan");

        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": false,
                "summary": "scanner failed",
                "errors": ["scanner missing"],
            }),
        );

        let summary = load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(summary.status, "failed");
        let failures = load_run_failures(tmp.path(), run_id).unwrap();
        assert_eq!(failures.status, "failed");
        assert_eq!(failures.failures[0].error, "scanner missing");
        let result =
            fs::read_to_string(run_dir(tmp.path(), run_id).join("result.json")).unwrap();
        let output = serde_json::from_str::<serde_json::Value>(&result).unwrap();
        assert_eq!(
            output["fallback_context"]["failedStage"],
            serde_json::json!("semgrep:scan")
        );
    }

    #[test]
    fn lists_run_summaries_sorted_and_ignores_incomplete_entries() {
        let tmp = tempfile::tempdir().unwrap();

        assert!(list_run_summaries(tmp.path()).unwrap().is_empty());

        let first = RunSummary::running("run-a", "scan", None, "target-a").complete();
        let second =
            RunSummary::running("run-b", "tool", Some("ctx:build".to_string()), "target-b")
                .complete();
        write_run_summary(tmp.path(), &first).unwrap();
        write_run_summary(tmp.path(), &second).unwrap();

        let root = runs_root(tmp.path());
        fs::write(root.join("not-a-run"), "ignored").unwrap();
        fs::create_dir_all(root.join("missing-summary")).unwrap();
        fs::create_dir_all(root.join("invalid-summary")).unwrap();
        fs::write(root.join("invalid-summary").join("summary.json"), "{").unwrap();
        fs::create_dir_all(root.join("run-c")).unwrap();
        fs::write(
            root.join("run-c").join("run.json"),
            serde_json::to_string(&RunSummary::running("run-c", "tool", None, "target-c")).unwrap(),
        )
        .unwrap();
        assert_eq!(load_run_summary(tmp.path(), "run-c").unwrap().kind, "tool");

        let run_ids = list_run_summaries(tmp.path())
            .unwrap()
            .into_iter()
            .map(|summary| summary.run_id)
            .collect::<Vec<_>>();

        assert_eq!(run_ids, vec!["run-c", "run-b", "run-a"]);
    }

    #[test]
    fn run_metadata_reads_run_json_before_legacy_summary_json() {
        let tmp = tempfile::tempdir().unwrap();
        let root = runs_root(tmp.path());
        fs::create_dir_all(root.join("run-canonical")).unwrap();
        fs::write(
            root.join("run-canonical").join("summary.json"),
            serde_json::to_string(&RunSummary::running(
                "run-canonical",
                "legacy",
                None,
                "legacy-target",
            ))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("run-canonical").join("run.json"),
            serde_json::to_string(&RunSummary::running(
                "run-canonical",
                "tool",
                Some("context:build".to_string()),
                "canonical-target",
            ))
            .unwrap(),
        )
        .unwrap();

        let loaded = load_run_summary(tmp.path(), "run-canonical").unwrap();
        assert_eq!(loaded.kind, "tool");
        assert_eq!(loaded.target, "canonical-target");

        let listed = list_run_summaries(tmp.path()).unwrap();
        assert_eq!(listed[0].kind, "tool");
        assert_eq!(listed[0].target, "canonical-target");
    }

    fn assert_forbidden_success_claims(claims: &[String]) {
        for claim in [
            "success claim without explicit verification",
            "verified claim",
            "exploited claim",
            "fixed claim",
            "false positive verdict",
            "no vulnerability verdict",
        ] {
            assert!(claims.contains(&claim.to_string()), "missing claim {claim}");
        }
    }

    #[test]
    fn list_run_summaries_marks_dead_process_running_summary_interrupted() {
        let tmp = tempfile::tempdir().unwrap();
        if !std::path::Path::new("/proc").exists() {
            return;
        }
        let summary =
            RunSummary::running("run-stale", "tool", None, "target").with_process_id(u32::MAX);
        write_run_summary(tmp.path(), &summary).unwrap();

        let loaded = list_run_summaries(tmp.path()).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, "interrupted");
        assert!(loaded[0].completed_at_unix.is_some());
        assert!(loaded[0].process_id.is_none());
        assert!(loaded[0]
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("no longer running"));
    }
}
