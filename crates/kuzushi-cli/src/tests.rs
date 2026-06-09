#[cfg(test)]
mod tests {
    use crate::adapters::auth_bridge::{
        bridge_ping_error, bridge_ping_summary, parse_bridge_stdout, run_auth_ping_bridge,
    };
    use crate::adapters::auth_oauth::{anthropic_oauth_readiness_message, auth_ping_model};
    use crate::adapters::auth_ping::{auth_ping_provider_kind, AuthPingLog};
    use crate::application::config::{config_command, ensure_config_init_allowed};
    use crate::application::run_tool::{
        apply_option_override, output_with_cli_run_artifacts, parse_option_override,
        start_cli_tool_run_with_loaded_modules,
    };
    use crate::application::runs::{filter_runs_by_status, run_trace_path};
    use crate::application::runs_diff::runs_diff;
    use crate::application::runs_prune::runs_prune_plan;
    use crate::application::scan::{scan_scope_body, scan_tool_input, scan_worktree_suffix};
    use crate::application::suppressions::{suppressions_command_output, suppressions_plain_lines};
    use crate::command::{ConfigCommand, McpBackend, ScanModeArg};
    use crate::doctor::{check_model_config, deterministic_capability_checks, DoctorStatus};
    use crate::mcp::{mcp_health_spawn_error, mcp_spawn_error};
    use crate::presentation::{
        ci_line, format_duration, plain_output_requested, scan_json_output, scan_started_body,
        shell_startup_progress_messages, should_emit_shell_startup_progress,
    };
    use crate::presentation::{
        parse_trace_json_lines, run_summary_plain, runs_list_output, runs_show_output,
        runs_trace_output,
    };
    use crate::tool_requirements::{
        tool_defaults_to_workspace, tool_needs_finding_store, tool_needs_runtime,
    };
    use crate::tool_run_artifacts::{fail_cli_tool_run, finish_cli_tool_run};
    use kuzushi_core::{
        latest_run_path, load_run_summary, run_dir, write_run_summary, RunSummary, ToolOptionStore,
        WorkspaceTarget,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn ci_line_uses_relative_timestamp_and_prefix() {
        let started = std::time::Instant::now();
        let line = ci_line(started, "scan", "demo started");
        assert!(line.starts_with("[+"), "got: {line}");
        assert!(line.ends_with("scan: demo started"));
    }

    #[test]
    fn format_duration_below_one_minute_is_decimal_seconds() {
        assert_eq!(
            format_duration(std::time::Duration::from_millis(500)),
            "0.5s"
        );
        assert_eq!(format_duration(std::time::Duration::from_secs(12)), "12.0s");
    }

    #[test]
    fn format_duration_above_one_minute_is_compound() {
        assert_eq!(
            format_duration(std::time::Duration::from_secs(78)),
            "1m 18s"
        );
        assert_eq!(
            format_duration(std::time::Duration::from_secs(3600)),
            "60m 0s"
        );
    }

    #[test]
    fn shell_startup_progress_names_real_first_finding_commands() {
        let bare = shell_startup_progress_messages(None).join("\n");
        assert!(bare.contains("loading config"));
        assert!(bare.contains("native registry"));
        assert!(bare.contains("first finding: scan ., then findings"));

        let targeted = shell_startup_progress_messages(Some(Path::new("."))).join("\n");
        assert!(targeted.contains("target ."));
        assert!(targeted.contains("first finding: scan, then findings"));
        assert!(!targeted.contains("scan ."));
    }

    #[test]
    fn doctor_lists_deterministic_module_capabilities() {
        let names = deterministic_capability_checks()
            .into_iter()
            .map(|check| check.name)
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "secret-scan",
                "dep-hygiene",
                "iac-scan",
                "license-scan",
                "cargo-audit"
            ]
        );
    }

    #[test]
    fn run_summary_plain_includes_optional_fields_and_artifacts() {
        let summary_path = run_dir(Path::new("/repo"), "run-123").join("summary.json");
        let summary =
            RunSummary::running("run-123", "scan", Some("sast:scan".to_string()), "/repo")
                .failed("boom")
                .with_findings(Some(2))
                .with_cost(Some(0.125))
                .with_artifact(kuzushi_core::RunArtifact {
                    label: "summary".to_string(),
                    path: summary_path.display().to_string(),
                    kind: "json".to_string(),
                });
        let mut summary = summary;
        summary.started_at_unix = 100;
        summary.completed_at_unix = Some(178);

        let rendered = run_summary_plain(&summary);

        assert!(rendered.contains("Run run-123"));
        assert!(rendered.contains("Status: failed"));
        assert!(rendered.contains("Tool: sast:scan"));
        assert!(rendered.contains("Duration: 1m 18s"));
        assert!(rendered.contains("Findings: 2"));
        assert!(rendered.contains("Cost USD: 0.1250"));
        assert!(rendered.contains("Error: boom"));
        assert!(rendered.contains(&format!("summary: {}", summary_path.display())));
        assert!(rendered.ends_with("Next: kuzushi runs trace run-123\n"));
    }

    #[test]
    fn runs_list_output_covers_empty_plain_rows_and_json() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let empty = runs_list_output(&workspace, &[], false).unwrap();
        assert!(empty.contains("no run artifacts found"));
        assert!(empty.contains("Next: kuzushi scan"));

        let runs = vec![
            summary_started_at("run-1", 100).with_findings(Some(3)),
            RunSummary::running("run-2", "tool", Some("ctx:build".to_string()), "target"),
        ];
        let plain = runs_list_output(&workspace, &runs, false).unwrap();
        assert!(plain.contains("Run artifacts"));
        assert!(plain.contains("run-1"));
        assert!(plain.contains("completed"));
        assert!(plain.contains("tool"));
        assert!(plain.contains("duration=1.0s"));
        assert!(plain.contains("findings=3"));
        assert!(plain.contains("run-2  running   ctx:build"));
        assert!(plain.ends_with('\n'));

        let json = runs_list_output(&workspace, &runs, true).unwrap();
        assert!(json.contains("\"runId\": \"run-1\""));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn runs_list_status_filter_keeps_matching_statuses() {
        let runs = vec![
            RunSummary::running("run-1", "scan", None, "target").complete(),
            RunSummary::running("run-2", "scan", None, "target").failed("boom"),
            RunSummary::running("run-3", "scan", None, "target"),
        ];
        let filtered =
            filter_runs_by_status(runs, &["completed".to_string(), "failed".to_string()]).unwrap();

        let run_ids = filtered
            .iter()
            .map(|run| run.run_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(run_ids, vec!["run-1", "run-2"]);
    }

    #[test]
    fn runs_list_status_filter_rejects_unknown_statuses() {
        let error = filter_runs_by_status(Vec::new(), &["done".to_string()]).unwrap_err();

        assert!(error.to_string().contains("unknown run status"));
    }

    #[test]
    fn runs_show_output_covers_plain_and_json() {
        let summary = RunSummary::running("run-123", "scan", None, "/repo").complete();

        assert!(runs_show_output(&summary, false)
            .unwrap()
            .contains("Run run-123"));
        assert!(runs_show_output(&summary, true)
            .unwrap()
            .contains("\"runId\": \"run-123\""));
    }

    #[test]
    fn cli_tool_run_preserves_started_summary_and_artifact_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let input = serde_json::json!({"model": "local", "maxFindings": 1});
        let config = kuzushi_core::V2Config {
            model: Some("openai:gpt-test".to_string()),
            ..Default::default()
        };
        let loaded_modules = vec![
            "builtin:agentic-sast".to_string(),
            "builtin:context".to_string(),
        ];
        let run_id = start_cli_tool_run_with_loaded_modules(
            tmp.path(),
            "agentic-sast:scan",
            &input,
            &config,
            loaded_modules.clone(),
        );
        let started = load_run_summary(tmp.path(), &run_id).unwrap();

        finish_cli_tool_run(
            tmp.path(),
            &run_id,
            "agentic-sast:scan",
            &serde_json::json!({
                "ok": true,
                "costUsd": 0.0,
                "data": { "findings": [] }
            }),
        );

        let summary = load_run_summary(tmp.path(), &run_id).unwrap();
        assert_eq!(summary.status, "completed");
        assert_eq!(summary.started_at_unix, started.started_at_unix);
        assert_eq!(summary.model.as_deref(), Some("openai:gpt-test"));
        assert_eq!(summary.loaded_modules, loaded_modules);
        assert!(summary.config_hash.as_deref().is_some_and(|hash| {
            hash.starts_with("sha256:") && hash.len() == "sha256:".len() + 64
        }));
        assert!(started.process_id.is_some());
        assert!(summary.process_id.is_none());
        let labels = summary
            .artifacts
            .iter()
            .map(|artifact| artifact.label.as_str())
            .collect::<Vec<_>>();
        assert_eq!(labels, vec!["tool input", "findings", "tool result"]);
        for artifact in &summary.artifacts {
            assert!(
                std::path::Path::new(&artifact.path).exists(),
                "missing artifact {}",
                artifact.path
            );
        }

        let failed_run_id = start_cli_tool_run_with_loaded_modules(
            tmp.path(),
            "agentic-sast:scan",
            &input,
            &config,
            Vec::new(),
        );
        fail_cli_tool_run(
            tmp.path(),
            &failed_run_id,
            "agentic-sast:scan",
            "bridge failed",
        );

        let failed_summary = load_run_summary(tmp.path(), &failed_run_id).unwrap();
        assert_eq!(failed_summary.status, "failed");
        assert_eq!(failed_summary.error.as_deref(), Some("bridge failed"));
        assert_eq!(failed_summary.model.as_deref(), Some("openai:gpt-test"));
        assert!(failed_summary.config_hash.is_some());
        let failed_labels = failed_summary
            .artifacts
            .iter()
            .map(|artifact| artifact.label.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            failed_labels,
            vec!["tool input", "failure handoff", "tool result"]
        );
        for artifact in &failed_summary.artifacts {
            assert!(
                std::path::Path::new(&artifact.path).exists(),
                "missing artifact {}",
                artifact.path
            );
        }
    }

    #[test]
    fn cli_completed_output_includes_recorded_run_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let input = serde_json::json!({});
        let config = kuzushi_core::V2Config::default();
        let run_id = start_cli_tool_run_with_loaded_modules(
            tmp.path(),
            "workspace:status",
            &input,
            &config,
            Vec::new(),
        );
        finish_cli_tool_run(
            tmp.path(),
            &run_id,
            "workspace:status",
            &serde_json::json!({
                "ok": true,
                "status": "completed",
                "artifacts": []
            }),
        );

        let output = output_with_cli_run_artifacts(
            tmp.path(),
            &run_id,
            serde_json::json!({
                "ok": true,
                "status": "completed",
                "artifacts": []
            }),
        );
        let artifacts = output["artifacts"].as_array().unwrap();

        assert!(artifacts.iter().any(|artifact| {
            artifact["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("result.json"))
        }));
    }

    #[test]
    fn trace_json_parser_skips_blank_lines_and_reports_values() {
        let steps = parse_trace_json_lines(
            Path::new("/tmp/trace.jsonl"),
            "\n{\"n\":1,\"kind\":\"plan\"}\n\n{\"n\":2,\"kind\":\"llm\"}\n",
        )
        .unwrap();

        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["kind"], "plan");
        assert_eq!(steps[1]["n"], 2);
    }

    #[test]
    fn runs_trace_output_covers_plain_and_json() {
        let body = "{\"n\":1,\"kind\":\"plan\",\"label\":\"draft\"}\n";

        let plain = runs_trace_output(Path::new("/tmp/trace.jsonl"), body, false).unwrap();
        assert!(plain.contains("plan"));
        assert!(plain.contains("draft"));
        assert!(plain.contains("[-]"));
        let json = runs_trace_output(Path::new("/tmp/trace.jsonl"), body, true).unwrap();
        assert!(json.contains("\"kind\": \"plan\""));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn runs_trace_output_renders_module_and_verb_columns() {
        let body = "{\"n\":1,\"kind\":\"tool\",\"label\":\"semgrep started\",\
                    \"module_id\":\"semgrep\",\"verb\":\"scan\"}\n\
                    {\"n\":2,\"kind\":\"reasoning\",\"label\":\"clustering\",\
                    \"module_id\":\"taint-iris\",\"verb\":\"hunt\",\"parent_step\":1,\
                    \"latency_ms\":143,\"cost_usd\":0.0021,\"severity\":\"info\"}\n";

        let plain = runs_trace_output(Path::new("/tmp/trace.jsonl"), body, false).unwrap();

        assert!(plain.contains("[semgrep:scan]"));
        assert!(plain.contains("[taint-iris:hunt]"));
        assert!(plain.contains("parent=1"));
        assert!(plain.contains("143ms"));
        assert!(plain.contains("$0.0021"));
        assert!(plain.contains("sev=info"));
    }

    #[test]
    fn run_trace_path_uses_shared_trace_artifact_spec() {
        let workspace = WorkspaceTarget::new(PathBuf::from(".")).unwrap();
        let leaf = kuzushi_core::run_artifacts::canonical_run_artifact_spec("trace.jsonl")
            .expect("trace artifact spec")
            .leaf;

        assert_eq!(
            run_trace_path(&workspace, "run-123"),
            run_dir(workspace.root(), "run-123").join(leaf)
        );
    }

    #[test]
    fn runs_prune_plan_keeps_newest_and_filters_old_runs() {
        let now = 2_000_000;
        let runs = vec![
            summary_started_at("run-old", now - 10 * 86_400),
            summary_started_at("run-new", now - 60),
            summary_started_at("run-middle", now - 5 * 86_400),
        ];

        let plan = runs_prune_plan(&runs, Some(1), Some(1), now).unwrap();

        assert_eq!(plan.run_ids, vec!["run-old", "run-middle"]);
    }

    #[test]
    fn runs_prune_plan_requires_a_retention_rule() {
        let error = runs_prune_plan(&[], None, None, 1).unwrap_err();

        assert!(error
            .to_string()
            .contains("requires --older-than-days or --keep-last"));
    }

    #[test]
    fn runs_prune_command_deletes_matching_run_directories() {
        let temp = tempfile::tempdir().unwrap();
        write_run_summary(
            temp.path(),
            &summary_started_at("run-old", 1_000_000 - 10 * 86_400),
        )
        .unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-new", 1_000_000)).unwrap();

        crate::application::runs_prune::runs_prune_command(
            Some(temp.path().to_path_buf()),
            None,
            Some(1),
            false,
            false,
        )
        .unwrap();

        assert!(!run_dir(temp.path(), "run-old").exists());
        assert!(run_dir(temp.path(), "run-new").exists());
        assert_eq!(
            std::fs::read_to_string(latest_run_path(temp.path())).unwrap(),
            "run-new\n"
        );
    }

    #[test]
    fn runs_diff_classifies_new_fixed_drifted_and_stable_findings() {
        let temp = tempfile::tempdir().unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-a", 1_000_000)).unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-b", 1_000_100)).unwrap();
        write_findings_snapshot(
            temp.path(),
            "run-a",
            serde_json::json!([
                {"fingerprint": "fixed", "severity": "high", "confidence": "high"},
                {"fingerprint": "drift", "severity": "medium", "confidence": "low", "triage": {"verdict": "needs_more_info"}},
                {"fingerprint": "stable", "severity": "low", "confidence": 0.5}
            ]),
        );
        write_findings_snapshot(
            temp.path(),
            "run-b",
            serde_json::json!([
                {"fingerprint": "new", "severity": "critical", "confidence": "high"},
                {"fingerprint": "drift", "severity": "high", "confidence": "medium", "triage": {"verdict": "true_positive"}},
                {"fingerprint": "stable", "severity": "low", "confidence": 0.5}
            ]),
        );

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert_eq!(diff.new, vec!["new"]);
        assert_eq!(diff.fixed, vec!["fixed"]);
        assert_eq!(diff.stable, 1);
        assert_eq!(diff.drifted.len(), 1);
        assert_eq!(diff.drifted[0].fingerprint, "drift");
        assert_eq!(diff.drifted[0].before.severity.as_deref(), Some("medium"));
        assert_eq!(diff.drifted[0].after.severity.as_deref(), Some("high"));
        assert_eq!(
            diff.drifted[0].after.verdict.as_deref(),
            Some("true_positive")
        );
    }

    #[test]
    fn suppressions_plain_lines_cover_empty_and_recorded_states() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let empty = suppressions_plain_lines(&workspace, &[]);
        assert!(empty.iter().any(|line| line == "none recorded"));
        assert!(empty
            .iter()
            .any(|line| line.contains("kuzushi suppress F-0001")));

        let record = kuzushi_core::WhiteboxSuppressionRecord {
            id: "sup-1".to_string(),
            scope: kuzushi_core::WhiteboxSuppressionScope {
                finding_fingerprint: Some("fp".to_string()),
                rule_id: "rule".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 7,
                end_line: 8,
                snippet_hash: "hash".to_string(),
            },
            evidence: Vec::new(),
            reason: "accepted risk".to_string(),
            author: "tester".to_string(),
            created_at_unix: 1,
            expires_at_unix: 2,
            metadata: serde_json::json!({}),
        };
        let rendered = suppressions_plain_lines(&workspace, &[record]).join("\n");

        assert!(rendered.contains("sup-1  src/lib.rs:7  expires=2  reason=accepted risk"));
        assert!(!rendered.contains("none recorded"));
    }

    #[test]
    fn suppressions_command_output_covers_plain_and_json() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let record = kuzushi_core::WhiteboxSuppressionRecord {
            id: "sup-1".to_string(),
            scope: kuzushi_core::WhiteboxSuppressionScope {
                finding_fingerprint: None,
                rule_id: "rule".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 7,
                end_line: 8,
                snippet_hash: "hash".to_string(),
            },
            evidence: Vec::new(),
            reason: "accepted risk".to_string(),
            author: "tester".to_string(),
            created_at_unix: 1,
            expires_at_unix: 2,
            metadata: serde_json::json!({}),
        };

        let plain = suppressions_command_output(&workspace, &[record.clone()], false).unwrap();
        assert!(plain.contains("sup-1  src/lib.rs:7"));
        assert!(plain.ends_with('\n'));

        let json = suppressions_command_output(&workspace, &[record], true).unwrap();
        assert!(json.contains("\"id\": \"sup-1\""));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn plain_flag_suppresses_tty_startup_progress() {
        assert!(plain_output_requested(true));
        assert!(!should_emit_shell_startup_progress(true));
    }

    #[test]
    fn auth_ping_model_preserves_operator_override_then_config_without_fallback() {
        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("openai:gpt-5.4".to_string());

        assert_eq!(
            auth_ping_model(Some("anthropic:claude-sonnet-4-5".to_string()), &config).unwrap(),
            "anthropic:claude-sonnet-4-5"
        );
        assert_eq!(auth_ping_model(None, &config).unwrap(), "openai:gpt-5.4");

        config.model = None;
        let err = auth_ping_model(None, &config).unwrap_err().to_string();
        assert!(err.contains("auth ping requires an explicit model"));
    }

    #[test]
    fn auth_ping_accepts_only_public_provider_selectors() {
        assert!(auth_ping_provider_kind("openai").is_ok());
        assert!(auth_ping_provider_kind("anthropic").is_ok());
        assert!(auth_ping_provider_kind("codex").is_err());
        assert!(auth_ping_provider_kind(&format!("openai-{}", "codex")).is_err());
    }

    #[test]
    fn doctor_model_check_uses_shared_model_policy() {
        let mut config = kuzushi_core::V2Config::default();
        config.model = None;

        let check = check_model_config(&config);

        assert_eq!(check.status, DoctorStatus::Warn);
        assert!(check.detail.contains("no fallback model will be selected"));

        config.model = Some(" openai : gpt-5.5 ".to_string());

        let check = check_model_config(&config);

        assert_eq!(check.status, DoctorStatus::Ok);
        assert!(check.detail.contains("provider openai"));

        config.model = Some("gpt-5.5".to_string());
        let check = check_model_config(&config);

        assert_eq!(check.status, DoctorStatus::Fail);
        assert!(check.detail.contains("provider:model"));
    }

    #[test]
    fn auth_ping_readiness_messages_cover_oauth_states() {
        let (ok, ready) =
            anthropic_oauth_readiness_message(kuzushi_openai::OauthReadiness::Ready {
                expires_at_ms: 0,
            });
        assert!(ok);
        assert!(ready.contains("oauth credentials ready"));

        let (ok, expired) =
            anthropic_oauth_readiness_message(kuzushi_openai::OauthReadiness::Expired {
                expires_at_ms: 0,
            });
        assert!(ok);
        assert!(expired.contains("will refresh on next call"));

        let missing_path = PathBuf::from("/tmp/kuzushi-oauth.json");
        let (ok, missing) =
            anthropic_oauth_readiness_message(kuzushi_openai::OauthReadiness::Missing {
                searched: missing_path.clone(),
            });
        assert!(!ok);
        assert!(missing.contains(&missing_path.display().to_string()));

        let (ok, invalid) =
            anthropic_oauth_readiness_message(kuzushi_openai::OauthReadiness::Invalid {
                searched: missing_path,
                reason: "malformed json".to_string(),
            });
        assert!(!ok);
        assert!(invalid.contains("malformed json"));
    }

    #[test]
    fn bridge_ping_error_and_summary_parse_bridge_json() {
        let parsed = parse_bridge_stdout(
            br#"{"ok":true,"auth_mode":"oauth","latency_ms":7,"input_tokens":2,"output_tokens":3,"cost_usd":0.0042}"#,
        )
        .unwrap();

        assert_eq!(bridge_ping_error(&parsed), None);
        assert_eq!(
            bridge_ping_summary(&parsed),
            "round-trip ok via oauth (7ms, 2/3 tokens, ~$0.00420)"
        );

        let failed = serde_json::json!({"ok": false, "error": "bad credentials"});
        assert_eq!(
            bridge_ping_error(&failed),
            Some("bad credentials".to_string())
        );
    }

    #[test]
    fn run_auth_ping_bridge_round_trips_json_over_stdio() {
        let mut log = AuthPingLog::default();
        let envelope = serde_json::json!({
            "ok": true,
            "auth_mode": "echo",
            "latency_ms": 1,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0
        });

        let parsed = run_auth_ping_bridge(&["cat".to_string()], &envelope, &mut log).unwrap();

        assert_eq!(parsed, envelope);
    }

    #[test]
    fn config_show_and_path_commands_return_success() {
        let temp = tempfile::tempdir().unwrap();

        config_command(ConfigCommand::Show, Some(temp.path().to_path_buf())).unwrap();
        config_command(ConfigCommand::Path, None).unwrap();
    }

    #[test]
    fn config_init_guard_rejects_existing_path_unless_forced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "existing").unwrap();

        assert!(ensure_config_init_allowed(&path, false)
            .unwrap_err()
            .to_string()
            .contains("--force"));
        ensure_config_init_allowed(&path, true).unwrap();
    }

    #[test]
    fn run_tool_policy_predicates_cover_workspace_store_and_runtime() {
        assert!(tool_defaults_to_workspace(
            "systems-hunt:deep-semantic-hunt"
        ));
        assert!(tool_defaults_to_workspace("offense-review:threat-hunt"));
        assert!(tool_defaults_to_workspace("taint-iris-next:dataflow-plan"));
        assert!(tool_defaults_to_workspace(
            "taint-iris-next:source-sink-trace"
        ));
        assert!(tool_defaults_to_workspace("taint-iris-next:finding-review"));
        assert!(tool_defaults_to_workspace("module-recommender:recommend"));
        assert!(tool_defaults_to_workspace("findings:list"));
        assert!(!tool_defaults_to_workspace("clang.health"));

        assert!(tool_needs_finding_store("variant:hunt"));
        assert!(tool_needs_finding_store("offense-review:threat-hunt"));
        assert!(tool_needs_finding_store("taint-iris-next:finding-review"));
        assert!(!tool_needs_finding_store("taint-iris-next:dataflow-plan"));
        assert!(!tool_needs_finding_store(
            "taint-iris-next:source-sink-trace"
        ));
        assert!(tool_needs_finding_store("module-recommender:recommend"));
        assert!(tool_needs_finding_store("prompt-armor:scan"));
        assert!(!tool_needs_finding_store("context-lite:index"));

        assert!(tool_needs_runtime("deep-audit:run", &serde_json::json!({})));
        assert!(tool_needs_runtime(
            "sast:scan",
            &serde_json::json!({"triage": true})
        ));
        assert!(!tool_needs_runtime(
            "sast:scan",
            &serde_json::json!({"whiteboxStatic": true})
        ));
    }

    #[test]
    fn scan_helpers_format_scope_tasks_and_json_summary() {
        let scope = scan_scope_body(&[PathBuf::from("src/lib.rs"), PathBuf::from("Cargo.toml")]);
        assert_eq!(scope, "src/lib.rs\nCargo.toml\n");
        assert_eq!(scan_tool_input(None, &[], None), serde_json::json!({}));
        assert_eq!(
            scan_tool_input(
                Some(ScanModeArg::Standard),
                &["sast".to_string()],
                Some(true)
            ),
            serde_json::json!({
                "mode": "standard",
                "taskMode": "manual",
                "tasks": ["sast"],
                "triage": true
            })
        );
        assert_eq!(scan_worktree_suffix(true), "(+worktree)");
        assert_eq!(scan_worktree_suffix(false), "");

        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("anthropic:claude-sonnet-4-5".to_string());
        assert!(scan_started_body(
            Path::new("."),
            &config,
            &["sast".to_string(), "triage".to_string()]
        )
        .contains("tasks=sast,triage"));

        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let data = serde_json::json!({
            "runId": "run-1",
            "target": ".",
            "findingsCount": 2,
            "mode": "standard",
            "whiteboxStatic": true,
            "triage": false,
        });
        let summary = scan_json_output(&workspace, &data);
        assert_eq!(summary["findingsCount"], serde_json::json!(2));
        assert!(summary["db"].as_str().unwrap().contains(".kuzushi"));
    }

    #[test]
    fn run_option_overrides_are_session_scoped_and_preserve_explicit_input_precedence() {
        assert_eq!(
            parse_option_override(" triage = yes ").unwrap(),
            ("triage".to_string(), "yes".to_string())
        );
        assert!(parse_option_override("missing-equals").is_err());
        assert!(parse_option_override("=value").is_err());

        let mut store = ToolOptionStore::new();
        apply_option_override(&mut store, "sast:scan", "triage=yes").unwrap();
        apply_option_override(&mut store, "sast:scan", "disabled_tasks=semgrep,codeql").unwrap();

        let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
        let prepared = registry
            .prepare_tool_input(
                "sast:scan",
                serde_json::json!({"triage": false}),
                Some(&store),
            )
            .unwrap();

        assert_eq!(prepared["triage"], serde_json::json!(false));
        assert_eq!(
            prepared["disabledTasks"],
            serde_json::json!(["semgrep", "codeql"])
        );
        assert_eq!(prepared.get("disabled_tasks"), None);
    }

    fn summary_started_at(run_id: &str, started_at_unix: u64) -> RunSummary {
        let mut summary = RunSummary::running(run_id, "tool", None, "target").complete();
        summary.started_at_unix = started_at_unix;
        summary.completed_at_unix = Some(started_at_unix + 1);
        summary
    }

    fn write_findings_snapshot(target: &Path, run_id: &str, value: serde_json::Value) {
        let leaf = kuzushi_core::run_artifacts::canonical_run_artifact_spec("findings.json")
            .expect("findings artifact must be in shared canonical spec")
            .leaf;
        std::fs::write(
            run_dir(target, run_id).join(leaf),
            serde_json::to_string_pretty(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn mcp_backend_binary_names_are_stable() {
        assert_eq!(McpBackend::Gtags.binary(), "kuzushi-mcp-gtags");
        assert_eq!(McpBackend::Clang.binary(), "kuzushi-mcp-clang");
        assert_eq!(McpBackend::Joern.binary(), "kuzushi-mcp-joern");
        assert_eq!(McpBackend::Revng.binary(), "kuzushi-mcp-revng");
        assert!(mcp_spawn_error("kuzushi-mcp-gtags").contains("cargo build"));
        assert!(mcp_health_spawn_error("kuzushi-mcp-gtags").contains("--health"));
    }
}
