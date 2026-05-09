#[cfg(test)]
mod tests {
    use crate::adapters::auth_bridge::{
        bridge_ping_error, bridge_ping_summary, parse_bridge_stdout, run_auth_ping_bridge,
    };
    use crate::adapters::auth_oauth::{anthropic_oauth_readiness_message, auth_ping_model};
    use crate::adapters::auth_ping::AuthPingLog;
    use crate::application::config::{config_command, ensure_config_init_allowed};
    use crate::application::scan::{scan_scope_body, scan_task_mode, scan_worktree_suffix};
    use crate::application::suppressions::{suppressions_command_output, suppressions_plain_lines};
    use crate::command::{ConfigCommand, McpBackend};
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
    use kuzushi_core::{RunSummary, WorkspaceTarget};
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
    fn run_summary_plain_includes_optional_fields_and_artifacts() {
        let summary =
            RunSummary::running("run-123", "scan", Some("sast:scan".to_string()), "/repo")
                .failed("boom")
                .with_findings(Some(2))
                .with_cost(Some(0.125))
                .with_artifact(kuzushi_core::RunArtifact {
                    label: "summary".to_string(),
                    path: "/repo/.kuzushi/runs/run-123/summary.json".to_string(),
                    kind: "json".to_string(),
                });

        let rendered = run_summary_plain(&summary);

        assert!(rendered.contains("Run run-123"));
        assert!(rendered.contains("Status: failed"));
        assert!(rendered.contains("Tool: sast:scan"));
        assert!(rendered.contains("Findings: 2"));
        assert!(rendered.contains("Cost USD: 0.1250"));
        assert!(rendered.contains("Error: boom"));
        assert!(rendered.contains("summary: /repo/.kuzushi/runs/run-123/summary.json"));
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
            RunSummary::running("run-1", "scan", None, "target").with_findings(Some(3)),
            RunSummary::running("run-2", "tool", Some("ctx:build".to_string()), "target"),
        ];
        let plain = runs_list_output(&workspace, &runs, false).unwrap();
        assert!(plain.contains("Run artifacts"));
        assert!(plain.contains("run-1  running   scan"));
        assert!(plain.contains("findings=3"));
        assert!(plain.contains("run-2  running   ctx:build"));
        assert!(plain.ends_with('\n'));

        let json = runs_list_output(&workspace, &runs, true).unwrap();
        assert!(json.contains("\"runId\": \"run-1\""));
        assert!(json.ends_with('\n'));
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
        let body = "{\"n\":1,\"kind\":\"plan\"}\n";

        assert_eq!(
            runs_trace_output(Path::new("/tmp/trace.jsonl"), body, false).unwrap(),
            body
        );
        let json = runs_trace_output(Path::new("/tmp/trace.jsonl"), body, true).unwrap();
        assert!(json.contains("\"kind\": \"plan\""));
        assert!(json.ends_with('\n'));
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
    fn auth_ping_model_preserves_operator_override_then_config_then_default() {
        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("openai:gpt-5.4".to_string());

        assert_eq!(
            auth_ping_model(Some("anthropic:claude-sonnet-4-5".to_string()), &config),
            "anthropic:claude-sonnet-4-5"
        );
        assert_eq!(auth_ping_model(None, &config), "openai:gpt-5.4");

        config.model = None;
        assert_eq!(auth_ping_model(None, &config), "anthropic:claude-haiku-4-5");
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
        assert!(tool_defaults_to_workspace("findings:list"));
        assert!(!tool_defaults_to_workspace("clang.health"));

        assert!(tool_needs_finding_store("variant:hunt"));
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
        assert_eq!(scan_task_mode(&[]), "auto");
        assert_eq!(scan_task_mode(&["sast".to_string()]), "manual");
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
    fn mcp_backend_binary_names_are_stable() {
        assert_eq!(McpBackend::Gtags.binary(), "kuzushi-mcp-gtags");
        assert_eq!(McpBackend::Clang.binary(), "kuzushi-mcp-clang");
        assert_eq!(McpBackend::Joern.binary(), "kuzushi-mcp-joern");
        assert!(mcp_spawn_error("kuzushi-mcp-gtags").contains("cargo build"));
        assert!(mcp_health_spawn_error("kuzushi-mcp-gtags").contains("--health"));
    }
}
