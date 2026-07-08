#[cfg(test)]
mod tests {
    use crate::adapters::auth_bridge::{
        bridge_ping_error, bridge_ping_summary, parse_bridge_stdout, run_auth_ping_bridge,
    };
    use crate::adapters::auth_oauth::{
        anthropic_missing_credential_message, anthropic_oauth_readiness_message, auth_ping_model,
        openai_missing_credential_message,
    };
    use crate::adapters::auth_ping::{auth_ping_provider_kind, AuthPingLog};
    use crate::application::config::{config_command, ensure_config_init_allowed};
    use crate::application::review_decisions::decision_command;
    use crate::application::run_tool::{
        apply_option_override, output_with_cli_run_artifacts, parse_option_override,
        run_tool_command, start_cli_tool_run_with_loaded_modules,
    };
    use crate::application::runs::{filter_runs_by_status, run_trace_path};
    use crate::application::runs_diff::{runs_diff, runs_diff_output};
    use crate::application::runs_prune::runs_prune_plan;
    use crate::application::scan::{scan_scope_body, scan_tool_input, scan_worktree_suffix};
    use crate::application::suppressions::{
        suppress_command, suppressions_command, suppressions_command_output,
        suppressions_plain_lines,
    };
    use crate::command::{Command, ConfigCommand, McpBackend, ScanModeArg};
    use crate::doctor::{
        check_auth_env, check_model_config, deterministic_capability_checks, DoctorStatus,
    };
    use crate::mcp::{mcp_health_spawn_error, mcp_spawn_error};
    use crate::presentation::{
        ci_line, format_duration, plain_output_requested, scan_json_output,
        scan_plain_artifact_footer, scan_started_body, shell_startup_progress_messages,
        should_emit_shell_startup_progress,
    };
    use crate::presentation::{
        parse_trace_json_lines, run_summary_plain, runs_list_output, runs_show_output,
        runs_trace_output,
    };
    use crate::tool_requirements::{
        run_tool_workspace, run_tool_workspace_for_input, tool_defaults_to_workspace,
        tool_needs_finding_store, tool_needs_runtime,
    };
    use crate::tool_run_artifacts::{fail_cli_tool_run, finish_cli_tool_run};
    use clap::{CommandFactory, Parser};
    use kuzushi_core::findings::{
        Finding, FindingStore, ReviewDecisionVerdict, Severity, TriageAuthor, TriageOutcome,
        TriageVerdict,
    };
    use kuzushi_core::{
        latest_run_path, load_run_summary, run_dir, write_run_summary, RunSummary, ToolOptionStore,
        WorkspaceTarget,
    };
    use std::path::{Path, PathBuf};

    struct EnvVarGuard {
        key: &'static str,
        prior: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn unset(key: &'static str) -> Self {
            let prior = std::env::var_os(key);
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, prior }
        }

        fn set(key: &'static str, value: &str) -> Self {
            let prior = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, prior }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prior {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn cli_public_args_have_help_text() {
        assert_args_have_help(&crate::cli::Cli::command(), "kuzushi");
    }

    #[test]
    fn cli_target_args_share_help_text() {
        assert_target_args_share_help(&crate::cli::Cli::command(), "kuzushi");
    }

    #[test]
    fn findings_cli_accepts_decision_and_completeness_filters() {
        let cli = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "findings",
            "--decision",
            "confirmed",
            "--completeness",
            "open",
            "--status",
            "seen",
        ])
        .unwrap();

        let Some(Command::Findings {
            decision,
            completeness,
            status,
            verdict,
            ..
        }) = cli.command
        else {
            panic!("expected findings command");
        };

        assert_eq!(decision, vec!["confirmed"]);
        assert_eq!(completeness, vec!["open"]);
        assert_eq!(status, vec!["seen"]);
        assert!(verdict.is_empty());
    }

    #[test]
    fn decision_cli_accepts_review_decision_input() {
        let cli = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "decision",
            "F-0001",
            "--verdict",
            "suppressed",
            "--reason",
            "reviewed under approved policy",
            "--json",
        ])
        .unwrap();

        let Some(Command::Decision {
            reference,
            verdict,
            reason,
            json,
        }) = cli.command
        else {
            panic!("expected decision command");
        };

        assert_eq!(reference, "F-0001");
        assert_eq!(verdict, "suppressed");
        assert_eq!(reason, "reviewed under approved policy");
        assert!(json);
    }

    #[test]
    fn export_cli_accepts_completeness_filter() {
        let cli = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "export",
            "--out",
            "findings.json",
            "--format",
            "json",
            "--completeness",
            "open",
            "--preview",
            "--allow-empty",
        ])
        .unwrap();

        let Some(Command::Export {
            format,
            completeness,
            preview,
            allow_empty,
            output,
        }) = cli.command
        else {
            panic!("expected export command");
        };

        assert_eq!(format.as_deref(), Some("json"));
        assert_eq!(completeness, "open");
        assert!(preview);
        assert!(allow_empty);
        assert_eq!(output, PathBuf::from("findings.json"));
    }

    #[test]
    fn export_preview_command_does_not_write_output_path() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding(
                "run-1",
                &Finding::new_tool(
                    "fixture",
                    "fixture/sql",
                    "src/app.ts",
                    10,
                    None,
                    Severity::High,
                    "request data reaches SQL",
                ),
            )
            .unwrap();

        crate::application::export::export_command(
            workspace.root().to_path_buf(),
            PathBuf::from("preview.json"),
            Some("json".to_string()),
            "all".to_string(),
            true,
            false,
        )
        .unwrap();

        assert!(!workspace.root().join("preview.json").exists());
    }

    #[test]
    fn export_command_requires_allow_empty_for_empty_write() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();

        let output = PathBuf::from("empty.json");
        let error = crate::application::export::export_command(
            workspace.root().to_path_buf(),
            output.clone(),
            Some("json".to_string()),
            "all".to_string(),
            false,
            false,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("selected 0 findings"));
        assert!(!workspace.root().join(&output).exists());
        crate::application::export::export_command(
            workspace.root().to_path_buf(),
            output.clone(),
            Some("json".to_string()),
            "all".to_string(),
            false,
            true,
        )
        .unwrap();
        assert!(workspace.root().join(output).exists());
    }

    #[test]
    fn export_preview_requires_allow_empty_for_empty_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let output = PathBuf::from("empty-preview.json");

        let error = crate::application::export::export_command(
            workspace.root().to_path_buf(),
            output.clone(),
            Some("json".to_string()),
            "all".to_string(),
            true,
            false,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("selected 0 findings"));
        assert!(!workspace.root().join(&output).exists());
        crate::application::export::export_command(
            workspace.root().to_path_buf(),
            output.clone(),
            Some("json".to_string()),
            "all".to_string(),
            true,
            true,
        )
        .unwrap();
        assert!(!workspace.root().join(output).exists());
    }

    #[test]
    fn run_review_export_preserves_scanner_output_and_user_review_state() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let run_id = "scan-review-export";
        write_run_summary(
            workspace.root(),
            &RunSummary::running(
                run_id,
                "scan",
                Some("sast:scan".to_string()),
                workspace.root().display().to_string(),
            )
            .complete()
            .with_findings(Some(1)),
        )
        .unwrap();
        store
            .record_run_started(run_id, workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "javascript.express.xss",
            "src/server.js",
            2,
            Some(2),
            Severity::High,
            "source-linked reflected XSS evidence reaches a response",
        );
        store.insert_finding(run_id, &finding).unwrap();
        drop(store);

        decision_command(
            Some(workspace.root().to_path_buf()),
            finding.fingerprint.clone(),
            "confirmed".to_string(),
            "operator confirmed source-linked evidence".to_string(),
            true,
        )
        .unwrap();

        let complete_output = PathBuf::from("review-export.json");
        crate::application::export::export_command(
            workspace.root().to_path_buf(),
            complete_output.clone(),
            Some("json".to_string()),
            "complete".to_string(),
            false,
            false,
        )
        .unwrap();

        let exported: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(workspace.root().join(complete_output)).unwrap(),
        )
        .unwrap();
        assert_eq!(exported["completeness"], "complete");
        assert_eq!(exported["count"], 1);
        assert_eq!(exported["includedCount"], 1);
        assert_eq!(exported["totalCount"], 1);
        let exported_finding = &exported["findings"][0];
        assert_eq!(exported_finding["reviewDecision"], "confirmed");
        assert_eq!(
            exported_finding["reviewDecisionReason"],
            "operator confirmed source-linked evidence"
        );
        assert_eq!(exported_finding["reviewDecisionAuthor"], "human");
        assert_eq!(exported_finding["triageVerdict"], "true_positive");
        assert_eq!(exported_finding["provenance"]["runId"], run_id);
        assert_eq!(exported_finding["provenance"]["runStatus"], "completed");
        assert!(exported_finding["identityId"].as_str().is_some());

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        assert_eq!(
            store.list_findings(10).unwrap()[0].triage,
            None,
            "user review state must not mutate scanner triage output"
        );

        let open_error = crate::application::export::export_command(
            workspace.root().to_path_buf(),
            PathBuf::from("open-review-export.json"),
            Some("json".to_string()),
            "open".to_string(),
            false,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(open_error.contains("selected 0 findings"));
    }

    #[test]
    fn run_review_export_uses_real_secret_scan_detector() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        write_secret_scan_fixture(&workspace);
        let _run_id = run_secret_scan_cli(&workspace);
        let finding = persisted_secret_scan_finding(&workspace);

        record_confirmed_secret_scan_decision(&workspace, &finding);
        let exported = export_complete_json(&workspace, "secret-review-export.json");

        assert_secret_scan_export(&exported, &finding);
        assert_persisted_scanner_triage_is_unmodified(&workspace);
    }

    #[test]
    fn run_compare_review_uses_real_secret_scan_detector() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        write_secret_scan_fixture(&workspace);
        let base_run_id = run_secret_scan_cli(&workspace);
        write_unrelated_compare_change(&workspace);
        let compare_run_id = run_secret_scan_cli(&workspace);
        let compare_scan_id = persisted_scan_id_for_cli_run(&workspace, &compare_run_id);
        let compare_finding = persisted_secret_scan_finding_for_scan(&workspace, &compare_scan_id);
        let artifact_identity = assert_secret_scan_artifact_identity(&workspace, &compare_run_id);

        let before_review = runs_diff(workspace.root(), &base_run_id, &compare_run_id).unwrap();
        assert_real_secret_scan_diff_before_review(&before_review, &artifact_identity);

        record_confirmed_secret_scan_decision(&workspace, &compare_finding);

        let after_review = runs_diff(workspace.root(), &base_run_id, &compare_run_id).unwrap();
        assert_real_secret_scan_diff_after_review(&after_review);
        assert_latest_secret_scan_review(&workspace, &artifact_identity);
        assert_persisted_scanner_triage_is_unmodified_for_scan(&workspace, &compare_scan_id);
    }

    fn write_secret_scan_fixture(workspace: &WorkspaceTarget) {
        std::fs::write(
            workspace.root().join("config.env"),
            [
                "OPENAI_API_KEY=",
                "sk",
                "-proj-",
                "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            ]
            .concat(),
        )
        .unwrap();
    }

    fn write_unrelated_compare_change(workspace: &WorkspaceTarget) {
        std::fs::write(
            workspace.root().join("README.md"),
            "unrelated compare change\n",
        )
        .unwrap();
    }

    fn run_secret_scan_cli(workspace: &WorkspaceTarget) -> String {
        run_tool_command(
            "secret-scan:scan".to_string(),
            "{}".to_string(),
            Vec::new(),
            Some(workspace.root().to_path_buf()),
            Vec::new(),
        )
        .unwrap();
        latest_cli_run_id(workspace)
    }

    fn latest_cli_run_id(workspace: &WorkspaceTarget) -> String {
        std::fs::read_to_string(latest_run_path(workspace.root()))
            .unwrap()
            .trim()
            .to_string()
    }

    fn persisted_secret_scan_finding(workspace: &WorkspaceTarget) -> Finding {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        let finding = findings[0].clone();
        assert_eq!(finding.tool, "secret-scan");
        assert_eq!(finding.rule_id, "secret-scan/openai-api-key");
        assert!(
            finding.scan_id.as_deref().is_some(),
            "real scanner run should persist scan provenance"
        );
        assert_eq!(finding.triage, None);
        finding
    }

    fn persisted_secret_scan_finding_for_scan(
        workspace: &WorkspaceTarget,
        scan_id: &str,
    ) -> Finding {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings_for_scan_id(scan_id).unwrap();
        assert_eq!(findings.len(), 1);
        let finding = findings[0].clone();
        assert_eq!(finding.tool, "secret-scan");
        assert_eq!(finding.rule_id, "secret-scan/openai-api-key");
        assert_eq!(finding.scan_id.as_deref(), Some(scan_id));
        assert!(finding
            .identity_id
            .as_deref()
            .is_some_and(|id| id.starts_with("fi_")));
        assert_eq!(finding.triage, None);
        finding
    }

    fn record_confirmed_secret_scan_decision(workspace: &WorkspaceTarget, finding: &Finding) {
        decision_command(
            Some(workspace.root().to_path_buf()),
            finding.fingerprint.clone(),
            "confirmed".to_string(),
            "operator confirmed deterministic secret-scan signal".to_string(),
            true,
        )
        .unwrap();
    }

    fn persisted_scan_id_for_cli_run(workspace: &WorkspaceTarget, run_id: &str) -> String {
        let result_path = run_dir(workspace.root(), run_id).join("result.json");
        let result: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(result_path).unwrap()).unwrap();
        result
            .pointer("/data/persisted/runId")
            .and_then(serde_json::Value::as_str)
            .expect("persisted scanner run id")
            .to_string()
    }

    fn assert_secret_scan_artifact_identity(workspace: &WorkspaceTarget, run_id: &str) -> String {
        let result_path = run_dir(workspace.root(), run_id).join("result.json");
        let result: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(result_path).unwrap()).unwrap();
        let findings = result
            .pointer("/data/coreFindings")
            .and_then(serde_json::Value::as_array)
            .expect("run result core findings");
        let identity = findings[0]["identityId"]
            .as_str()
            .expect("run artifact finding identity")
            .to_string();
        assert!(identity.starts_with("fi_"));
        assert_eq!(findings[0]["tool"], "secret-scan");
        assert_eq!(findings[0]["rule_id"], "secret-scan/openai-api-key");
        identity
    }

    fn assert_real_secret_scan_diff_before_review(
        diff: &crate::application::runs_diff::RunsDiff,
        artifact_identity: &str,
    ) {
        assert_eq!(diff.base_status, "completed");
        assert_eq!(diff.compare_status, "completed");
        assert!(diff.warnings.is_empty(), "{:?}", diff.warnings);
        assert_eq!(diff.stable, 1);
        assert!(diff.new.is_empty());
        assert!(diff.not_seen.is_empty());
        assert!(diff.changed.is_empty());
        assert!(diff.uncertain_matches.is_empty());
        let summary = diff.decision_summary.as_ref().expect("decision summary");
        assert_eq!(summary.identities, 1);
        assert_eq!(summary.with_stored_decision, 0);
        assert!(artifact_identity.starts_with("fi_"));
    }

    fn assert_real_secret_scan_diff_after_review(diff: &crate::application::runs_diff::RunsDiff) {
        let summary = diff.decision_summary.as_ref().expect("decision summary");
        assert_eq!(summary.identities, 1);
        assert_eq!(summary.with_stored_decision, 1);
        assert_eq!(summary.carry_forward, 1);
        assert_eq!(summary.conflicts, 0);
        let plain = runs_diff_output(diff, false).unwrap();
        assert!(plain.contains("decisions: identities=1 stored=1 carry_forward=1 conflicts=0"));
    }

    fn assert_latest_secret_scan_review(workspace: &WorkspaceTarget, identity: &str) {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let review = store
            .latest_review_decision_for_identity(identity)
            .unwrap()
            .expect("latest review decision");
        assert_eq!(review.decision.verdict, ReviewDecisionVerdict::Confirmed);
        assert_eq!(
            review.decision.rationale,
            "operator confirmed deterministic secret-scan signal"
        );
    }

    fn export_complete_json(workspace: &WorkspaceTarget, file_name: &str) -> serde_json::Value {
        crate::application::export::export_command(
            workspace.root().to_path_buf(),
            PathBuf::from(file_name),
            Some("json".to_string()),
            "complete".to_string(),
            false,
            false,
        )
        .unwrap();

        serde_json::from_str(&std::fs::read_to_string(workspace.root().join(file_name)).unwrap())
            .unwrap()
    }

    fn assert_secret_scan_export(exported: &serde_json::Value, finding: &Finding) {
        assert_eq!(exported["completeness"], "complete");
        assert_eq!(exported["count"], 1);
        let exported_finding = &exported["findings"][0];
        assert_eq!(exported_finding["tool"], "secret-scan");
        assert_eq!(exported_finding["ruleId"], "secret-scan/openai-api-key");
        assert_eq!(exported_finding["reviewDecision"], "confirmed");
        assert_eq!(
            exported_finding["reviewDecisionReason"],
            "operator confirmed deterministic secret-scan signal"
        );
        assert_eq!(exported_finding["reviewDecisionAuthor"], "human");
        let scan_id = finding.scan_id.as_deref().expect("persisted scan id");
        assert_eq!(
            exported_finding["provenance"]["runId"].as_str(),
            Some(scan_id)
        );
    }

    fn assert_persisted_scanner_triage_is_unmodified(workspace: &WorkspaceTarget) {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        assert_eq!(
            store.list_findings(10).unwrap()[0].triage,
            None,
            "user review state must not mutate real scanner triage output"
        );
    }

    fn assert_persisted_scanner_triage_is_unmodified_for_scan(
        workspace: &WorkspaceTarget,
        scan_id: &str,
    ) {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        assert_eq!(
            store.list_findings_for_scan_id(scan_id).unwrap()[0].triage,
            None,
            "user review state must not mutate compare-run scanner triage output"
        );
    }

    fn assert_args_have_help(command: &clap::Command, path: &str) {
        for arg in command.get_arguments() {
            let has_help = arg.get_help().is_some() || arg.get_long_help().is_some();
            assert!(
                has_help,
                "{path} argument {:?} has no help text",
                arg.get_id()
            );
        }
        for subcommand in command.get_subcommands() {
            let child_path = format!("{path} {}", subcommand.get_name());
            assert_args_have_help(subcommand, &child_path);
        }
    }

    fn assert_target_args_share_help(command: &clap::Command, path: &str) {
        for arg in command.get_arguments() {
            if arg.get_id().as_str() == "target" {
                assert_eq!(
                    arg.get_help().map(|help| help.to_string()),
                    Some(crate::support::TARGET_HELP.to_string()),
                    "{path} target help changed"
                );
            }
        }
        for subcommand in command.get_subcommands() {
            let child_path = format!("{path} {}", subcommand.get_name());
            assert_target_args_share_help(subcommand, &child_path);
        }
    }

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
        let artifact_path = run_dir(Path::new("/repo"), "run-123").join("analysis.json");
        let summary =
            RunSummary::running("run-123", "scan", Some("sast:scan".to_string()), "/repo")
                .failed("boom")
                .with_findings(Some(2))
                .with_cost(Some(0.125))
                .with_artifact(kuzushi_core::RunArtifact {
                    label: "analysis".to_string(),
                    path: artifact_path.display().to_string(),
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
        assert!(rendered.contains(&format!("analysis: {}", artifact_path.display())));
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
        assert_eq!(labels, vec!["tool input", "tool result"]);
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
            temp.path().to_path_buf(),
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
    fn runs_diff_classifies_new_not_seen_changed_and_stable_findings() {
        let temp = tempfile::tempdir().unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-a", 1_000_000)).unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-b", 1_000_100)).unwrap();
        write_result_findings_snapshot(
            temp.path(),
            "run-a",
            serde_json::json!([
                {"fingerprint": "absent", "severity": "high", "confidence": "high"},
                {"identityId": "fi_drift", "fingerprint": "drift-old", "severity": "medium", "confidence": "low", "triage": {"verdict": "needs_more_info"}},
                {"identityId": "fi_stable", "fingerprint": "stable-old", "severity": "low", "confidence": 0.5}
            ]),
        );
        write_result_findings_snapshot(
            temp.path(),
            "run-b",
            serde_json::json!([
                {"fingerprint": "new", "severity": "critical", "confidence": "high"},
                {"identityId": "fi_drift", "fingerprint": "drift-new", "severity": "high", "confidence": "medium", "triage": {"verdict": "true_positive"}},
                {"identityId": "fi_stable", "fingerprint": "stable-new", "severity": "low", "confidence": 0.5}
            ]),
        );

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert_eq!(diff.base_status, "completed");
        assert_eq!(diff.compare_status, "completed");
        assert!(diff.warnings.is_empty());
        assert_eq!(diff.new, vec!["new"]);
        assert_eq!(diff.not_seen, vec!["absent"]);
        assert_eq!(diff.stable, 1);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].finding_key, "fi_drift");
        assert_eq!(diff.changed[0].before.severity.as_deref(), Some("medium"));
        assert_eq!(diff.changed[0].after.severity.as_deref(), Some("high"));
        assert_eq!(
            diff.changed[0].after.verdict.as_deref(),
            Some("true_positive")
        );
    }

    #[test]
    fn runs_diff_preserves_completed_status() {
        let temp = tempfile::tempdir().unwrap();
        write_run_summary(
            temp.path(),
            &summary_started_at_with_status("run-a", 1_000_000, "completed"),
        )
        .unwrap();
        write_run_summary(
            temp.path(),
            &summary_started_at_with_status("run-b", 1_000_100, "completed"),
        )
        .unwrap();
        write_result_findings_snapshot(temp.path(), "run-a", serde_json::json!([]));
        write_result_findings_snapshot(temp.path(), "run-b", serde_json::json!([]));

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert_eq!(diff.base_status, "completed");
        assert_eq!(diff.compare_status, "completed");
        assert!(diff.warnings.is_empty(), "{:?}", diff.warnings);
    }

    #[test]
    fn runs_diff_exposes_unique_uncertain_identity_matches() {
        let temp = tempfile::tempdir().unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-a", 1_000_000)).unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-b", 1_000_100)).unwrap();
        write_result_findings_snapshot(
            temp.path(),
            "run-a",
            serde_json::json!([
                {
                    "fingerprint": "line-old",
                    "ruleId": "demo.sql",
                    "title": "line shifted item",
                    "severity": "medium",
                    "confidence": "low",
                    "filePath": "src/db.rs",
                    "startLine": 20,
                    "tool": "semgrep"
                }
            ]),
        );
        write_result_findings_snapshot(
            temp.path(),
            "run-b",
            serde_json::json!([
                {
                    "fingerprint": "line-new",
                    "ruleId": "demo.sql",
                    "title": "line shifted item",
                    "severity": "high",
                    "confidence": "medium",
                    "filePath": "src/db.rs",
                    "startLine": 24,
                    "tool": "semgrep"
                }
            ]),
        );

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert!(diff.new.is_empty());
        assert!(diff.not_seen.is_empty());
        assert_eq!(diff.uncertain_matches.len(), 1);
        let uncertain = &diff.uncertain_matches[0];
        assert_eq!(uncertain.base_finding_key, "line-old");
        assert_eq!(uncertain.compare_finding_key, "line-new");
        assert_eq!(uncertain.before.severity.as_deref(), Some("medium"));
        assert_eq!(uncertain.after.severity.as_deref(), Some("high"));
        assert!(uncertain
            .reason
            .contains("review before carrying decisions"));

        let plain = runs_diff_output(&diff, false).unwrap();
        assert!(plain.contains("uncertain=1"), "{plain}");
        assert!(plain.contains("Uncertain matches:"), "{plain}");
        assert!(plain.contains("line-old -> line-new"), "{plain}");
        assert!(!plain.contains("Fixed"), "{plain}");

        let json: serde_json::Value =
            serde_json::from_str(&runs_diff_output(&diff, true).unwrap()).unwrap();
        assert_eq!(json["counts"]["uncertainMatches"], serde_json::json!(1));
        assert_eq!(
            json["uncertainMatches"][0]["baseFindingKey"],
            serde_json::json!("line-old")
        );
    }

    #[test]
    fn runs_diff_does_not_carry_decisions_to_uncertain_matches() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("stored-decisions", workspace.root(), "completed")
            .unwrap();
        let reviewed_identity = stored_identity_with_review(
            &store,
            "stored-decisions",
            "demo.sql",
            TriageVerdict::TruePositive,
        );
        write_run_summary(temp.path(), &summary_started_at("run-a", 1_000_000)).unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-b", 1_000_100)).unwrap();
        write_result_findings_snapshot(
            temp.path(),
            "run-a",
            serde_json::json!([
                {
                    "identityId": reviewed_identity,
                    "fingerprint": "line-old",
                    "ruleId": "demo.sql",
                    "title": "line shifted item",
                    "severity": "medium",
                    "filePath": "src/db.rs",
                    "startLine": 20,
                    "tool": "semgrep"
                }
            ]),
        );
        write_result_findings_snapshot(
            temp.path(),
            "run-b",
            serde_json::json!([
                {
                    "fingerprint": "line-new",
                    "ruleId": "demo.sql",
                    "title": "line shifted item",
                    "severity": "high",
                    "filePath": "src/db.rs",
                    "startLine": 24,
                    "tool": "semgrep"
                }
            ]),
        );

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert_eq!(diff.uncertain_matches.len(), 1);
        let summary = diff.decision_summary.as_ref().expect("decision summary");
        assert_eq!(summary.identities, 0);
        assert_eq!(summary.with_stored_decision, 0);
        assert_eq!(summary.carry_forward, 0);
        assert_eq!(summary.conflicts, 0);
    }

    #[test]
    fn runs_diff_includes_identity_decision_summary_when_store_exists() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("stored-decisions", workspace.root(), "completed")
            .unwrap();
        let carried = stored_identity_with_review(
            &store,
            "stored-decisions",
            "demo.carried",
            TriageVerdict::TruePositive,
        );
        let conflict = stored_identity_with_review(
            &store,
            "stored-decisions",
            "demo.conflict",
            TriageVerdict::TruePositive,
        );
        write_run_summary(temp.path(), &summary_started_at("run-a", 1_000_000)).unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-b", 1_000_100)).unwrap();
        write_result_findings_snapshot(temp.path(), "run-a", serde_json::json!([]));
        write_result_findings_snapshot(
            temp.path(),
            "run-b",
            serde_json::json!([
                {"identityId": carried, "fingerprint": "carried", "severity": "high"},
                {"identityId": conflict, "fingerprint": "conflict", "severity": "high", "triage": {"verdict": "false_positive"}}
            ]),
        );

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();
        let summary = diff.decision_summary.as_ref().expect("decision summary");

        assert_eq!(summary.identities, 2);
        assert_eq!(summary.with_stored_decision, 2);
        assert_eq!(summary.carry_forward, 1);
        assert_eq!(summary.conflicts, 1);
        let plain = runs_diff_output(&diff, false).unwrap();
        assert!(plain.contains("decisions: identities=2 stored=2 carry_forward=1 conflicts=1"));
    }

    #[test]
    fn run_compare_review_records_human_decision_after_diff() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-a", 1_000_000)).unwrap();
        write_run_summary(temp.path(), &summary_started_at("run-b", 1_000_100)).unwrap();
        store
            .record_run_started("run-a", workspace.root(), "completed")
            .unwrap();
        store
            .record_run_started("run-b", workspace.root(), "completed")
            .unwrap();
        let base = Finding::new_tool(
            "semgrep",
            "javascript.express.xss",
            "src/server.js",
            20,
            Some(20),
            Severity::Medium,
            "source-linked finding reaches response",
        );
        let compare = Finding::new_tool(
            "semgrep",
            "javascript.express.xss",
            "src/server.js",
            24,
            Some(24),
            Severity::High,
            "source-linked finding reaches response",
        );
        store.insert_finding("run-a", &base).unwrap();
        store.insert_finding("run-b", &compare).unwrap();
        let base_row = store
            .list_findings_for_scan_id("run-a")
            .unwrap()
            .pop()
            .expect("base finding");
        let compare_row = store
            .list_findings_for_scan_id("run-b")
            .unwrap()
            .pop()
            .expect("compare finding");
        let identity = compare_row.identity_id.clone().expect("compare identity");
        assert_eq!(base_row.identity_id.as_deref(), Some(identity.as_str()));
        let compare_reference = compare_row.fingerprint.clone();
        drop(store);
        write_result_findings_snapshot(
            temp.path(),
            "run-a",
            serde_json::json!([{
                "identityId": identity.clone(),
                "fingerprint": base.fingerprint,
                "ruleId": base.rule_id,
                "title": base.title,
                "severity": "medium",
                "filePath": base.file_path,
                "startLine": base.start_line,
                "tool": base.tool
            }]),
        );
        write_result_findings_snapshot(
            temp.path(),
            "run-b",
            serde_json::json!([{
                "identityId": identity.clone(),
                "fingerprint": compare.fingerprint,
                "ruleId": compare.rule_id,
                "title": compare.title,
                "severity": "high",
                "filePath": compare.file_path,
                "startLine": compare.start_line,
                "tool": compare.tool
            }]),
        );

        let before_review = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert_eq!(before_review.changed.len(), 1);
        assert_eq!(before_review.changed[0].finding_key, identity);
        let before_summary = before_review
            .decision_summary
            .as_ref()
            .expect("decision summary");
        assert_eq!(before_summary.identities, 1);
        assert_eq!(before_summary.with_stored_decision, 0);

        decision_command(
            Some(temp.path().to_path_buf()),
            compare_reference,
            "confirmed".to_string(),
            "operator confirmed compare-run evidence".to_string(),
            true,
        )
        .unwrap();

        let after_review = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        let after_summary = after_review
            .decision_summary
            .as_ref()
            .expect("decision summary");
        assert_eq!(after_summary.identities, 1);
        assert_eq!(after_summary.with_stored_decision, 1);
        assert_eq!(after_summary.carry_forward, 1);
        assert_eq!(after_summary.conflicts, 0);
        let plain = runs_diff_output(&after_review, false).unwrap();
        assert!(plain.contains("decisions: identities=1 stored=1 carry_forward=1 conflicts=0"));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let compare_row = store
            .list_findings_for_scan_id("run-b")
            .unwrap()
            .pop()
            .expect("compare finding");
        assert_eq!(
            compare_row.triage, None,
            "run compare review must not mutate scanner triage"
        );
    }

    fn stored_identity_with_review(
        store: &FindingStore,
        run_id: &str,
        rule_id: &str,
        verdict: TriageVerdict,
    ) -> String {
        let finding = Finding::new_semgrep(
            rule_id,
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "reviewed finding",
        );
        let finding_id = store.insert_finding(run_id, &finding).unwrap();
        store
            .record_triage_with_author(
                finding_id,
                &TriageOutcome {
                    verdict,
                    confidence: 0.95,
                    rationale: "operator reviewed durable identity".to_string(),
                    ..Default::default()
                },
                TriageAuthor::Human,
            )
            .unwrap();
        store
            .list_findings_for_scan_id(run_id)
            .unwrap()
            .into_iter()
            .find(|finding| finding.rule_id == rule_id)
            .and_then(|finding| finding.identity_id)
            .expect("stored identity")
    }

    #[test]
    fn runs_diff_warns_that_not_seen_is_uncertain_for_partial_or_failed_runs() {
        let temp = tempfile::tempdir().unwrap();
        write_run_summary(
            temp.path(),
            &summary_started_at_with_status("run-partial", 1_000_000, "partial"),
        )
        .unwrap();
        write_run_summary(
            temp.path(),
            &summary_started_at_with_status("run-failed", 1_000_100, "failed"),
        )
        .unwrap();
        write_result_findings_snapshot(
            temp.path(),
            "run-partial",
            serde_json::json!([{"fingerprint": "left-only", "severity": "high"}]),
        );
        write_result_findings_snapshot(temp.path(), "run-failed", serde_json::json!([]));

        let diff = runs_diff(temp.path(), "run-partial", "run-failed").unwrap();

        assert_eq!(diff.base_status, "partial");
        assert_eq!(diff.compare_status, "failed");
        assert_eq!(diff.not_seen, vec!["left-only"]);
        assert_eq!(diff.warnings.len(), 2);
        assert!(
            diff.warnings[0].contains("run-partial: run status partial")
                && diff.warnings[0].contains("incomplete coverage")
        );
        assert!(
            diff.warnings[1].contains("run-failed: run status failed")
                && diff.warnings[1].contains("incomplete coverage")
        );

        let plain = runs_diff_output(&diff, false).unwrap();
        assert!(plain.contains("status: partial -> failed"), "{plain}");
        assert!(plain.contains("warning: run-partial"), "{plain}");
        assert!(!plain.contains("Fixed"), "{plain}");
    }

    #[test]
    fn suppression_commands_require_explicit_target() {
        let suppress_error = suppress_command(
            None,
            "F-0001".to_string(),
            "accepted risk".to_string(),
            "tester".to_string(),
            7,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(suppress_error.contains("suppress needs a target"));

        let list_error = suppressions_command(None, false).unwrap_err().to_string();
        assert!(list_error.contains("suppressions needs a target"));
    }

    #[test]
    fn decision_command_requires_explicit_target() {
        let error = decision_command(
            None,
            "F-0001".to_string(),
            "suppressed".to_string(),
            "accepted risk".to_string(),
            false,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("decision needs a target"));
    }

    #[test]
    fn decision_command_rejects_empty_reason() {
        let tmp = tempfile::tempdir().unwrap();
        let error = decision_command(
            Some(tmp.path().to_path_buf()),
            "F-0001".to_string(),
            "suppressed".to_string(),
            "   ".to_string(),
            false,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("review decision reason cannot be empty"));
    }

    #[test]
    fn decision_command_appends_user_review_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(tmp.path().join(".kuzushi/v3/index.sqlite3")).unwrap();
        store
            .record_run_started("scan-decision", tmp.path(), "completed")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "javascript.express.xss",
            "src/server.js",
            2,
            Some(2),
            Severity::High,
            "CWE-79 reflected XSS reaches response",
        );
        let finding_id = store.insert_finding("scan-decision", &finding).unwrap();
        drop(store);

        decision_command(
            Some(tmp.path().to_path_buf()),
            finding.fingerprint.clone(),
            "rejected-false-positive".to_string(),
            "source-linked evidence reviewed".to_string(),
            true,
        )
        .unwrap();

        let store = FindingStore::open(tmp.path().join(".kuzushi/v3/index.sqlite3")).unwrap();
        let decision = store
            .latest_review_decision(finding_id)
            .unwrap()
            .expect("review decision");
        assert_eq!(
            decision.decision.verdict,
            ReviewDecisionVerdict::RejectedFalsePositive
        );
        assert_eq!(decision.decision.author, TriageAuthor::Human);
        assert_eq!(
            decision.decision.rationale,
            "source-linked evidence reviewed"
        );
        assert_eq!(decision.triage_verdict, Some(TriageVerdict::FalsePositive));
        assert_eq!(
            store.list_findings(10).unwrap()[0].triage,
            None,
            "user decision must not mutate scanner triage"
        );
    }

    #[test]
    fn suppress_command_appends_user_review_decision() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src")).unwrap();
        std::fs::write(
            tmp.path().join("src/server.js"),
            "const express = require('express');\nres.send(req.query.name);\n",
        )
        .unwrap();
        let store = FindingStore::open(tmp.path().join(".kuzushi/v3/index.sqlite3")).unwrap();
        store
            .record_run_started("scan-suppress", tmp.path(), "completed")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "javascript.express.xss",
            "src/server.js",
            2,
            Some(2),
            Severity::High,
            "CWE-79 reflected XSS reaches response",
        );
        let finding_id = store.insert_finding("scan-suppress", &finding).unwrap();
        drop(store);

        suppress_command(
            Some(tmp.path().to_path_buf()),
            finding.fingerprint.clone(),
            "operator confirmed escaping upstream".to_string(),
            "security@example.test".to_string(),
            7,
            true,
        )
        .unwrap();

        let store = FindingStore::open(tmp.path().join(".kuzushi/v3/index.sqlite3")).unwrap();
        let decision = store
            .latest_review_decision(finding_id)
            .unwrap()
            .expect("suppression review decision");
        assert_eq!(decision.decision.verdict, ReviewDecisionVerdict::Suppressed);
        assert_eq!(decision.decision.author, TriageAuthor::Human);
        assert_eq!(
            decision.decision.rationale,
            "operator confirmed escaping upstream"
        );
        assert_eq!(decision.triage_verdict, None);
        assert_eq!(
            store.list_findings(10).unwrap()[0].triage,
            None,
            "suppression must not mutate scanner triage"
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
    fn auth_ping_missing_credential_messages_name_export_commands() {
        assert!(anthropic_missing_credential_message().contains("export ANTHROPIC_API_KEY="));
        assert!(openai_missing_credential_message().contains("export OPENAI_API_KEY="));
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

        config.model = Some("anthropic:claude-sonnet-4-6".to_string());
        let check = check_model_config(&config);

        assert_eq!(check.status, DoctorStatus::Fail);
        assert!(check.detail.contains("requires ANTHROPIC_API_KEY"));

        config.runtime.api_key_env = "ANTHROPIC_API_KEY".to_string();
        let check = check_model_config(&config);

        assert_eq!(check.status, DoctorStatus::Ok);
        assert!(check.detail.contains("provider anthropic"));

        config.model = Some("openai:gpt-5.5".to_string());
        let check = check_model_config(&config);

        assert_eq!(check.status, DoctorStatus::Fail);
        assert!(check.detail.contains("requires OPENAI_API_KEY"));
    }

    #[test]
    fn doctor_auth_check_matches_configured_model_provider() {
        let _openai = EnvVarGuard::unset("OPENAI_API_KEY");
        let _anthropic = EnvVarGuard::set("ANTHROPIC_API_KEY", "hidden");
        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("openai:gpt-5.5".to_string());

        let check = check_auth_env(&config);

        assert_eq!(check.status, DoctorStatus::Warn);
        assert!(check.detail.contains("OPENAI_API_KEY"));
        assert!(!check.detail.contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn doctor_auth_check_reads_openai_oauth_for_codex_models() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = EnvVarGuard::set("HOME", tmp.path().to_str().unwrap());
        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("openai-codex:gpt-5.4".to_string());

        let missing = check_auth_env(&config);
        assert_eq!(missing.status, DoctorStatus::Warn);
        assert!(missing
            .detail
            .contains("OpenAI OAuth credentials not found"));

        let credentials_path = kuzushi_core::config::default_oauth_credentials_path(tmp.path());
        std::fs::create_dir_all(credentials_path.parent().unwrap()).unwrap();
        std::fs::write(
            &credentials_path,
            serde_json::json!({
                "openai-codex": {
                    "access": "hidden-access",
                    "refresh": "hidden-refresh",
                    "expires": u64::MAX
                }
            })
            .to_string(),
        )
        .unwrap();

        let ready = check_auth_env(&config);
        assert_eq!(ready.status, DoctorStatus::Ok);
        assert!(ready.detail.contains("OpenAI OAuth credentials are stored"));
        assert!(!ready.detail.contains("hidden-access"));
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
        assert!(tool_needs_finding_store("variant:lift-pattern"));
        assert!(tool_needs_finding_store("offense:chain"));
        assert!(tool_needs_finding_store("offense-review:threat-hunt"));
        assert!(tool_needs_finding_store("taint-iris-next:finding-review"));
        assert!(!tool_needs_finding_store("taint-iris-next:dataflow-plan"));
        assert!(!tool_needs_finding_store(
            "taint-iris-next:source-sink-trace"
        ));
        assert!(tool_needs_finding_store("module-recommender:recommend"));
        assert!(tool_needs_finding_store("prompt-armor:scan"));
        assert!(tool_needs_finding_store("cargo-audit:scan"));
        assert!(tool_needs_finding_store("sbom-scan:scan"));
        assert!(tool_needs_finding_store("secret-scan:scan"));
        assert!(tool_needs_finding_store("android-apk:scan"));
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
    fn run_tool_workspace_requires_explicit_target_for_workspace_tools() {
        let error = run_tool_workspace("sast:scan", None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("--target <path>"), "{error}");
        assert!(
            run_tool_workspace_for_input("iac-scan:scan", None, r#"{"target":"missing"}"#)
                .unwrap()
                .is_none()
        );
        assert!(run_tool_workspace("clang.health", None).unwrap().is_none());
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

        let footer = scan_plain_artifact_footer(&workspace, &data);
        assert!(footer.contains(".kuzushi/v3/runs/run-1"));
        assert!(footer.contains(".kuzushi/v3/index.sqlite3"));
        assert!(footer.contains("kuzushi runs show run-1"));
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

    fn summary_started_at_with_status(
        run_id: &str,
        started_at_unix: u64,
        status: &str,
    ) -> RunSummary {
        let mut summary = summary_started_at(run_id, started_at_unix);
        summary.status = status.to_string();
        summary
    }

    fn write_result_findings_snapshot(target: &Path, run_id: &str, value: serde_json::Value) {
        std::fs::write(
            run_dir(target, run_id).join("result.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "data": { "coreFindings": value }
            }))
            .unwrap(),
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
