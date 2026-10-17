#[cfg(test)]
mod tests {
    use crate::adapters::auth_bridge::{bridge_ping_error, bridge_ping_summary};
    use crate::adapters::auth_oauth::{
        anthropic_missing_credential_message, anthropic_oauth_readiness_message, auth_ping_model,
        openai_missing_credential_message,
    };
    use crate::adapters::auth_ping::auth_ping_provider_kind;
    use crate::application::config::{config_command, ensure_config_init_allowed};
    use crate::application::findings::findings_command;
    use crate::application::review_decisions::decision_command;
    use crate::application::review_yield::review_yield_command;
    use crate::application::run_tool::{
        apply_option_override, output_with_cli_run_artifacts, parse_option_override,
        run_tool_command, start_cli_tool_run_with_loaded_modules,
    };
    use crate::application::runs::filter_runs_by_status;
    use crate::application::runs_diff::{runs_diff, runs_diff_output};
    use crate::application::runs_prune::runs_prune_plan;
    use crate::application::scan::{scan_scope_body, scan_tool_input, scan_worktree_suffix};
    use crate::application::suppressions::{
        suppress_command, suppressions_command, suppressions_command_output,
        suppressions_plain_lines,
    };
    use crate::command::{
        Command, ConfigCommand, McpBackend, ReviewYieldCommand, ScanModeArg, SessionExportFormat,
        SessionsCommand,
    };
    use crate::doctor::{
        check_auth_env, check_model_config, check_treesitter_grammars,
        deterministic_capability_checks, DoctorStatus,
    };
    use crate::mcp::{mcp_health_spawn_error, mcp_spawn_error};
    use crate::presentation::review_yield_census_output;
    use crate::presentation::{
        ci_line, format_duration, plain_output_requested, scan_json_output,
        scan_plain_artifact_footer, scan_started_body, shell_startup_progress_messages,
        should_emit_shell_startup_progress,
    };
    use crate::presentation::{
        run_summary_plain, runs_list_output, runs_show_output, runs_trace_output,
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
    fn parser_preserves_distinct_global_and_command_targets_for_conflict_policy() {
        let cli = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "--target",
            "/tmp/global-target",
            "scan",
            "/tmp/command-target",
        ])
        .unwrap();

        assert_eq!(cli.target, Some(PathBuf::from("/tmp/global-target")));
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan command");
        };
        assert_eq!(args.target, Some(PathBuf::from("/tmp/command-target")));
    }

    #[test]
    fn shell_target_flag_has_one_identity_before_or_after_the_subcommand() {
        for argv in [
            vec!["kuzushi", "--target", "/tmp/target", "shell"],
            vec!["kuzushi", "shell", "--target", "/tmp/target"],
        ] {
            let cli = crate::cli::Cli::try_parse_from(argv).unwrap();
            assert_eq!(cli.target, Some(PathBuf::from("/tmp/target")));
            assert!(matches!(cli.command, Some(Command::Shell {})));
        }
    }

    #[test]
    fn nested_commands_reuse_the_global_target_identity() {
        for argv in [
            vec!["kuzushi", "runs", "list", "--target", "/tmp/target"],
            vec!["kuzushi", "kwp", "audit", "--target", "/tmp/target"],
            vec![
                "kuzushi",
                "campaign",
                "run",
                "campaign-1",
                "--target",
                "/tmp/target",
            ],
            vec!["kuzushi", "pr-comment", "--target", "/tmp/target"],
        ] {
            let cli = crate::cli::Cli::try_parse_from(argv).unwrap();
            assert_eq!(cli.target, Some(PathBuf::from("/tmp/target")));
        }
    }

    #[test]
    fn sessions_cli_parses_management_subcommands() {
        let list = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "--target",
            "/tmp/project",
            "sessions",
            "list",
            "--json",
        ])
        .unwrap();
        let Some(Command::Sessions {
            command: SessionsCommand::List { json },
        }) = list.command
        else {
            panic!("expected sessions list command");
        };
        assert!(json);
        assert_eq!(list.target, Some(PathBuf::from("/tmp/project")));

        let export = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "sessions",
            "export",
            "session-1",
            "--format",
            "markdown",
            "--out",
            "session.md",
        ])
        .unwrap();
        let Some(Command::Sessions {
            command:
                SessionsCommand::Export {
                    session_id,
                    format,
                    output,
                },
        }) = export.command
        else {
            panic!("expected sessions export command");
        };
        assert_eq!(session_id, "session-1");
        assert_eq!(format, SessionExportFormat::Markdown);
        assert_eq!(output, PathBuf::from("session.md"));
    }

    #[test]
    fn sessions_cli_parses_show_and_prune_options() {
        let show =
            crate::cli::Cli::try_parse_from(["kuzushi", "sessions", "show", "session-1", "--json"])
                .unwrap();
        assert!(matches!(
            show.command,
            Some(Command::Sessions {
                command: SessionsCommand::Show {
                    session_id,
                    json: true,
                },
            }) if session_id == "session-1"
        ));

        let prune = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "sessions",
            "prune",
            "--older-than-days",
            "45",
            "--dry-run",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            prune.command,
            Some(Command::Sessions {
                command: SessionsCommand::Prune {
                    older_than_days: Some(45),
                    dry_run: true,
                    json: true,
                },
            })
        ));
    }

    #[test]
    fn shell_session_persistence_opt_out_has_visible_alias() {
        for flag in ["--no-session-persistence", "--ephemeral"] {
            let cli = crate::cli::Cli::try_parse_from(["kuzushi", flag, "shell"]).unwrap();
            assert!(cli.no_session_persistence, "flag {flag} was not applied");
            assert!(matches!(cli.command, Some(Command::Shell { .. })));
        }

        let help = crate::cli::Cli::command().render_help().to_string();
        assert!(help.contains("--no-session-persistence"), "{help}");
        assert!(help.contains("--ephemeral"), "{help}");
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
    fn findings_cli_parses_scan_batch_report_subcommand() {
        let cli = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "findings",
            "batch",
            "batch-1234",
            "--json",
        ])
        .unwrap();

        let Some(Command::Findings {
            command: Some(crate::command::FindingsCommand::Batch { batch_id, json }),
            ..
        }) = cli.command
        else {
            panic!("expected findings batch command");
        };
        assert_eq!(batch_id, "batch-1234");
        assert!(json);
    }

    #[test]
    fn findings_cli_parses_read_only_identity_audit() {
        let cli =
            crate::cli::Cli::try_parse_from(["kuzushi", "findings", "identity-audit", "--json"])
                .unwrap();

        let Some(Command::Findings {
            command: Some(crate::command::FindingsCommand::IdentityAudit { action: None, json }),
            ..
        }) = cli.command
        else {
            panic!("expected findings identity-audit command");
        };
        assert!(json);
    }

    #[test]
    fn findings_cli_parses_identity_audit_approval() {
        let cli = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "findings",
            "identity-audit",
            "approve",
            "--from",
            "approval.json",
            "--json",
        ])
        .unwrap();

        let Some(Command::Findings {
            command:
                Some(crate::command::FindingsCommand::IdentityAudit {
                    action: Some(crate::command::IdentityAuditCommand::Approve { input, json }),
                    ..
                }),
            ..
        }) = cli.command
        else {
            panic!("expected findings identity-audit approve command");
        };
        assert_eq!(input, std::path::PathBuf::from("approval.json"));
        assert!(json);
    }

    #[test]
    fn scan_trials_accepts_compatibility_aliases() {
        for flag in ["--trials", "--attempts", "--samples"] {
            let cli = crate::cli::Cli::try_parse_from(["kuzushi", "scan", flag, "3"]).unwrap();
            let Some(Command::Scan(args)) = cli.command else {
                panic!("expected scan command for {flag}");
            };
            assert_eq!(args.trials, 3, "{flag}");
        }
    }

    #[test]
    fn scan_batch_parses_requested_workers() {
        let cli =
            crate::cli::Cli::try_parse_from(["kuzushi", "scan", "--trials", "3", "--workers", "2"])
                .unwrap();
        let Some(Command::Scan(args)) = cli.command else {
            panic!("expected scan batch command");
        };
        assert_eq!((args.trials, args.workers), (3, 2));
    }

    #[test]
    fn campaign_batch_parses_the_detached_controller_surface() {
        let cli = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "campaign",
            "batch",
            "batch-1234",
            "--json",
        ])
        .unwrap();
        let Some(Command::Campaign {
            command: crate::command::CampaignCommand::Batch { batch_id, json, ci },
        }) = cli.command
        else {
            panic!("expected campaign batch controller command");
        };
        assert_eq!(batch_id, "batch-1234");
        assert!(json);
        assert!(!ci);
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
            "--campaign-id",
            "study-1",
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
            campaign_id,
            format,
            completeness,
            preview,
            allow_empty,
            output,
        }) = cli.command
        else {
            panic!("expected export command");
        };

        assert_eq!(campaign_id.as_deref(), Some("study-1"));
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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

    #[test]
    fn cli_autonomy_flag_refuses_tools_above_the_rung() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        // triage:run is a Review action; deprecated `--autonomy hunt` resolves
        // to Scan and must refuse it rather than silently running/substituting.
        let error = run_tool_command(
            "triage:run".to_string(),
            "{}".to_string(),
            Vec::new(),
            Some("hunt".to_string()),
            Some(workspace.root().to_path_buf()),
            Vec::new(),
            None,
        )
        .expect_err("triage:run must be refused under deprecated --autonomy hunt alias");
        assert!(error.to_string().contains("raise posture"), "{error}");
        let exit = error
            .downcast_ref::<crate::application::run_exit::RunCommandExit>()
            .expect("autonomy refusal must carry a deterministic batch exit");
        assert_eq!(
            exit.code(),
            crate::application::run_exit::EXIT_RUN_PREPARE_FAILED
        );
        let run_id = latest_cli_run_id(&workspace);
        let outcome = kuzushi_core::load_persisted_run_terminal_outcome(workspace.root(), &run_id)
            .expect("autonomy refusal must have one agreeing terminal bundle");
        assert_eq!(
            outcome.status,
            kuzushi_core::run_lifecycle::RunItemStatus::Blocked
        );
        assert_eq!(outcome.result["status"], "blocked");
        let done: serde_json::Value = serde_json::from_slice(
            &std::fs::read(kuzushi_core::run_dir(workspace.root(), &run_id).join("done.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(done["status"], "blocked");
        assert_eq!(done["exitCode"], 2);
    }

    #[test]
    fn cli_autonomy_flag_rejects_unknown_rung() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let error = run_tool_command(
            "secret-scan:scan".to_string(),
            "{}".to_string(),
            Vec::new(),
            Some("bogus".to_string()),
            Some(workspace.root().to_path_buf()),
            Vec::new(),
            None,
        )
        .expect_err("an unknown rung must be a hard error");
        assert!(
            error.to_string().contains("--autonomy must be one of"),
            "{error}"
        );
    }

    fn run_secret_scan_cli(workspace: &WorkspaceTarget) -> String {
        run_tool_command(
            "secret-scan:scan".to_string(),
            "{}".to_string(),
            Vec::new(),
            None,
            Some(workspace.root().to_path_buf()),
            Vec::new(),
            None,
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
        use kuzushi_core::findings::ScanComparisonClass;
        assert_eq!(diff.base_status(), "completed");
        assert_eq!(diff.compare_status(), "completed");
        assert!(diff.warnings.is_empty(), "{:?}", diff.warnings);
        assert_eq!(diff.stable_count(), 1);
        assert!(diff.keys_of(ScanComparisonClass::New).is_empty());
        assert!(diff.keys_of(ScanComparisonClass::Resolved).is_empty());
        assert!(diff.keys_of(ScanComparisonClass::NotRescanned).is_empty());
        assert!(diff.changed().is_empty());
        assert!(diff.comparison.uncertain.is_empty());
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
        assert!(plain.contains("Recorded decisions: 1 of 1 finding identities."));
        assert!(!plain.contains("carry_forward="));
        assert!(plain.contains("Check decision sources in Review before reusing a verdict."));
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
            None,
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
    fn shell_startup_progress_names_the_real_interactive_entry_path() {
        let bare = shell_startup_progress_messages(None).join("\n");
        assert!(bare.contains("loading config"));
        assert!(bare.contains("native registry"));
        assert!(bare.contains("choose a target in the picker"));
        assert!(bare.contains("run `demo` for the offline fixture"));
        assert!(!bare.contains("scan ."));

        let targeted = shell_startup_progress_messages(Some(Path::new("."))).join("\n");
        assert!(targeted.contains("target ."));
        assert!(targeted.contains("opening operator shell"));
        assert!(!targeted.contains("first finding"));
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
    fn treesitter_doctor_check_probes_the_sidecar_and_lists_languages() {
        let prior = std::env::var_os("KUZUSHI_MCP_TREESITTER_BIN");

        // A real sidecar path (any existing file works for the probe) → green,
        // and the compiled language list still appears in the detail.
        let sidecar = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("KUZUSHI_MCP_TREESITTER_BIN", sidecar.path());
        let present = check_treesitter_grammars();
        assert_eq!(present.status, DoctorStatus::Ok);
        assert_eq!(present.name, "treesitter");
        assert!(present.detail.contains("cpp"), "{}", present.detail);
        assert!(present.detail.contains("rust"), "{}", present.detail);
        assert!(present.next.is_none());

        // A missing sidecar path → honest warn with an actionable next step.
        std::env::set_var(
            "KUZUSHI_MCP_TREESITTER_BIN",
            sidecar.path().join("does-not-exist"),
        );
        let absent = check_treesitter_grammars();
        assert_eq!(absent.status, DoctorStatus::Warn);
        assert_eq!(absent.name, "treesitter");
        assert!(absent.detail.contains("cpp"), "{}", absent.detail);
        assert!(absent.next.is_some());

        match prior {
            Some(value) => std::env::set_var("KUZUSHI_MCP_TREESITTER_BIN", value),
            None => std::env::remove_var("KUZUSHI_MCP_TREESITTER_BIN"),
        }
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
        )
        .unwrap();

        let summary = load_run_summary(tmp.path(), &run_id).unwrap();
        assert_eq!(summary.status, "completed");
        assert_eq!(summary.started_at_unix, started.started_at_unix);
        assert_eq!(summary.model.as_deref(), Some("local"));
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
        assert_eq!(
            labels,
            vec![
                "tool input",
                "run metadata",
                "run events",
                "semantic run items",
                "failure handoff",
                "report",
                "artifact manifest",
                "tool result",
            ]
        );
        for artifact in &summary.artifacts {
            let path =
                kuzushi_core::run_artifacts::run_artifact_path(tmp.path(), &run_id, &artifact.path);
            assert!(path.exists(), "missing artifact {}", artifact.path);
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
        assert_eq!(failed_summary.model.as_deref(), Some("local"));
        assert!(failed_summary.config_hash.is_some());
        let failed_labels = failed_summary
            .artifacts
            .iter()
            .map(|artifact| artifact.label.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            failed_labels,
            vec![
                "tool input",
                "run metadata",
                "run events",
                "semantic run items",
                "failure handoff",
                "report",
                "artifact manifest",
                "tool result",
            ]
        );
        for artifact in &failed_summary.artifacts {
            let path = kuzushi_core::run_artifacts::run_artifact_path(
                tmp.path(),
                &failed_run_id,
                &artifact.path,
            );
            assert!(path.exists(), "missing artifact {}", artifact.path);
        }
    }

    #[test]
    fn cli_runtime_free_tool_receipt_does_not_claim_the_profile_model() {
        let tmp = tempfile::tempdir().unwrap();
        let config = kuzushi_core::V2Config {
            model: Some("openai:gpt-test".to_string()),
            ..Default::default()
        };
        let run_id = start_cli_tool_run_with_loaded_modules(
            tmp.path(),
            "workspace:status",
            &serde_json::json!({}),
            &config,
            Vec::new(),
        );

        let summary = load_run_summary(tmp.path(), &run_id).unwrap();

        assert_eq!(summary.model, None);
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
        )
        .unwrap();

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
    fn runs_trace_output_covers_plain_and_json() {
        let read = typed_tool_trace_fixture();

        let plain = runs_trace_output(&read, false).unwrap();
        assert!(plain.contains("Semgrep") && plain.contains("started"));
        assert!(plain.contains("Scanning repository files · 421/832"));
        assert!(plain.contains("7 findings"));
        let json = runs_trace_output(&read, true).unwrap();
        assert!(json.contains("\"tool_call_progress\""));
        assert!(json.ends_with('\n'));
    }

    fn typed_tool_trace_fixture() -> kuzushi_core::run_lifecycle::RunProjectionRead {
        use kuzushi_core::run_lifecycle::{
            OperationFingerprint, RunCallId, RunItemId, RunItemRecord, RunItemSource,
            RunItemStatus, RunItemV1, RunItemWriter, SafeText,
        };
        let tmp = tempfile::tempdir().unwrap();
        let run_id = kuzushi_core::new_run_id("cli-trace");
        let writer = RunItemWriter::open(tmp.path(), &run_id, None).unwrap();
        let item_id = RunItemId::new();
        let call_id = RunCallId::new();
        let record =
            |item| RunItemRecord::new(item_id, RunItemSource::Dispatch, item).with_call(call_id);
        writer
            .emit_and_flush(record(RunItemV1::ToolCallRequested {
                tool_name: SafeText::operator_visible("semgrep:scan"),
                operation_fingerprint: OperationFingerprint::from_bytes(b"cli trace"),
                safe_option_names: Vec::new(),
            }))
            .unwrap();
        writer
            .emit_and_flush(record(RunItemV1::ToolCallStarted {
                tool_name: SafeText::operator_visible("semgrep:scan"),
                runtime: None,
                model: None,
            }))
            .unwrap();
        writer
            .emit_and_flush(record(RunItemV1::ToolCallProgress {
                message: SafeText::operator_visible("Scanning repository files"),
                completed: Some(421),
                total: Some(832),
            }))
            .unwrap();
        writer
            .emit_and_flush(record(RunItemV1::ToolCallFinished {
                status: RunItemStatus::Completed,
                cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
                result_artifact: None,
                preview: vec![SafeText::operator_visible("7 findings")],
                warning_count: 0,
                error_count: 0,
            }))
            .unwrap();
        writer.shutdown().unwrap();
        kuzushi_core::run_lifecycle::load_run_projection(tmp.path(), &run_id).unwrap()
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

    fn diff_run_with_findings(
        store: &FindingStore,
        target: &Path,
        run_id: &str,
        findings: &[Finding],
    ) {
        // A real run materializes its artifact directory at start; without it
        // the run's scan scope reads as unknown and nothing may be retired.
        std::fs::create_dir_all(kuzushi_core::run_dir(target, run_id)).unwrap();
        store.record_run_started(run_id, target, "running").unwrap();
        for finding in findings {
            store.insert_finding(run_id, finding).unwrap();
        }
        store
            .record_run_finished(run_id, "completed", findings.len())
            .unwrap();
    }

    #[test]
    fn runs_diff_classifies_new_resolved_changed_and_stable_findings() {
        use kuzushi_core::findings::ScanComparisonClass;
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let absent = Finding::new_tool(
            "semgrep",
            "demo.absent",
            "src/a.rs",
            5,
            Some(5),
            Severity::High,
            "resolved by the compare run",
        );
        let drift_before = Finding::new_tool(
            "semgrep",
            "demo.drift",
            "src/b.rs",
            10,
            Some(10),
            Severity::Medium,
            "severity drifts",
        );
        let mut drift_after = drift_before.clone();
        drift_after.severity = Severity::High;
        let steady = Finding::new_tool(
            "semgrep",
            "demo.steady",
            "src/c.rs",
            20,
            Some(20),
            Severity::Low,
            "unchanged",
        );
        let fresh = Finding::new_tool(
            "semgrep",
            "demo.fresh",
            "src/d.rs",
            30,
            Some(30),
            Severity::Critical,
            "newly discovered",
        );
        diff_run_with_findings(
            &store,
            workspace.root(),
            "run-a",
            &[absent, drift_before, steady.clone()],
        );
        diff_run_with_findings(
            &store,
            workspace.root(),
            "run-b",
            &[drift_after, steady, fresh],
        );

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert_eq!(diff.base_status(), "completed");
        assert_eq!(diff.compare_status(), "completed");
        assert!(diff.warnings.is_empty());
        assert_eq!(diff.keys_of(ScanComparisonClass::New).len(), 1);
        assert_eq!(
            diff.keys_of(ScanComparisonClass::Resolved).len(),
            1,
            "same-target completed semgrep re-scan proves absence"
        );
        assert!(diff.keys_of(ScanComparisonClass::NotRescanned).is_empty());
        let json: serde_json::Value =
            serde_json::from_str(&runs_diff_output(&diff, true).unwrap()).unwrap();
        assert!(json.get("baseSource").is_some());
        assert_eq!(json["baseContext"]["state"], "unavailable");
        assert_eq!(json["contextComparison"], "comparison unavailable");
        assert!(json["baseSource"]["treeHash"].is_null());
        assert_eq!(json["absenceCoverage"][0]["status"], "not_reassessed");
        assert!(json["absenceCoverage"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("receipt"));
        assert_eq!(json["observationCounts"]["notReassessed"], 1);
        assert_eq!(json["observationSchemaVersion"], 1);
        assert_eq!(json["legacyClassifications"]["fixEvidence"], false);
        let plain = runs_diff_output(&diff, false).unwrap();
        assert!(plain.contains("not_reassessed=1"), "{plain}");
        assert!(!plain.contains("resolved="), "{plain}");
        assert!(!plain.contains("Resolved:"), "{plain}");
        assert!(plain.contains("Absence does not establish a fix."));
        assert_eq!(diff.stable_count(), 1);
        let changed = diff.changed();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].before.severity.as_deref(), Some("medium"));
        assert_eq!(changed[0].after.severity.as_deref(), Some("high"));
    }

    #[test]
    fn runs_diff_warns_about_a_malformed_result_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        diff_run_with_findings(&store, workspace.root(), "run-a", &[]);
        diff_run_with_findings(&store, workspace.root(), "run-b", &[]);
        std::fs::write(
            run_dir(workspace.root(), "run-b").join("result.json"),
            "{bad",
        )
        .unwrap();

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert_eq!(diff.warnings.len(), 1);
        assert!(diff.warnings[0].contains("run-b result artifact is malformed JSON"));
    }

    #[test]
    fn runs_diff_rejects_run_id_traversal() {
        let target = tempfile::tempdir().unwrap();

        let error = runs_diff(target.path(), "../outside", "run-safe").unwrap_err();

        assert!(error.to_string().contains("run id"), "{error:#}");
    }

    #[test]
    fn runs_diff_requires_a_recorded_findings_database() {
        let target = tempfile::tempdir().unwrap();

        let error = runs_diff(target.path(), "run-a", "run-b").unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Run a scan against this target first"),
            "{error:#}"
        );
    }

    #[test]
    fn runs_diff_reports_not_rescanned_when_the_engine_did_not_rerun() {
        use kuzushi_core::findings::ScanComparisonClass;
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        diff_run_with_findings(
            &store,
            workspace.root(),
            "run-a",
            &[Finding::new_tool(
                "semgrep",
                "demo.gone",
                "src/a.rs",
                5,
                Some(5),
                Severity::High,
                "semgrep-only finding",
            )],
        );
        diff_run_with_findings(
            &store,
            workspace.root(),
            "run-b",
            &[Finding::new_tool(
                "codeql",
                "cql.rule",
                "src/b.rs",
                9,
                Some(9),
                Severity::Low,
                "codeql-only rescan",
            )],
        );

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert!(diff.keys_of(ScanComparisonClass::Resolved).is_empty());
        let not_rescanned = diff.not_rescanned();
        assert_eq!(not_rescanned.len(), 1);
        assert_eq!(
            not_rescanned[0].1,
            "no run evidence for engine semgrep in the compare scan"
        );
        let plain = runs_diff_output(&diff, false).unwrap();
        assert!(plain.contains("Not reassessed:"), "{plain}");
        assert!(
            plain.contains("scan coverage receipt is unavailable"),
            "{plain}"
        );
    }

    /// Two findings that look identical (tool/rule/file/title) but carry
    /// different fingerprints AND different dedup buckets, so no identity
    /// tier converges them: the honest answer is `uncertain`, not
    /// resolved-plus-new.
    fn uncertain_pair() -> (Finding, Finding) {
        let mut before = Finding::new_tool(
            "semgrep",
            "demo.sql",
            "src/db.rs",
            20,
            Some(20),
            Severity::Medium,
            "tainted query built from request input",
        );
        before.title = "line shifted item".to_string();
        before.fingerprint = "fp3_forced_before".to_string();
        let mut after = Finding::new_tool(
            "semgrep",
            "demo.sql",
            "src/db.rs",
            60,
            Some(60),
            Severity::High,
            "query concatenates attacker-controlled parameters",
        );
        after.title = "line shifted item".to_string();
        after.fingerprint = "fp3_forced_after".to_string();
        (before, after)
    }

    fn write_uncertain_pair_source(target: &Path) {
        let source_path = target.join("src/db.rs");
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        let mut lines = vec!["// unchanged"; 60];
        lines[19] = "query(request_input);";
        lines[59] = "query(attacker_parameters);";
        std::fs::write(source_path, lines.join("\n")).unwrap();
    }

    #[test]
    fn runs_diff_exposes_unique_uncertain_identity_matches() {
        use kuzushi_core::findings::ScanComparisonClass;
        let temp = tempfile::tempdir().unwrap();
        write_uncertain_pair_source(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let (before, after) = uncertain_pair();
        diff_run_with_findings(&store, workspace.root(), "run-a", &[before]);
        diff_run_with_findings(&store, workspace.root(), "run-b", &[after]);

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert!(diff.keys_of(ScanComparisonClass::New).is_empty());
        assert!(diff.keys_of(ScanComparisonClass::Resolved).is_empty());
        assert!(diff.keys_of(ScanComparisonClass::NotRescanned).is_empty());
        assert_eq!(diff.comparison.uncertain.len(), 1);
        let uncertain = &diff.comparison.uncertain[0];
        assert_ne!(uncertain.base_key, uncertain.compare_key);
        assert_eq!(uncertain.before.severity.as_deref(), Some("medium"));
        assert_eq!(uncertain.after.severity.as_deref(), Some("high"));
        assert!(uncertain
            .reason
            .contains("review before carrying decisions"));

        let plain = runs_diff_output(&diff, false).unwrap();
        assert!(plain.contains("uncertain=1"), "{plain}");
        assert!(plain.contains("Uncertain matches:"), "{plain}");
        assert!(!plain.contains("Fixed"), "{plain}");

        let json: serde_json::Value =
            serde_json::from_str(&runs_diff_output(&diff, true).unwrap()).unwrap();
        assert_eq!(json["counts"]["uncertainMatches"], serde_json::json!(1));
        assert_eq!(
            json["uncertainMatches"][0]["baseFindingKey"],
            serde_json::json!(uncertain.base_key)
        );
    }

    #[test]
    fn runs_diff_does_not_carry_decisions_to_uncertain_matches() {
        let temp = tempfile::tempdir().unwrap();
        write_uncertain_pair_source(temp.path());
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let (before, after) = uncertain_pair();
        diff_run_with_findings(&store, workspace.root(), "run-a", &[before.clone()]);
        diff_run_with_findings(&store, workspace.root(), "run-b", &[after]);
        // A stored decision on the base-side identity must not silently carry
        // onto its uncertain counterpart in the compare run.
        let base_row = store
            .list_findings_for_scan_id("run-a")
            .unwrap()
            .pop()
            .expect("base finding");
        decision_command(
            Some(temp.path().to_path_buf()),
            base_row.fingerprint.clone(),
            "confirmed".to_string(),
            "operator reviewed the base observation".to_string(),
            true,
        )
        .unwrap();

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        assert_eq!(diff.comparison.uncertain.len(), 1);
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
        let carried = Finding::new_tool(
            "semgrep",
            "demo.carried",
            "src/carried.rs",
            5,
            Some(5),
            Severity::High,
            "decision carries forward",
        );
        let mut conflict = Finding::new_tool(
            "semgrep",
            "demo.conflict",
            "src/conflict.rs",
            9,
            Some(9),
            Severity::High,
            "snapshot disagrees with stored decision",
        );
        conflict.triage = Some(TriageOutcome {
            verdict: TriageVerdict::FalsePositive,
            confidence: 0.9,
            rationale: "scanner triage disagrees".to_string(),
            ..Default::default()
        });
        diff_run_with_findings(&store, workspace.root(), "run-a", &[]);
        diff_run_with_findings(
            &store,
            workspace.root(),
            "run-b",
            &[carried.clone(), conflict.clone()],
        );
        for reference in [&carried.fingerprint, &conflict.fingerprint] {
            decision_command(
                Some(temp.path().to_path_buf()),
                reference.clone(),
                "confirmed".to_string(),
                "operator confirmed the finding".to_string(),
                true,
            )
            .unwrap();
        }

        let diff = runs_diff(temp.path(), "run-a", "run-b").unwrap();
        let summary = diff.decision_summary.as_ref().expect("decision summary");

        assert_eq!(summary.identities, 2);
        assert_eq!(summary.with_stored_decision, 2);
        assert_eq!(summary.carry_forward, 1);
        assert_eq!(summary.conflicts, 1);
        let plain = runs_diff_output(&diff, false).unwrap();
        assert!(plain.contains("Recorded decisions: 2 of 2 finding identities."));
        assert!(plain.contains("Differing snapshot verdicts: 1"));
        assert!(!plain.contains("carry_forward="));
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

        let before_review = runs_diff(temp.path(), "run-a", "run-b").unwrap();

        let before_changed = before_review.changed();
        assert_eq!(before_changed.len(), 1);
        assert_eq!(before_changed[0].finding_key, identity);
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
        assert!(plain.contains("Recorded decisions: 1 of 1 finding identities."));
        assert!(!plain.contains("carry_forward="));

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

    #[test]
    fn runs_diff_never_resolves_against_a_failed_compare_run() {
        use kuzushi_core::findings::ScanComparisonClass;
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        diff_run_with_findings(
            &store,
            workspace.root(),
            "run-base",
            &[Finding::new_tool(
                "semgrep",
                "demo.gone",
                "src/a.rs",
                5,
                Some(5),
                Severity::High,
                "vanished in a failed rescan",
            )],
        );
        store
            .record_run_started("run-failed", workspace.root(), "running")
            .unwrap();
        store
            .record_run_finished("run-failed", "failed", 0)
            .unwrap();

        let diff = runs_diff(temp.path(), "run-base", "run-failed").unwrap();

        assert_eq!(diff.base_status(), "completed");
        assert_eq!(diff.compare_status(), "failed");
        assert!(diff.keys_of(ScanComparisonClass::Resolved).is_empty());
        let not_rescanned = diff.not_rescanned();
        assert_eq!(not_rescanned.len(), 1);
        assert_eq!(not_rescanned[0].1, "compare run status is failed");

        let plain = runs_diff_output(&diff, false).unwrap();
        assert!(plain.contains("status: completed -> failed"), "{plain}");
        assert!(plain.contains("later run did not complete"), "{plain}");
        assert!(!plain.contains("Fixed"), "{plain}");
    }

    /// A well-formed but unrecorded run id is a typo, not an empty scan: it
    /// must error with the remedy instead of rendering a plausible diff.
    #[test]
    fn runs_diff_rejects_unrecorded_run_ids_with_a_remedy() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        diff_run_with_findings(
            &store,
            workspace.root(),
            "run-recorded",
            &[Finding::new_tool(
                "semgrep",
                "demo.only",
                "src/a.rs",
                5,
                Some(5),
                Severity::High,
                "the one recorded run",
            )],
        );

        let error = runs_diff(temp.path(), "run-recorded", "run-typo").unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("run-typo"), "{message}");
        assert!(message.contains("kuzushi runs list"), "{message}");
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
    fn review_yield_census_output_reports_cutoff_split_without_jargon() {
        let mut report = kuzushi_core::review_yield::domain::CensusReport::default();
        report.decision_events = 4;
        report.human_decision_events = 3;
        report.eligible_identities = 2;
        report.positive = 1;
        report.negative = 1;
        report.by_author.insert("human".to_string(), 3);
        report.by_author.insert("auto".to_string(), 1);
        report
            .cutoff_quality
            .insert("barrier_at_head".to_string(), 3);

        let plain = review_yield_census_output(&report, false).unwrap();

        assert!(plain.contains("Head-barrier cutoff           3"), "{plain}");
        assert!(plain.contains("Decisions by author"), "{plain}");
        assert!(plain.contains("review-yield export --out"), "{plain}");
        assert!(!plain.to_lowercase().contains("watermark"), "{plain}");

        let json = review_yield_census_output(&report, true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["cutoffQuality"]["barrier_at_head"], 3);
        assert_eq!(parsed["taskId"], "review_yield_predecision_v1");
    }

    #[test]
    fn review_yield_empty_census_points_at_the_review_surface() {
        let report = kuzushi_core::review_yield::domain::CensusReport::default();

        let plain = review_yield_census_output(&report, false).unwrap();

        assert!(plain.contains("Next: adjudicate findings"), "{plain}");
    }

    #[test]
    fn review_yield_commands_require_explicit_target() {
        let census = review_yield_command(ReviewYieldCommand::Census { json: false }, None)
            .unwrap_err()
            .to_string();
        assert!(
            census.contains("review-yield census needs a target"),
            "{census}"
        );

        let export = review_yield_command(
            ReviewYieldCommand::Export {
                output: PathBuf::from("dataset.jsonl"),
            },
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            export.contains("review-yield export needs a target"),
            "{export}"
        );
    }

    /// `findings` reads persisted state and loads no config, so a scanned
    /// repository's own `[review_yield]` section neither arms the feature nor
    /// stops the listing. The config-loading surfaces reject the same file
    /// loudly — that asymmetry is deliberate and pinned here so neither half
    /// drifts into the other.
    #[test]
    fn findings_cli_ignores_a_project_local_review_yield_section() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(tmp.path()).unwrap();
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("scan-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding(
                "scan-1",
                &kuzushi_core::Finding::new_semgrep(
                    "demo.rule",
                    "src/app.rs",
                    1,
                    None,
                    kuzushi_core::Severity::High,
                    "listed finding",
                ),
            )
            .unwrap();
        let project_config = tmp.path().join(".kuzushi/v3/config.toml");
        std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        std::fs::write(
            &project_config,
            "[review_yield]\nmode = \"within-band\"\nmodel_path = \"/models/tree.json\"\n",
        )
        .unwrap();

        // The config-loading surfaces (shell, scan) refuse the section.
        let rejection = kuzushi_core::load_config_for_target(Some(tmp.path()))
            .unwrap_err()
            .to_string();
        assert!(rejection.contains("review_yield"), "{rejection}");

        // `findings` proceeds over the same target without reading it.
        findings_command(
            Some(tmp.path().to_path_buf()),
            kuzushi_core::FindingListFilter::with_limit(kuzushi_core::FindingListFilter::MAX_LIMIT),
            true,
        )
        .unwrap();
    }

    #[test]
    fn review_yield_export_requires_recorded_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let error = review_yield_command(
            ReviewYieldCommand::Census { json: true },
            Some(tmp.path().to_path_buf()),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("No recorded findings database"), "{error}");
        assert!(!tmp.path().join(".kuzushi").exists());
    }

    #[test]
    fn review_yield_cli_parses_census_and_export() {
        let census = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "--target",
            "/tmp/project",
            "review-yield",
            "census",
            "--json",
        ])
        .unwrap();
        let Some(Command::ReviewYield {
            command: ReviewYieldCommand::Census { json },
        }) = census.command
        else {
            panic!("expected review-yield census command");
        };
        assert!(json);
        assert_eq!(census.target, Some(PathBuf::from("/tmp/project")));

        let export = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "review-yield",
            "export",
            "--out",
            "review-yield.jsonl",
        ])
        .unwrap();
        let Some(Command::ReviewYield {
            command: ReviewYieldCommand::Export { output },
        }) = export.command
        else {
            panic!("expected review-yield export command");
        };
        assert_eq!(output, PathBuf::from("review-yield.jsonl"));
    }

    fn parity_model(name: &str) -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../experiments/review-yield/fixtures/parity"
        ))
        .join(name)
    }

    #[test]
    fn validate_model_reports_metadata_json() {
        let model = kuzushi_core::review_yield::persistence::load_model_artifact(&parity_model(
            "model-mixed-depth3.json",
        ))
        .expect("the parity model loads");

        let rendered = crate::presentation::review_yield_model_output(&model, true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(parsed["nodeCount"], 7);
        assert_eq!(parsed["depth"], 2);
        assert_eq!(parsed["taskId"], "review_yield_predecision_v1");
        assert_eq!(parsed["minimumLeafSupport"], 20);

        let plain = crate::presentation::review_yield_model_output(&model, false).unwrap();
        assert!(plain.contains("Review-yield model"), "{plain}");
        assert!(plain.contains("blake3:"), "{plain}");
    }

    /// A refused artifact must surface as a nonzero-exit error carrying both
    /// the reason and the eligibility kind, never a warning.
    #[test]
    fn validate_model_fails_on_tampered_artifact() {
        let error = review_yield_command(
            ReviewYieldCommand::ValidateModel {
                model: parity_model("model-tampered-hash.json"),
                json: false,
            },
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("digest mismatch"), "{error}");
        assert!(error.contains("invalidModelHash"), "{error}");
    }

    #[test]
    fn validate_model_fails_on_an_absent_artifact() {
        let error = review_yield_command(
            ReviewYieldCommand::ValidateModel {
                model: PathBuf::from("/tmp/kuzushi-no-such-review-yield-model.json"),
                json: true,
            },
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unreadable"), "{error}");
        assert!(error.contains("unsupportedModelSchema"), "{error}");
    }

    #[test]
    fn score_requires_explicit_target() {
        let error = review_yield_command(
            ReviewYieldCommand::Score {
                model: parity_model("model-numeric-small.json"),
                json: false,
            },
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("review-yield score needs a target"),
            "{error}"
        );
    }

    /// The artifact is opened before the store, so a refused model never
    /// reaches the findings database.
    #[test]
    fn score_rejects_a_bad_model_before_reading_findings() {
        let tmp = tempfile::tempdir().unwrap();

        let error = review_yield_command(
            ReviewYieldCommand::Score {
                model: parity_model("model-tampered-hash.json"),
                json: false,
            },
            Some(tmp.path().to_path_buf()),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("digest mismatch"), "{error}");
        assert!(!tmp.path().join(".kuzushi").exists());
    }

    #[test]
    fn review_yield_subcommands_parse() {
        let checked = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "review-yield",
            "validate-model",
            "--model",
            "model.json",
            "--json",
        ])
        .unwrap();
        let Some(Command::ReviewYield {
            command: ReviewYieldCommand::ValidateModel { model, json },
        }) = checked.command
        else {
            panic!("expected review-yield validate-model command");
        };
        assert_eq!(model, PathBuf::from("model.json"));
        assert!(json);

        let scored = crate::cli::Cli::try_parse_from([
            "kuzushi",
            "--target",
            "/tmp/project",
            "review-yield",
            "score",
            "--model",
            "model.json",
        ])
        .unwrap();
        let Some(Command::ReviewYield {
            command: ReviewYieldCommand::Score { model, json },
        }) = scored.command
        else {
            panic!("expected review-yield score command");
        };
        assert_eq!(model, PathBuf::from("model.json"));
        assert!(!json);
        assert_eq!(scored.target, Some(PathBuf::from("/tmp/project")));
    }

    #[test]
    fn score_output_labels_itself_advisory() {
        let model = kuzushi_core::review_yield::persistence::load_model_artifact(&parity_model(
            "model-numeric-small.json",
        ))
        .unwrap();

        let plain = crate::presentation::review_yield_score_output(&model, &[], false).unwrap();
        let encoded = crate::presentation::review_yield_score_output(&model, &[], true).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&encoded).unwrap();

        assert!(plain.contains("does not change review order"), "{plain}");
        assert!(plain.contains("Next: run a scan"), "{plain}");
        assert_eq!(
            parsed["advisory"],
            "advisory signal; does not change review order"
        );
        assert_eq!(parsed["scores"].as_array().unwrap().len(), 0);
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
        let parsed: kuzushi_openai::PingBridgeResponse = serde_json::from_slice(
            br#"{"ok":true,"auth_mode":"oauth","latency_ms":7,"input_tokens":2,"output_tokens":3,"cost_usd":0.0042}"#,
        )
        .unwrap();

        assert_eq!(bridge_ping_error(&parsed), None);
        assert_eq!(
            bridge_ping_summary(&parsed),
            "round-trip ok via oauth (7ms, 2/3 tokens, ~$0.00420)"
        );

        let failed: kuzushi_openai::PingBridgeResponse =
            serde_json::from_value(serde_json::json!({"ok": false, "error": "bad credentials"}))
                .unwrap();
        assert_eq!(
            bridge_ping_error(&failed),
            Some("bad credentials".to_string())
        );
    }

    /// The ping envelope carries the credential env of the *model's* provider,
    /// so a config whose `runtime.api_key_env` names another provider cannot
    /// smuggle that provider's secret into the request.
    #[test]
    fn auth_ping_binds_the_envelope_to_the_model_provider() {
        let anthropic = kuzushi_core::runtime::require_model_auth_binding(
            auth_ping_provider_kind("anthropic").unwrap(),
            "anthropic:claude-haiku-4-5",
            "ANTHROPIC_API_KEY",
        )
        .unwrap();
        assert_eq!(anthropic.api_key_env, "ANTHROPIC_API_KEY");

        // The shipped default config: an OpenAI credential env plus the
        // default `anthropic` positional provider.
        let config = kuzushi_core::V2Config::default();
        let error = kuzushi_core::runtime::require_model_auth_binding(
            auth_ping_provider_kind("anthropic").unwrap(),
            "anthropic:claude-haiku-4-5",
            &config.runtime.api_key_env,
        )
        .expect_err("OPENAI_API_KEY must not authenticate an Anthropic ping")
        .to_string();
        assert!(error.contains("ANTHROPIC_API_KEY"), "{error}");

        let crossed = kuzushi_core::runtime::require_model_auth_binding(
            auth_ping_provider_kind("anthropic").unwrap(),
            "openai:gpt-5.5",
            &config.runtime.api_key_env,
        )
        .expect_err("an OpenAI model must not answer an Anthropic ping")
        .to_string();
        assert!(
            crossed.contains("will not forward a credential across providers"),
            "{crossed}"
        );
    }

    /// The ping runs through the strict bridge runner, so a bridge that exits
    /// nonzero is a failure even when it printed a success document.
    ///
    /// The fake bridge is a `/bin/sh` script, so both helpers below are
    /// `#[cfg(unix)]`; the test carries the same gate or the whole crate's
    /// `--all-targets` check stops compiling on Windows.
    #[cfg(unix)]
    #[test]
    fn run_auth_ping_bridge_round_trips_json_over_stdio() {
        let temp = tempfile::tempdir().unwrap();
        let success = serde_json::json!({
            "ok": true,
            "auth_mode": "echo",
            "latency_ms": 1,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0
        });

        let ok_bridge = fake_ping_bridge(temp.path(), "ok.sh", &success.to_string(), 0);
        let parsed = ping_runtime(&ok_bridge)
            .auth_ping_blocking("openai-codex:gpt-5.5")
            .unwrap();
        assert!(parsed.ok);
        assert_eq!(bridge_ping_error(&parsed), None);
        assert_eq!(parsed.auth_mode.as_deref(), Some("echo"));

        let lying_bridge = fake_ping_bridge(temp.path(), "lying.sh", &success.to_string(), 3);
        let error = ping_runtime(&lying_bridge)
            .auth_ping_blocking("openai-codex:gpt-5.5")
            .expect_err("a nonzero bridge exit must not report a healthy round trip")
            .to_string();
        assert!(error.contains("auth ping bridge exited with"), "{error}");
    }

    #[cfg(unix)]
    fn fake_ping_bridge(
        dir: &std::path::Path,
        name: &str,
        stdout: &str,
        exit_code: i32,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let script = dir.join(name);
        std::fs::write(
            &script,
            format!("#!/bin/sh\ncat > /dev/null\nprintf '%s' '{stdout}'\nexit {exit_code}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    /// A runtime whose OAuth bag is already usable, so the ping reaches the
    /// bridge instead of stopping at credential validation.
    #[cfg(unix)]
    fn ping_runtime(bridge: &std::path::Path) -> kuzushi_openai::LangGraphRuntime {
        let oauth = bridge.parent().unwrap().join("oauth-credentials.json");
        std::fs::write(
            &oauth,
            serde_json::json!({
                "openai-codex": {
                    "access": "test-access-token",
                    "refresh": "test-refresh-token",
                    "expires": 4_102_444_800_000_u64
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut config = kuzushi_core::V2Config::default();
        config.runtime.langgraph_bridge_command = Some(vec![bridge.to_string_lossy().into_owned()]);
        config.runtime.anthropic_oauth = Some(kuzushi_core::AnthropicOauthConfig {
            credentials_path: Some(oauth),
            allow_env_token: false,
        });
        kuzushi_openai::LangGraphRuntime::from_config(&config, bridge.parent().unwrap()).unwrap()
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
        assert!(!tool_needs_finding_store("module-recommender:recommend"));
        assert!(tool_needs_finding_store("prompt-armor:scan"));
        assert!(tool_needs_finding_store("cargo-audit:scan"));
        assert!(!tool_needs_finding_store("sbom-scan:scan"));
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
        let inline_target = tempfile::tempdir().unwrap();
        let input = serde_json::json!({"target": inline_target.path()}).to_string();
        let workspace = run_tool_workspace_for_input("iac-scan:scan", None, &input)
            .unwrap()
            .expect("inline target should establish the workspace");
        assert_eq!(
            workspace.root(),
            inline_target.path().canonicalize().unwrap()
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
        let result = serde_json::json!({
            "ok": true,
            "status": "completed",
            "summary": "scan complete",
            "warnings": [],
            "errors": [],
            "data": data.clone(),
        });
        let summary = scan_json_output(&workspace, &result, &data);
        assert_eq!(summary["findingsCount"], serde_json::json!(2));
        assert_eq!(summary["status"], serde_json::json!("completed"));
        assert!(summary["db"].as_str().unwrap().contains(".kuzushi"));

        let footer = scan_plain_artifact_footer(&workspace, &data);
        assert!(footer.contains(".kuzushi/v3/runs/run-1"));
        assert!(footer.contains(".kuzushi/v3/index.sqlite3"));
        assert!(footer.contains("kuzushi --target"));
        assert!(footer.contains("runs show run-1"));
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

    #[test]
    fn mcp_backend_binary_names_are_stable() {
        assert_eq!(McpBackend::Gtags.binary(), "kuzushi-mcp-gtags");
        assert_eq!(McpBackend::Clang.binary(), "kuzushi-mcp-clang");
        assert_eq!(McpBackend::Cpg.binary(), "kuzushi-mcp-cpg");
        assert_eq!(McpBackend::Findings.binary(), "kuzushi-mcp-findings");
        assert_eq!(McpBackend::Revng.binary(), "kuzushi-mcp-revng");
        assert!(mcp_spawn_error("kuzushi-mcp-gtags").contains("cargo build"));
        assert!(mcp_health_spawn_error("kuzushi-mcp-gtags").contains("--health"));
    }
}
