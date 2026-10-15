#[cfg(test)]
mod tests {
    use super::super::application::sanitize_csv_field;
    use super::super::*;
    use crate::findings::{
        DismissReason, Finding, FindingEvidence, FindingStore, PatchLifecycleFile,
        PatchLifecycleRecord, PatchLifecycleState, ReviewDecision, ReviewDecisionVerdict, Severity,
        StaticProofState, TriageAuthor, TriageOutcome, TriageVerdict,
    };
    use crate::run_artifacts::{write_run_summary, RunLlmCallAudit, RunSummary};
    use crate::runtime::{RuntimeCost, RuntimeCostReport};
    use std::fs;

    #[test]
    fn missing_workspace_target_reports_domain_failure_with_actionable_cli_guidance() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");

        let error = WorkspaceTarget::new(&missing).unwrap_err().to_string();

        assert!(error.contains("Target path does not exist"), "{error}");
        assert!(error.contains("missing"), "{error}");
        assert!(error.contains("Next: use an existing directory"), "{error}");
        assert!(error.contains("kuzushi --target . scan"), "{error}");
    }

    #[test]
    fn resolves_v3_state_paths_under_project() {
        let tmp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(tmp.path()).unwrap();

        assert_eq!(target.state_dir(), target.root().join(".kuzushi/v3"));
        assert_eq!(
            target.findings_db_path(),
            target.root().join(".kuzushi/v3/index.sqlite3")
        );
        assert_eq!(
            target.event_log_dir(),
            target.root().join(".kuzushi/v3/log")
        );
        assert_eq!(
            workspace_static_evidence_db_path(target.root()),
            target.root().join(".kuzushi/v3/static-evidence.sqlite3")
        );
        assert_eq!(
            workspace_artifact_kb_db_path(target.root()),
            target.root().join(".kuzushi/v3/artifact-kb.sqlite3")
        );
        assert_eq!(
            workspace_attachments_path(target.root()),
            target.root().join(".kuzushi/v3/attachments.json")
        );
    }

    #[test]
    fn initializing_workspace_state_keeps_generated_state_out_of_git() {
        let tmp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(tmp.path()).unwrap();

        target.ensure_state_dir().unwrap();

        assert_eq!(
            fs::read_to_string(target.root().join(".kuzushi/.gitignore")).unwrap(),
            "*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n"
        );
    }

    #[test]
    fn initializing_workspace_state_preserves_an_existing_ignore_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(tmp.path()).unwrap();
        let ignore_path = target.root().join(".kuzushi/.gitignore");
        fs::create_dir_all(ignore_path.parent().unwrap()).unwrap();
        let policy =
            "# custom\n*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n";
        fs::write(&ignore_path, policy).unwrap();

        target.ensure_state_dir().unwrap();

        assert_eq!(fs::read_to_string(ignore_path).unwrap(), policy);
    }

    #[test]
    fn resolves_codeql_database_paths_under_project() {
        let tmp = tempfile::tempdir().unwrap();

        assert_eq!(
            workspace_codeql_db_path(tmp.path()),
            tmp.path().join(".kuzushi/v3/codeql-db")
        );
        assert_eq!(
            legacy_workspace_codeql_db_path(tmp.path()),
            tmp.path().join(".kuzushi/codeql-db")
        );
        assert_eq!(
            legacy_codeql_db_path(tmp.path()),
            tmp.path().join(".codeql/db")
        );
    }

    #[test]
    fn records_user_review_decision_without_mutating_scanner_triage() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-review", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.review",
            "src/app.ts",
            12,
            Some(12),
            Severity::Medium,
            "needs human review",
        );
        let finding_id = store.insert_finding("run-review", &finding).unwrap();
        let persisted = store.list_findings(10).unwrap().remove(0);

        let decision_id = record_user_review_decision_for_finding(
            &workspace,
            &persisted,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Suppressed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "reviewed under approved suppression policy".to_string(),
                dismiss_reason: None,
                actor: None,
            },
        )
        .unwrap();

        assert!(decision_id > 0);
        let latest = store
            .latest_review_decision(finding_id)
            .unwrap()
            .expect("review decision");
        assert_eq!(latest.decision.verdict, ReviewDecisionVerdict::Suppressed);
        assert_eq!(latest.triage_verdict, None);
        assert_eq!(store.list_findings(10).unwrap()[0].triage, None);
        let events = crate::event_log::EventLog::open(workspace.event_log_dir())
            .unwrap()
            .read_all()
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0].event_kind,
            crate::event_log::EventKind::RunStarted
        );
        assert_eq!(
            events[1].event_kind,
            crate::event_log::EventKind::FindingObserved
        );
        assert_eq!(
            events[2].event_kind,
            crate::event_log::EventKind::SuppressionAdded
        );
        assert_eq!(
            events[2].payload["stableFp"],
            persisted
                .identity_id
                .as_deref()
                .unwrap_or(&persisted.fingerprint)
        );
    }

    #[test]
    fn workspace_export_format_accepts_aliases_and_rejects_unknown_values() {
        assert_eq!(
            WorkspaceExportFormat::from_input(" json ").unwrap(),
            WorkspaceExportFormat::Json
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("NDJSON").unwrap(),
            WorkspaceExportFormat::Jsonl
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("sarif").unwrap(),
            WorkspaceExportFormat::Sarif
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("csv").unwrap(),
            WorkspaceExportFormat::Csv
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("markdown-bundle").unwrap(),
            WorkspaceExportFormat::MarkdownBundle
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("bundle").unwrap(),
            WorkspaceExportFormat::MarkdownBundle
        );
        assert!(WorkspaceExportFormat::from_input("xml")
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
    }

    #[test]
    fn workspace_export_format_resolves_from_output_extension() {
        assert_eq!(
            WorkspaceExportFormat::from_output_path(std::path::Path::new("out.sarif")).unwrap(),
            WorkspaceExportFormat::Sarif
        );
        assert_eq!(
            WorkspaceExportFormat::from_output_path(std::path::Path::new("out.sarif.json"))
                .unwrap(),
            WorkspaceExportFormat::Sarif
        );
        assert_eq!(
            WorkspaceExportFormat::from_output_path(std::path::Path::new("out.csv")).unwrap(),
            WorkspaceExportFormat::Csv
        );
        assert_eq!(
            WorkspaceExportFormat::from_output_path(std::path::Path::new("report")).unwrap(),
            WorkspaceExportFormat::MarkdownBundle
        );
    }

    #[test]
    fn exports_workspace_findings_to_json() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        write_fixture_source(workspace.root());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        write_run_summary(
            workspace.root(),
            &RunSummary::running(
                "run-1",
                "scan",
                Some("sast:scan".to_string()),
                workspace.root().display().to_string(),
            )
            .with_model(Some("openai:gpt-test".to_string()))
            .complete(),
        )
        .unwrap();
        let finding = Finding::new_tool(
            "fixture",
            "fixture/sql",
            "src/app.ts",
            10,
            None,
            Severity::High,
            "request data reaches SQL",
        )
        .with_evidence(vec![FindingEvidence {
            kind: "sink".to_string(),
            file_path: "src/app.ts".to_string(),
            line: 10,
            snippet: "db.query(request.query.q)".to_string(),
            rationale: "The request value is used in a SQL query".to_string(),
            confidence: 91,
            ..Default::default()
        }]);
        store.insert_finding("run-1", &finding).unwrap();

        let output = tmp.path().join("exports/findings.json");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.format, WorkspaceExportFormat::Json);
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(exported["format"], "kuzushi.workspace.findings.v2");
        assert_eq!(exported["count"], serde_json::json!(1));
        assert_eq!(exported["metadata"]["format"], "json");
        assert_eq!(
            exported["metadata"]["projection"],
            "WorkspaceFindingExportRecord"
        );
        assert_eq!(exported["metadata"]["completeness"], "all");
        assert_eq!(
            exported["metadata"]["kuzushiVersion"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(exported["metadata"]["includedCount"], 1);
        assert_eq!(exported["metadata"]["totalCount"], 1);
        assert!(exported["metadata"]["omittedFields"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(exported["findings"][0]["ruleId"], "fixture/sql");
        assert_eq!(exported["findings"][0]["kind"], "scanner_finding");
        assert_eq!(exported["findings"][0]["location"]["file"], "src/app.ts");
        assert_eq!(exported["findings"][0]["evidence"]["state"], "observed");
        assert_eq!(
            exported["findings"][0]["evidence"]["observedEvidencePresent"],
            serde_json::json!(true)
        );
        assert_eq!(
            exported["findings"][0]["evidence"]["derivedSourcePresent"],
            serde_json::json!(false)
        );
        assert_eq!(exported["findings"][0]["evidence"]["observedCount"], 1);
        assert_eq!(
            exported["findings"][0]["evidence"]["observedCodeCount"],
            serde_json::json!(1)
        );
        assert_eq!(
            exported["findings"][0]["evidence"]["observedCaptureCount"],
            serde_json::json!(0)
        );
        assert_eq!(
            exported["findings"][0]["evidence"]["modelGeneratedReasoningPresent"],
            serde_json::json!(false)
        );
        assert_eq!(
            exported["findings"][0]["analysis"]["automatedReasoningPresent"],
            serde_json::json!(false)
        );
        assert_eq!(exported["findings"][0]["reviewDecision"], "needs_review");
        assert_eq!(exported["findings"][0]["staticProofState"], "not_recorded");
        assert_eq!(exported["findings"][0]["proofConfidence"], "unverified");
        assert_eq!(
            exported["findings"][0]["provenance"]["runStatus"],
            "completed"
        );
        assert_eq!(
            exported["findings"][0]["provenance"]["model"],
            "openai:gpt-test"
        );
    }

    #[test]
    fn empty_workspace_findings_export_requires_allow_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let output = workspace.root().join("exports/empty.json");
        let options =
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)).with_allow_empty(false);

        let error = export_workspace_findings_with_options(&workspace, &output, &options)
            .unwrap_err()
            .to_string();

        assert!(error.contains("selected 0 findings"));
        assert!(!workspace.root().join("exports").exists());

        let report = export_workspace_findings_with_options(
            &workspace,
            &output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)).with_allow_empty(true),
        )
        .unwrap();
        assert_eq!(report.count, 0);
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(exported["count"], serde_json::json!(0));
        assert_eq!(exported["metadata"]["includedCount"], 0);
        assert_eq!(exported["metadata"]["totalCount"], 0);
    }

    /// Export provenance: the block appears only when a session actually ran
    /// with the signal armed, and it never claims these rows were reordered —
    /// export order is the severity-major alias order in every mode.
    #[test]
    fn export_metadata_records_review_yield_mode_and_model_id() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let output = workspace.root().join("exports/armed.json");
        let options = WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
            .with_allow_empty(true)
            .with_review_yield(Some(ReviewYieldExportProvenance {
                mode: crate::config::ReviewYieldMode::WithinBand,
                model_id: Some("blake3:abc123".to_string()),
            }));

        export_workspace_findings_with_options(&workspace, &output, &options).unwrap();
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();

        assert_eq!(exported["metadata"]["reviewYield"]["mode"], "within-band");
        assert_eq!(
            exported["metadata"]["reviewYield"]["modelId"],
            "blake3:abc123"
        );
        assert_eq!(
            exported["metadata"]["reviewYield"]["orderingInfluence"],
            "review-display-only"
        );
    }

    /// A mode that never moved a row says so, rather than leaving a reader to
    /// assume the export was ranked.
    #[test]
    fn export_metadata_reports_no_ordering_influence_for_non_ordering_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let output = workspace.root().join("exports/shadow.json");
        let options = WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
            .with_allow_empty(true)
            .with_review_yield(Some(ReviewYieldExportProvenance {
                mode: crate::config::ReviewYieldMode::Shadow,
                model_id: None,
            }));

        export_workspace_findings_with_options(&workspace, &output, &options).unwrap();
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();

        assert_eq!(exported["metadata"]["reviewYield"]["mode"], "shadow");
        assert!(exported["metadata"]["reviewYield"]["modelId"].is_null());
        assert_eq!(
            exported["metadata"]["reviewYield"]["orderingInfluence"],
            "none"
        );
    }

    /// An unarmed session carries no block at all. An empty one would suggest
    /// a model was in play and declined to identify itself.
    #[test]
    fn export_metadata_omits_review_yield_when_off() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();

        for provenance in [
            None,
            Some(ReviewYieldExportProvenance {
                mode: crate::config::ReviewYieldMode::Off,
                model_id: None,
            }),
        ] {
            let output = workspace.root().join("exports/off.json");
            let options = WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_allow_empty(true)
                .with_review_yield(provenance);

            export_workspace_findings_with_options(&workspace, &output, &options).unwrap();
            let exported: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();

            assert!(exported["metadata"].get("reviewYield").is_none());
        }
    }

    /// The provenance is a fact the host observed, so tool input must not be
    /// able to assert it. A caller that could would stamp an export with a
    /// model id no model ever produced.
    #[test]
    fn review_yield_provenance_cannot_be_supplied_as_tool_input() {
        let options: WorkspaceExportOptions = serde_json::from_value(serde_json::json!({
            "format": "json",
            "completeness": "all",
            "allowEmpty": true,
            "reviewYield": { "mode": "within-band", "modelId": "blake3:forged" },
        }))
        .expect("an unknown-to-serde field is ignored, not honored");

        assert_eq!(options.review_yield, None);
    }

    #[test]
    fn workspace_status_reports_persisted_finding_count() {
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

        let status = workspace_status_for_target(Some(workspace.root()), None);

        assert_eq!(status.findings_count, Some(1));
        assert_eq!(status.root.as_deref(), Some(workspace.root()));
        assert!(status.status.contains("workspace ready; 1 finding"));
    }

    #[test]
    fn missing_workspace_status_names_the_headless_cli_command() {
        let status = workspace_status_for_target(None, None);

        assert!(status.status.contains("Next: kuzushi scan <target>"));
        assert!(!status.status.contains("Next: scan <target>"));
    }

    #[test]
    fn rejects_unsupported_findings_export_extensions() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let error = export_workspace_findings(&workspace, tmp.path().join("findings.xml"), None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported workspace findings export extension"));
        assert!(error.contains(".json"));
    }

    #[test]
    fn previews_single_file_workspace_findings_with_same_body_as_export() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);
        for (format, extension) in [
            (WorkspaceExportFormat::Json, "json"),
            (WorkspaceExportFormat::Jsonl, "jsonl"),
            (WorkspaceExportFormat::Csv, "csv"),
            (WorkspaceExportFormat::Sarif, "sarif"),
        ] {
            let options = WorkspaceExportOptions::new(Some(format))
                .with_completeness(WorkspaceExportCompleteness::Open);

            let preview = preview_workspace_findings_export(&workspace, format, &options).unwrap();
            let output = tmp.path().join(format!("preview-equivalent.{extension}"));
            let report =
                export_workspace_findings_with_options(&workspace, &output, &options).unwrap();

            assert_eq!(
                preview.body,
                fs::read_to_string(output).unwrap(),
                "{format:?} preview must use the same body as export"
            );
            assert_eq!(preview.format, format);
            assert_eq!(preview.completeness, WorkspaceExportCompleteness::Open);
            assert_eq!(preview.count, report.count);
            assert_eq!(preview.total_count, 2);
        }
    }

    #[test]
    fn empty_workspace_findings_preview_requires_allow_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let options =
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)).with_allow_empty(false);

        let error =
            preview_workspace_findings_export(&workspace, WorkspaceExportFormat::Json, &options)
                .unwrap_err()
                .to_string();

        assert!(error.contains("selected 0 findings"));

        let preview = preview_workspace_findings_export(
            &workspace,
            WorkspaceExportFormat::Json,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)).with_allow_empty(true),
        )
        .unwrap();
        assert_eq!(preview.count, 0);
        assert_eq!(preview.total_count, 0);
        let body: serde_json::Value = serde_json::from_str(&preview.body).unwrap();
        assert_eq!(body["metadata"]["includedCount"], 0);
        assert_eq!(body["metadata"]["totalCount"], 0);
    }

    #[test]
    fn rejects_markdown_bundle_preview_as_directory_shaped() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let options = WorkspaceExportOptions::new(Some(WorkspaceExportFormat::MarkdownBundle));

        let error = preview_workspace_findings_export(
            &workspace,
            WorkspaceExportFormat::MarkdownBundle,
            &options,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("markdown-bundle preview is directory-shaped"));
    }

    #[test]
    fn markdown_bundle_neutralizes_hostile_finding_content() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-hostile", workspace.root(), "completed")
            .unwrap();
        let mut finding = Finding::new_tool(
            "burp-har",
            "http-evidence",
            "src/a|pp.ts",
            12,
            None,
            Severity::Info,
            "GET https://api.lab.test/x (imported)",
        )
        .with_evidence(vec![FindingEvidence {
            kind: "sink\n# heading-kind".to_string(),
            file_path: "src/x\n|y.ts".to_string(),
            line: 12,
            snippet: "payload\n```\n# injected markdown\n```tail".to_string(),
            rationale: "capture-derived".to_string(),
            confidence: 50,
            ..Default::default()
        }]);
        finding.title = "Evil\n# fake title".to_string();
        finding.message = "# forged message\n| forged | table |".to_string();
        finding.evidence[0].rationale =
            "## forged rationale\r\n[hostile](javascript:alert(1))".to_string();
        store.insert_finding("run-hostile", &finding).unwrap();

        let bundle_dir = tmp.path().join("bundle");
        export_workspace_findings(
            &workspace,
            &bundle_dir,
            Some(WorkspaceExportFormat::MarkdownBundle),
        )
        .unwrap();

        let finding_doc = fs::read_dir(bundle_dir.join("findings"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let markdown = fs::read_to_string(finding_doc).unwrap();
        // Snippet fence is longer than any backtick run inside the snippet,
        // so the embedded ``` cannot terminate it early.
        let fence_lines: Vec<&str> = markdown
            .lines()
            .filter(|line| line.trim_end() == "````")
            .collect();
        assert_eq!(
            fence_lines.len(),
            2,
            "expected 4-backtick fences:\n{markdown}"
        );
        // Newlines in inline fields collapse to spaces instead of minting
        // injected markdown lines. (The store itself normalizes the unknown
        // evidence kind to "reasoning" before the bundle ever sees it.)
        assert!(markdown.contains("· src/x |y.ts:12"), "{markdown}");
        assert!(
            !markdown.lines().any(|line| line == "# fake title"),
            "{markdown}"
        );
        assert!(
            markdown.contains("```\n# forged message\n| forged | table |\n```")
                && markdown.contains("```\n## forged rationale\n[hostile](javascript:alert(1))"),
            "free-form finding text must stay inside balanced fences:\n{markdown}"
        );
        let three_tick_fences = markdown
            .lines()
            .filter(|line| line.trim_end() == "```")
            .count();
        assert_eq!(
            three_tick_fences, 5,
            "two balanced three-tick blocks plus one safely nested hostile fence:\n{markdown}"
        );

        let readme = fs::read_to_string(bundle_dir.join("README.md")).unwrap();
        assert!(readme.contains("src/a\\|pp.ts"), "{readme}");
    }

    fn fixture_finding(rule_id: &str, severity: Severity, line: u32) -> Finding {
        Finding::new_tool(
            "fixture",
            rule_id,
            "src/app.ts",
            line,
            Some(line + 3),
            severity,
            "request data reaches a dangerous sink",
        )
        .with_evidence(vec![FindingEvidence {
            kind: "sink".to_string(),
            file_path: "src/app.ts".to_string(),
            line,
            snippet: "db.query(request.query.q)".to_string(),
            rationale: "User-controlled value flows into SQL".to_string(),
            confidence: 91,
            ..Default::default()
        }])
    }

    fn assert_exported_alias_and_priority(
        document: &serde_json::Value,
        rule_id: &str,
        alias: &str,
        priority: &str,
    ) {
        let finding = document["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["ruleId"] == rule_id)
            .unwrap_or_else(|| panic!("missing exported finding {rule_id}"));
        assert_eq!(finding["alias"], alias);
        assert_eq!(finding["priority"], priority);
    }

    fn seed_workspace_with_findings(workspace: &WorkspaceTarget, count: u32) {
        write_fixture_source(workspace.root());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        let severities = [Severity::Critical, Severity::High, Severity::Medium];
        for index in 0..count {
            let severity = severities[(index as usize) % severities.len()];
            let finding = fixture_finding(&format!("fixture/rule-{index}"), severity, 10 + index);
            store.insert_finding("run-1", &finding).unwrap();
        }
    }

    fn write_fixture_source(root: &std::path::Path) {
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        let body = (1..=40)
            .map(|line| format!("db.query(request.query.q); // line {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(src.join("app.ts"), body).unwrap();
    }

    #[test]
    fn exports_workspace_findings_to_sarif() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);

        let output = tmp.path().join("out.sarif");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.format, WorkspaceExportFormat::Sarif);
        assert_eq!(report.count, 2);

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        assert_eq!(document["version"], "2.1.0");
        assert_eq!(document["properties"]["kuzushiExport"]["format"], "sarif");
        assert_eq!(
            document["properties"]["kuzushiExport"]["completeness"],
            "all"
        );
        assert_eq!(document["properties"]["kuzushiExport"]["includedCount"], 2);
        assert_eq!(document["runs"][0]["tool"]["driver"]["name"], "fixture");
        assert_eq!(
            document["runs"][0]["properties"]["kuzushiExport"]["totalCount"],
            2
        );
        assert!(document["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["ruleId"] == "fixture/rule-0"));
        let first = &document["runs"][0]["results"][0];
        assert!(["error", "warning", "note"].contains(&first["level"].as_str().unwrap()));
        assert!(first["locations"][0]["physicalLocation"]["region"]["startLine"].is_number());
        // Unverified fixture findings (no runtime/static proof recorded) map to
        // the mid-band SARIF rank and the `unverified` confidence token.
        assert_eq!(first["rank"], serde_json::json!(30.0));
        assert_eq!(
            first["properties"]["kuzushiProofConfidence"],
            serde_json::json!("unverified")
        );
        assert!(first["properties"]["kuzushiReviewDecision"].is_string());
        assert!(first["properties"]["kuzushiObservedEvidencePresent"].is_boolean());
        assert!(first["properties"]["kuzushiObservedCodeEvidenceCount"].is_number());
        assert!(first["properties"]["kuzushiObservedCaptureEvidenceCount"].is_number());
        assert!(first["properties"]["kuzushiObservedOtherEvidenceCount"].is_number());
        assert!(first["properties"]["kuzushiModelGeneratedReasoningPresent"].is_boolean());
        assert!(first["properties"]["kuzushiDerivedSourcePresent"].is_boolean());
        assert!(first["properties"]["kuzushiAutomatedReasoningPresent"].is_boolean());
        assert!(first["properties"]["kuzushiRawHttpBlobPresent"].is_boolean());
        assert!(first["properties"].get("kuzushiCwe").is_none());
        // Non-suppressed findings carry no SARIF result.suppressions array.
        assert!(first.get("suppressions").is_none());
    }

    #[test]
    fn remediation_truth_is_additive_across_every_export_format() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 1);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = store.list_findings(1).unwrap().remove(0);
        let stable_fp = store
            .patch_lifecycle_stable_fp(&finding.fingerprint)
            .unwrap();
        let mut lifecycle = PatchLifecycleRecord {
            application_id: "application-1".to_string(),
            stable_fp,
            fingerprint: finding.fingerprint,
            finding_scan_id: finding.scan_id,
            patch_run_id: "patch-run-1".to_string(),
            target: workspace.root().display().to_string(),
            diff_hash: "sha256:diff".to_string(),
            base_commit: Some("base-commit".to_string()),
            touched_files: vec![PatchLifecycleFile {
                path: "src/app.ts".to_string(),
                before_hash: Some("sha256:before".to_string()),
                after_hash: Some("sha256:after".to_string()),
            }],
            state: PatchLifecycleState::Verified,
            reverify_run_id: Some("reverify-run-1".to_string()),
            reverify_evidence: None,
            detail: Some("originating detector no longer rediscovered it".to_string()),
            actor: "operator".to_string(),
            application_started_at: "2026-07-13T11:59:59Z".to_string(),
            applied_at: Some("2026-07-13T12:00:00Z".to_string()),
            updated_at: "2026-07-13T12:05:00Z".to_string(),
        };
        let objects = crate::content_store::ContentStore::open(workspace.objects_dir()).unwrap();
        let reproducer = objects
            .put_json(
                crate::content_store::ObjectKind::ProofSnapshot,
                &serde_json::json!({"schemaVersion": 2}),
            )
            .unwrap();
        let receipt = crate::findings::test_verified_receipt(&lifecycle, reproducer);
        lifecycle.reverify_evidence = Some(
            objects
                .put_json(crate::content_store::ObjectKind::ProofSnapshot, &receipt)
                .unwrap(),
        );
        store.insert_patch_lifecycle_record(&lifecycle).unwrap();

        let json_path = tmp.path().join("findings.json");
        export_workspace_findings(&workspace, &json_path, None).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(json_path).unwrap()).unwrap();
        let remediation = &json["findings"][0]["remediation"];
        assert_eq!(remediation["applicationId"], "application-1");
        assert_eq!(remediation["applicationState"], "verified");
        assert_eq!(remediation["empiricallyVerified"], true);
        assert_eq!(remediation["reverifyOutcome"], "verified");
        assert_eq!(remediation["touchedPaths"][0], "src/app.ts");

        let jsonl_path = tmp.path().join("findings.jsonl");
        export_workspace_findings(&workspace, &jsonl_path, None).unwrap();
        let finding_line = fs::read_to_string(jsonl_path)
            .unwrap()
            .lines()
            .nth(1)
            .unwrap()
            .to_string();
        assert!(finding_line.contains("\"applicationId\":\"application-1\""));

        let csv_path = tmp.path().join("findings.csv");
        export_workspace_findings(&workspace, &csv_path, None).unwrap();
        let csv = fs::read_to_string(csv_path).unwrap();
        assert!(csv.contains("remediation_application_id"));
        assert!(csv.contains("application-1,patch-run-1,verified,true,verified,reverify-run-1"));

        let sarif_path = tmp.path().join("findings.sarif");
        export_workspace_findings(&workspace, &sarif_path, None).unwrap();
        let sarif: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(sarif_path).unwrap()).unwrap();
        let properties = &sarif["runs"][0]["results"][0]["properties"];
        assert_eq!(
            properties["kuzushiRemediationApplicationId"],
            "application-1"
        );
        assert_eq!(properties["kuzushiRemediationReverifyOutcome"], "verified");
        assert_eq!(properties["kuzushiRemediationEmpiricallyVerified"], true);

        let markdown_path = tmp.path().join("report");
        export_workspace_findings(
            &workspace,
            &markdown_path,
            Some(WorkspaceExportFormat::MarkdownBundle),
        )
        .unwrap();
        let finding_doc = fs::read_dir(markdown_path.join("findings"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let markdown = fs::read_to_string(finding_doc).unwrap();
        assert!(markdown.contains("**Remediation:** verified (`application-1`)"));
        assert!(markdown.contains("**Empirically verified:** true"));
        assert!(markdown.contains("**Re-verification:** verified (`reverify-run-1`)"));
        assert!(markdown.contains("**Touched paths:** `src/app.ts`"));
    }

    #[test]
    fn sarif_emits_shared_domain_cwe_without_changing_fingerprints() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        write_fixture_source(workspace.root());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-cwe", workspace.root(), "completed")
            .unwrap();
        let finding = fixture_finding("semgrep/CWE_89/sql", Severity::High, 12);
        let fingerprint = finding.fingerprint.clone();
        store.insert_finding("run-cwe", &finding).unwrap();
        let json_output = tmp.path().join("cwe.json");
        let output = tmp.path().join("cwe.sarif");

        export_workspace_findings(&workspace, &json_output, None).unwrap();
        export_workspace_findings(&workspace, &output, None).unwrap();

        let projection: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(json_output).unwrap()).unwrap();
        assert_eq!(projection["findings"][0]["cwe"], "CWE-89");
        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let run = &document["runs"][0];
        assert_eq!(
            run["tool"]["driver"]["rules"][0]["properties"]["tags"][1],
            "CWE-89"
        );
        assert_eq!(run["results"][0]["properties"]["kuzushiCwe"], "CWE-89");
        assert_eq!(run["results"][0]["fingerprints"]["kuzushi/v1"], fingerprint);
    }

    #[test]
    fn allowed_empty_sarif_has_one_stable_driver_run() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let output = tmp.path().join("empty.sarif");

        export_workspace_findings_with_options(
            &workspace,
            &output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Sarif)).with_allow_empty(true),
        )
        .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(document["runs"].as_array().unwrap().len(), 1);
        assert_eq!(document["runs"][0]["tool"]["driver"]["name"], "Kuzushi");
        assert_eq!(
            document["runs"][0]["tool"]["driver"]["rules"],
            serde_json::json!([])
        );
        assert_eq!(document["runs"][0]["results"], serde_json::json!([]));
    }

    #[test]
    fn empty_scan_sarif_identifies_outer_run_and_keeps_spend() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        write_terminal_scan_summary(&workspace, "scan-empty", "sast:scan", 0.0);
        let output = tmp.path().join("empty-scan.sarif");

        export_scan_findings_sarif_with_run_summary(
            &workspace,
            &output,
            &["scan-empty".to_string()],
            "scan-empty",
        )
        .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(
            document["runs"][0]["tool"]["driver"]["name"],
            "kuzushi:sast-scan"
        );
        assert_eq!(
            document["runs"][0]["properties"]["kuzushiScanRunId"],
            "scan-empty"
        );
        assert_eq!(document["runs"][0]["results"], serde_json::json!([]));
        assert_eq!(
            document["properties"]["kuzushiBenchmark"]["aggregateSpend"]["runId"],
            "scan-empty"
        );
        assert_eq!(
            document["properties"]["kuzushiBenchmark"]["aggregateSpend"]["totalCostUsd"],
            0.0
        );
        assert_eq!(
            document["properties"]["kuzushiBenchmark"]["aggregateSpend"]["llmCallCount"],
            0
        );
        assert_eq!(
            document["properties"]["kuzushiBenchmark"]["aggregateSpend"]["models"],
            serde_json::json!([])
        );
    }

    #[test]
    fn scan_sarif_uses_outer_run_cost_once_without_summing_children() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 1);
        write_terminal_scan_summary(&workspace, "run-1", "sast:scan", 0.42);
        write_terminal_scan_summary(&workspace, "child-1", "agentic-sast:scan", 9.99);
        let run_ids = vec!["run-1".to_string(), "child-1".to_string()];
        let output = tmp.path().join("scan.sarif");

        export_scan_findings_sarif_with_run_summary(&workspace, &output, &run_ids, "run-1")
            .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let benchmark = &document["properties"]["kuzushiBenchmark"];
        assert_eq!(benchmark["schemaVersion"], 2);
        assert_eq!(benchmark["aggregateSpend"]["runId"], "run-1");
        assert_eq!(benchmark["aggregateSpend"]["totalCostUsd"], 0.42);
        assert_eq!(
            benchmark["aggregateSpend"]["source"],
            "canonical-run-summary"
        );
        assert_eq!(benchmark["aggregateSpend"]["llmAuditComplete"], true);
        assert_eq!(
            benchmark["aggregateSpend"]["configHash"],
            format!("sha256:{}", "a".repeat(64))
        );
        assert!(document["runs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|run| run.pointer("/properties/kuzushiBenchmark").is_none()));
    }

    #[test]
    fn scan_sarif_omits_canonical_spend_receipt_for_incomplete_aggregate_cost() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        let observed = RuntimeCost::from_usd(0.25, "test benchmark cost").unwrap();
        let summary = RunSummary::running(
            "scan-incomplete",
            "scan",
            Some("sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .complete()
        .with_cost_report(RuntimeCostReport::incomplete(observed));
        write_run_summary(workspace.root(), &summary).unwrap();
        let output = tmp.path().join("incomplete.sarif");

        export_scan_findings_sarif_with_run_summary(
            &workspace,
            &output,
            &["scan-incomplete".to_string()],
            "scan-incomplete",
        )
        .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert!(document.pointer("/properties/kuzushiBenchmark").is_none());
    }

    fn write_terminal_scan_summary(
        workspace: &WorkspaceTarget,
        run_id: &str,
        tool: &str,
        cost_usd: f64,
    ) {
        let summary = RunSummary::running(
            run_id,
            "scan",
            Some(tool.to_string()),
            workspace.root().display().to_string(),
        )
        .complete()
        .with_cost(Some(cost_usd))
        .with_config_hash(Some(format!("sha256:{}", "a".repeat(64))));
        write_run_summary(workspace.root(), &summary).unwrap();
    }

    #[test]
    fn scan_sarif_binds_observed_models_from_every_included_run() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        write_terminal_scan_summary(&workspace, "scan-models", "sast:scan", 0.42);
        write_model_run_summary(&workspace, "child-a", "anthropic:model-a", false);
        write_model_run_summary(&workspace, "child-b", "anthropic:model-b", false);
        let run_ids = vec!["scan-models".into(), "child-a".into(), "child-b".into()];
        let output = tmp.path().join("models.sarif");

        export_scan_findings_sarif_with_run_summary(&workspace, &output, &run_ids, "scan-models")
            .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let receipt = &document["properties"]["kuzushiBenchmark"]["aggregateSpend"];
        assert_eq!(receipt["llmCallCount"], 2);
        assert_eq!(
            receipt["models"],
            serde_json::json!(["anthropic:model-a", "anthropic:model-b"])
        );
        assert_eq!(receipt["llmAuditComplete"], true);
    }

    #[test]
    fn scan_sarif_excludes_explicitly_unattempted_model_calls_from_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        write_terminal_scan_summary(&workspace, "scan-pre-call", "sast:scan", 0.0);
        write_pre_call_model_run_summary(&workspace, "child-pre-call", "anthropic:model-a");
        let output = tmp.path().join("pre-call.sarif");

        export_scan_findings_sarif_with_run_summary(
            &workspace,
            &output,
            &["scan-pre-call".into(), "child-pre-call".into()],
            "scan-pre-call",
        )
        .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        let receipt = &document["properties"]["kuzushiBenchmark"]["aggregateSpend"];
        assert_eq!(receipt["llmCallCount"], 0);
        assert_eq!(receipt["models"], serde_json::json!([]));
        assert_eq!(receipt["llmAuditComplete"], true);
    }

    #[test]
    fn scan_sarif_marks_model_audit_incomplete_when_a_trace_was_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        write_terminal_scan_summary(&workspace, "scan-malformed", "sast:scan", 0.42);
        write_model_run_summary(&workspace, "child-malformed", "anthropic:model-a", true);
        let run_ids = vec!["scan-malformed".into(), "child-malformed".into()];
        let output = tmp.path().join("malformed.sarif");

        export_scan_findings_sarif_with_run_summary(
            &workspace,
            &output,
            &run_ids,
            "scan-malformed",
        )
        .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(
            document["properties"]["kuzushiBenchmark"]["aggregateSpend"]["llmAuditComplete"],
            false
        );
    }

    #[test]
    fn scan_sarif_marks_model_audit_incomplete_for_unresolved_child_spend() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        FindingStore::open(workspace.findings_db_path()).unwrap();
        write_terminal_scan_summary(&workspace, "scan-unresolved-child", "sast:scan", 0.42);
        let observed = RuntimeCost::from_usd(0.1, "test child cost").unwrap();
        let child = RunSummary::running(
            "child-unresolved",
            "tool",
            Some("agentic-sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .complete()
        .with_cost_report(RuntimeCostReport::incomplete(observed))
        .with_llm_calls(vec![RunLlmCallAudit {
            n: 1,
            kind: "reasoning".to_string(),
            verb: Some("query".to_string()),
            model: "anthropic:model-a".to_string(),
            provider: "anthropic".to_string(),
            prompt_hash: "sha256:test".to_string(),
            latency_ms: Some(1),
            cost_usd: Some(0.1),
            observed_cost_usd: None,
            provider_spend_unresolved: false,
            call_attempted: Some(true),
        }]);
        write_run_summary(workspace.root(), &child).unwrap();
        let output = tmp.path().join("unresolved-child.sarif");

        export_scan_findings_sarif_with_run_summary(
            &workspace,
            &output,
            &["scan-unresolved-child".into(), "child-unresolved".into()],
            "scan-unresolved-child",
        )
        .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(
            document["properties"]["kuzushiBenchmark"]["aggregateSpend"]["llmAuditComplete"],
            false
        );
    }

    fn write_model_run_summary(
        workspace: &WorkspaceTarget,
        run_id: &str,
        model: &str,
        malformed_trace: bool,
    ) {
        let summary = RunSummary::running(
            run_id,
            "tool",
            Some("agentic-sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .complete()
        .with_cost(Some(0.1))
        .with_llm_calls(vec![RunLlmCallAudit {
            n: 1,
            kind: "reasoning".to_string(),
            verb: Some("query".to_string()),
            model: model.to_string(),
            provider: "anthropic".to_string(),
            prompt_hash: "sha256:test".to_string(),
            latency_ms: Some(1),
            cost_usd: Some(0.1),
            observed_cost_usd: None,
            provider_spend_unresolved: false,
            call_attempted: None,
        }])
        .with_lifecycle_malformed_items(malformed_trace.then_some(1));
        write_run_summary(workspace.root(), &summary).unwrap();
    }

    fn write_pre_call_model_run_summary(workspace: &WorkspaceTarget, run_id: &str, model: &str) {
        let summary = RunSummary::running(
            run_id,
            "tool",
            Some("agentic-sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .complete()
        .with_cost(Some(0.0))
        .with_llm_calls(vec![RunLlmCallAudit {
            n: 1,
            kind: "reasoning".to_string(),
            verb: Some("query".to_string()),
            model: model.to_string(),
            provider: "anthropic".to_string(),
            prompt_hash: "sha256:test".to_string(),
            latency_ms: None,
            cost_usd: None,
            observed_cost_usd: None,
            provider_spend_unresolved: false,
            call_attempted: Some(false),
        }]);
        write_run_summary(workspace.root(), &summary).unwrap();
    }

    #[test]
    fn suppressed_finding_emits_sarif_suppression() {
        use crate::suppressions::{
            run_suppression_sweep, save_suppression_rules, FindingRef, SuppressionOrigin,
            SuppressionPredicate, SuppressionReason, SuppressionRule,
        };
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 1);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = store.list_findings(1).unwrap().into_iter().next().unwrap();
        let rule = SuppressionRule {
            id: "sup-sarif".to_string(),
            predicate: SuppressionPredicate {
                finding_id: Some(FindingRef(finding.fingerprint.clone())),
                ..SuppressionPredicate::empty()
            },
            reason: SuppressionReason::FalsePositive,
            statement: "sanitized upstream".to_string(),
            actor: "tester".to_string(),
            created_at_unix: 1,
            expires_at_unix: None,
            origin: SuppressionOrigin::File,
        };
        save_suppression_rules(&workspace, &[rule]).unwrap();
        run_suppression_sweep(&store, &workspace, "tester").unwrap();

        let output = tmp.path().join("out.sarif");
        export_workspace_findings(&workspace, &output, None).unwrap();
        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        let result = &document["runs"][0]["results"][0];
        assert_eq!(result["suppressions"][0]["kind"], "external");
    }

    #[test]
    fn export_reflects_a_lapsed_suppression_rule() {
        use crate::suppressions::{
            run_suppression_sweep, save_suppression_rules, FindingRef, SuppressionOrigin,
            SuppressionPredicate, SuppressionReason, SuppressionRule,
        };
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 1);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let fingerprint = store.list_findings(1).unwrap()[0].fingerprint.clone();
        let rule = |expires: Option<u64>| SuppressionRule {
            id: "sup-exp".to_string(),
            predicate: SuppressionPredicate {
                finding_id: Some(FindingRef(fingerprint.clone())),
                ..SuppressionPredicate::empty()
            },
            reason: SuppressionReason::FalsePositive,
            statement: "sanitized".to_string(),
            actor: "op".to_string(),
            created_at_unix: 1,
            expires_at_unix: expires,
            origin: SuppressionOrigin::File,
        };

        // Live rule suppresses the finding (rule-originated) via a sweep.
        save_suppression_rules(&workspace, &[rule(None)]).unwrap();
        run_suppression_sweep(&store, &workspace, "test").unwrap();
        assert!(store.list_findings(1).unwrap()[0].suppressed);

        // Rule lapses. Export must reconcile and show the finding NOT suppressed,
        // even with no intervening scan.
        save_suppression_rules(&workspace, &[rule(Some(2))]).unwrap();
        let output = tmp.path().join("out.sarif");
        export_workspace_findings(&workspace, &output, None).unwrap();
        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        let result = &document["runs"][0]["results"][0];
        assert!(
            result.get("suppressions").is_none(),
            "a lapsed rule must not export as suppressed/accepted"
        );
        let reopened = FindingStore::open(workspace.findings_db_path()).unwrap();
        assert!(!reopened.list_findings(1).unwrap()[0].suppressed);
    }

    #[test]
    fn sarif_export_emits_suppression_for_dismissed_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let dismissed_id = store.list_findings(10).unwrap()[0]
            .id
            .expect("persisted finding id");
        store
            .append_dismissal(
                dismissed_id,
                DismissReason::FalsePositive,
                "sanitized upstream",
                "alice",
            )
            .unwrap();

        let output = tmp.path().join("out.sarif");
        export_workspace_findings(&workspace, &output, None).unwrap();
        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();

        let results = document["runs"][0]["results"].as_array().unwrap();
        let suppressed: Vec<&serde_json::Value> = results
            .iter()
            .filter(|result| result.get("suppressions").is_some())
            .collect();
        assert_eq!(suppressed.len(), 1, "exactly one dismissed finding");
        let suppression = &suppressed[0]["suppressions"][0];
        assert_eq!(suppression["kind"], "external");
        assert_eq!(suppression["status"], "accepted");
        assert_eq!(
            suppression["justification"],
            "false_positive: sanitized upstream"
        );
        assert_eq!(
            suppression["properties"]["kuzushiDismissReason"],
            "false_positive"
        );
        assert_eq!(suppression["properties"]["kuzushiDismissedBy"], "alice");
        // Non-dismissed results carry no suppressions key at all.
        assert!(results
            .iter()
            .any(|result| result.get("suppressions").is_none()));
    }

    #[test]
    fn sarif_export_omits_suppression_for_automated_dismissal() {
        // An LLM auto-triage that maps to a dismissal-style verdict must NOT
        // emit a SARIF suppression (which asserts a human accepted the risk).
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding_id = store.list_findings(10).unwrap()[0]
            .id
            .expect("persisted finding id");
        store
            .record_triage_with_author(
                finding_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.8,
                    rationale: "model believes this is a false positive".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
                TriageAuthor::Auto,
            )
            .unwrap();

        let output = tmp.path().join("out.sarif");
        export_workspace_findings(&workspace, &output, None).unwrap();
        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();

        for run in document["runs"].as_array().unwrap() {
            for result in run["results"].as_array().unwrap() {
                assert!(
                    result.get("suppressions").is_none(),
                    "automated triage must not emit a SARIF suppression"
                );
            }
        }
    }

    #[test]
    fn exports_workspace_findings_to_csv() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding_id = store.list_findings(1).unwrap()[0]
            .id
            .expect("persisted finding id");
        store
            .record_triage_with_author(
                finding_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "reviewed source-linked evidence".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
                TriageAuthor::Human,
            )
            .unwrap();

        let output = tmp.path().join("out.csv");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.format, WorkspaceExportFormat::Csv);
        let body = fs::read_to_string(&output).unwrap();
        let first_line = body.lines().next().unwrap();
        assert!(first_line.starts_with("alias,identity_id,fingerprint,kind,rule_id,title"));
        assert!(first_line.contains("confidence,priority,lifecycle_status,review_decision"));
        assert!(
            first_line.contains("review_decision,review_decision_conflict,review_decision_author")
        );
        assert!(first_line.contains("review_decision_author,triage_verdict,suppressed"));
        assert!(first_line.contains(
            "observed_evidence_present,observed_evidence_count,observed_code_evidence_count"
        ));
        assert!(first_line.contains(
            "observed_capture_evidence_count,observed_other_evidence_count,model_generated_reasoning_present"
        ));
        assert!(first_line.contains("model_generated_reasoning_count,derived_source_present"));
        assert!(first_line.contains("static_proof_state,proof_confidence,verification"));
        assert!(first_line.contains("run_id,run_status,kuzushi_version,model"));
        assert!(first_line.contains(
            "export_completeness,export_included_count,export_total_count,format_omitted_fields"
        ));
        assert!(body.contains("confirmed,,human,true_positive"));
        // Neither fixture finding has runtime/static proof recorded, so the
        // `proof_confidence` column (between static_proof_state and
        // verification) reads `unverified`.
        assert!(body.contains("not_recorded,unverified,not attempted"));
        let omitted = workspace_export_omitted_fields(WorkspaceExportFormat::Csv);
        assert!(omitted.contains(&"provenance.sourceHistory"));
        assert!(body.contains(&format!("all,2,2,{}", omitted.join(";"))));
        assert!(body.contains("fixture/rule-0"));
        assert!(body.contains("fixture/rule-1"));
    }

    #[test]
    fn sanitize_csv_field_guards_formula_leading_characters() {
        for dangerous in ["=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd", "\n=cmd"] {
            assert_eq!(sanitize_csv_field(dangerous), format!("'{dangerous}"));
        }
        // Benign values and interior dangerous characters are left untouched.
        assert_eq!(sanitize_csv_field("fixture/rule-0"), "fixture/rule-0");
        assert_eq!(sanitize_csv_field("a=b"), "a=b");
        assert_eq!(sanitize_csv_field(""), "");
        // A leading multibyte UTF-8 character is not a formula trigger.
        assert_eq!(sanitize_csv_field("é=mc2"), "é=mc2");
    }

    #[test]
    fn csv_export_neutralizes_formula_injection_in_finding_text() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        write_fixture_source(workspace.root());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();
        // A scan target can influence finding text (rule id, title). A crafted
        // finding whose fields begin with `=` would execute as a spreadsheet
        // formula if written verbatim into a CSV cell.
        let finding = Finding::new_tool(
            "fixture",
            "=cmd",
            "src/app.ts",
            10,
            Some(13),
            Severity::High,
            "=1+1",
        );
        store.insert_finding("run-1", &finding).unwrap();

        let output = tmp.path().join("out.csv");
        export_workspace_findings(&workspace, &output, None).unwrap();
        let body = fs::read_to_string(&output).unwrap();

        // The dangerous cells are prefixed with a single quote, so a
        // spreadsheet treats them as text instead of evaluating a formula.
        assert!(body.contains("'=cmd"), "rule id not guarded: {body}");
        assert!(body.contains("'=1+1"), "title not guarded: {body}");
        // The raw, unguarded formula never appears at a cell boundary.
        assert!(
            !body.contains(",=cmd,"),
            "unguarded rule id present: {body}"
        );
        assert!(!body.contains(",=1+1,"), "unguarded title present: {body}");
    }

    #[test]
    fn exports_workspace_findings_to_jsonl_with_metadata_header() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 1);

        let output = tmp.path().join("out.jsonl");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.format, WorkspaceExportFormat::Jsonl);
        assert_eq!(report.count, 1);

        let body = fs::read_to_string(&output).unwrap();
        let lines = body.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        let metadata: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(metadata["recordType"], "metadata");
        assert_eq!(metadata["metadata"]["format"], "jsonl");
        assert_eq!(metadata["metadata"]["completeness"], "all");
        assert_eq!(metadata["metadata"]["includedCount"], 1);
        assert!(metadata["metadata"]["omittedFields"]
            .as_array()
            .unwrap()
            .is_empty());
        let record: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(record["ruleId"], "fixture/rule-0");
        assert_eq!(record["kind"], "scanner_finding");
    }

    #[test]
    fn exports_workspace_findings_by_review_completeness() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();

        let confirmed = fixture_finding("fixture/confirmed", Severity::High, 10);
        let needs_review = fixture_finding("fixture/needs-review", Severity::Medium, 20);
        let untriaged = fixture_finding("fixture/untriaged", Severity::Low, 30);
        let confirmed_id = store.insert_finding("run-1", &confirmed).unwrap();
        let needs_review_id = store.insert_finding("run-1", &needs_review).unwrap();
        store.insert_finding("run-1", &untriaged).unwrap();
        store
            .record_triage_with_author(
                confirmed_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "operator confirmed evidence".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
                TriageAuthor::Human,
            )
            .unwrap();
        store
            .record_auto_triage(
                needs_review_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.5,
                    rationale: "more evidence required".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
            )
            .unwrap();

        let complete_output = tmp.path().join("complete.json");
        let complete = export_workspace_findings_with_options(
            &workspace,
            &complete_output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();
        assert_eq!(complete.count, 1);

        let complete_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(complete_output).unwrap()).unwrap();
        assert_eq!(complete_json["completeness"], "complete");
        assert_eq!(complete_json["totalCount"], 3);
        assert_eq!(complete_json["findings"][0]["ruleId"], "fixture/confirmed");

        let open_output = tmp.path().join("open.csv");
        let open = export_workspace_findings_with_options(
            &workspace,
            &open_output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Csv))
                .with_completeness(WorkspaceExportCompleteness::Open),
        )
        .unwrap();
        assert_eq!(open.count, 2);
        let open_csv = fs::read_to_string(open_output).unwrap();
        assert!(!open_csv.contains("fixture/confirmed"));
        assert!(open_csv.contains("fixture/needs-review"));
        assert!(open_csv.contains("fixture/untriaged"));
    }

    #[test]
    fn filtered_exports_keep_workspace_aliases_and_priority_in_json_and_markdown() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        write_fixture_source(workspace.root());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-aliases", workspace.root(), "completed")
            .unwrap();

        let critical = fixture_finding("fixture/terminal-critical", Severity::Critical, 10);
        let open = fixture_finding("fixture/open-high", Severity::High, 20);
        let low = fixture_finding("fixture/terminal-low", Severity::Low, 30);
        let critical_id = store.insert_finding("run-aliases", &critical).unwrap();
        store.insert_finding("run-aliases", &open).unwrap();
        let low_id = store.insert_finding("run-aliases", &low).unwrap();
        for finding_id in [critical_id, low_id] {
            store
                .record_triage_with_author(
                    finding_id,
                    &TriageOutcome {
                        first_link: None,
                        refute_reason: None,
                        verdict: TriageVerdict::TruePositive,
                        confidence: 0.95,
                        rationale: "operator confirmed the evidence".to_string(),
                        cost_usd: 0.0,
                        cost_usd_exact: true,
                        estimated_cost_usd: None,
                    },
                    TriageAuthor::Human,
                )
                .unwrap();
        }

        let all_output = tmp.path().join("all-aliases.json");
        export_workspace_findings(&workspace, &all_output, Some(WorkspaceExportFormat::Json))
            .unwrap();
        let all: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(all_output).unwrap()).unwrap();
        assert_exported_alias_and_priority(
            &all,
            "fixture/terminal-critical",
            "F-0001",
            "review-order:1",
        );
        assert_exported_alias_and_priority(&all, "fixture/open-high", "F-0002", "review-order:2");
        assert_exported_alias_and_priority(
            &all,
            "fixture/terminal-low",
            "F-0003",
            "review-order:3",
        );

        let open_output = tmp.path().join("open-aliases.json");
        export_workspace_findings_with_options(
            &workspace,
            &open_output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Open),
        )
        .unwrap();
        let open: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(open_output).unwrap()).unwrap();
        assert_eq!(open["findings"].as_array().unwrap().len(), 1);
        assert_exported_alias_and_priority(&open, "fixture/open-high", "F-0002", "review-order:2");

        let complete_output = tmp.path().join("complete-aliases.json");
        export_workspace_findings_with_options(
            &workspace,
            &complete_output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();
        let complete: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(complete_output).unwrap()).unwrap();
        assert_exported_alias_and_priority(
            &complete,
            "fixture/terminal-critical",
            "F-0001",
            "review-order:1",
        );
        assert_exported_alias_and_priority(
            &complete,
            "fixture/terminal-low",
            "F-0003",
            "review-order:3",
        );

        let bundle = tmp.path().join("complete-aliases-bundle");
        export_workspace_findings_with_options(
            &workspace,
            &bundle,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::MarkdownBundle))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(bundle.join("manifest.json")).unwrap())
                .unwrap();
        let aliases = manifest["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["alias"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(aliases, vec!["F-0001", "F-0003"]);
        let low_markdown = fs::read_to_string(bundle.join("findings/F-0003.md")).unwrap();
        assert!(low_markdown.starts_with("# F-0003 ·"), "{low_markdown}");
    }

    #[test]
    fn exports_review_completeness_by_durable_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-identity-a", workspace.root(), "completed")
            .unwrap();
        store
            .record_run_started("run-identity-b", workspace.root(), "completed")
            .unwrap();

        let repeated = fixture_finding("fixture/repeated", Severity::High, 10);
        let first_id = store.insert_finding("run-identity-a", &repeated).unwrap();
        let second_id = store.insert_finding("run-identity-b", &repeated).unwrap();
        store
            .record_triage_with_author(
                first_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "operator confirmed the durable finding".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
                TriageAuthor::Human,
            )
            .unwrap();

        let second_row = store
            .list_findings_for_scan_id("run-identity-b")
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(second_row.id, Some(second_id));
        assert!(second_row.triage.is_none());

        let complete_output = tmp.path().join("identity-complete.json");
        let complete = export_workspace_findings_with_options(
            &workspace,
            &complete_output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();
        assert_eq!(complete.count, 1);

        let complete_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(complete_output).unwrap()).unwrap();
        let decisions = complete_json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["reviewDecision"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(decisions, vec!["confirmed"]);
        assert!(complete_json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["reviewDecisionAuthor"] == serde_json::json!("human")));

        let open_output = tmp.path().join("identity-open.csv");
        let open = export_workspace_findings_with_options(
            &workspace,
            &open_output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Csv))
                .with_completeness(WorkspaceExportCompleteness::Open),
        )
        .unwrap();
        assert_eq!(open.count, 0);
    }

    #[test]
    fn exports_reappeared_rejected_identity_as_open_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-rejected-a", workspace.root(), "completed")
            .unwrap();
        store
            .record_run_started("run-rejected-b", workspace.root(), "completed")
            .unwrap();

        let repeated = fixture_finding("fixture/reappeared", Severity::High, 10);
        let first_id = store.insert_finding("run-rejected-a", &repeated).unwrap();
        let mut second = repeated;
        second.static_proof_state = Some(StaticProofState::SourceSinkLinked);
        store.insert_finding("run-rejected-b", &second).unwrap();
        store
            .record_triage_with_author(
                first_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.91,
                    rationale: "operator rejected prior occurrence".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
                TriageAuthor::Human,
            )
            .unwrap();

        let complete_output = tmp.path().join("reappeared-complete.json");
        let complete = export_workspace_findings_with_options(
            &workspace,
            &complete_output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();
        assert_eq!(complete.count, 0);

        let open_output = tmp.path().join("reappeared-open.json");
        let open = export_workspace_findings_with_options(
            &workspace,
            &open_output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Open),
        )
        .unwrap();
        assert_eq!(open.count, 1);

        let open_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(open_output).unwrap()).unwrap();
        let finding = &open_json["findings"][0];
        assert_eq!(finding["runId"], "run-rejected-b");
        assert_eq!(finding["reviewDecision"], "rejected_false_positive");
        assert_eq!(
            finding["reviewDecisionConflict"],
            "reappeared_after_rejection"
        );
        assert_eq!(finding["lifecycleStatus"], "statically_supported");
    }

    #[test]
    fn exports_workspace_findings_to_markdown_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);

        let output = tmp.path().join("bundle");
        let report = export_workspace_findings(
            &workspace,
            &output,
            Some(WorkspaceExportFormat::MarkdownBundle),
        )
        .unwrap();

        assert_eq!(report.format, WorkspaceExportFormat::MarkdownBundle);
        assert!(output.join("README.md").exists());
        assert!(output.join("manifest.json").exists());

        let readme = fs::read_to_string(output.join("README.md")).unwrap();
        assert!(readme.contains("automated, AI-assisted security analysis"));
        assert!(readme.contains("Treat each finding as a review candidate"));
        assert!(readme.contains("`confirmed` means authenticated runtime reproduction"));
        assert!(!readme.contains("WorkspaceFindingExportRecord"));
        assert!(readme.contains("**Finding selection:** `all`"));
        assert!(readme.contains("**Included:** 2 of 2 finding(s)"));
        assert!(readme.contains("**Field coverage:** human-readable subset"));
        assert!(readme.contains("**Review decisions:** needs_review=2"));
        assert!(readme.contains(
            "| Alias | Severity | Proof band | Decision | Lifecycle | Evidence | Location |"
        ));

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["count"], 2);
        assert_eq!(manifest["completeness"], "all");
        assert_eq!(manifest["metadata"]["format"], "markdown-bundle");
        assert_eq!(
            manifest["metadata"]["projection"],
            "WorkspaceFindingExportRecord"
        );
        assert_eq!(manifest["includedCount"], 2);
        assert_eq!(manifest["totalCount"], 2);
        let omitted = manifest["metadata"]["omittedFields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();
        for field in [
            "kind",
            "triageState",
            "dismissal",
            "suppressed",
            "location.endLine",
            "evidence.rawHttpBlobPresent",
            "evidence.evidenceConfidenceMax",
            "analysis.humanReviewPresent",
            "verification.backend",
            "vulnSource",
            "provenance.kuzushiVersion",
            "remediation.findingScanId",
        ] {
            assert!(omitted.contains(&field), "missing omitted field {field}");
        }
        for rendered in [
            "recommendation",
            "impact",
            "category",
            "exploitScenario",
            "preconditions",
        ] {
            assert!(
                !omitted.contains(&rendered),
                "rendered field listed as omitted: {rendered}"
            );
        }
        let files = manifest["files"].as_array().unwrap();
        assert_eq!(files.len(), 3);
        assert!(files.iter().any(|file| {
            file["path"] == "README.md"
                && file["sha256"]
                    .as_str()
                    .is_some_and(|hash| hash.starts_with("sha256:"))
        }));
        let entries = manifest["findings"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let alias = entries[0]["alias"].as_str().unwrap();
        assert_eq!(entries[0]["path"], format!("findings/{alias}.md"));
        assert!(entries[0]["sha256"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        assert!(output.join("findings").join(format!("{alias}.md")).exists());
    }

    /// Field names the fixture cannot populate because their type is not part
    /// of the crate's public export surface. They are still checked for
    /// membership in the manifest, just not for presence in the bundle.
    const BUNDLE_FIELDS_THE_FIXTURE_CANNOT_POPULATE: &[&str] = &["dismissal"];

    /// `MARKDOWN_BUNDLE_OMITTED` and the bundle renderer are two hand-kept
    /// lists that must agree, and they drifted once. Render a record whose
    /// every string-valued field carries a distinct sentinel, then assert the
    /// sentinel is in the bundle exactly when the manifest does not call that
    /// field omitted.
    ///
    /// Numeric and boolean fields carry no distinctive value, so the presence
    /// half of the check covers the string-valued fields; the membership check
    /// below still pins every omitted name against the live projection, so a
    /// renamed or deleted field cannot leave a stale entry behind.
    #[test]
    fn markdown_bundle_renders_every_field_its_manifest_does_not_call_omitted() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let record = sentinel_export_record();
        let finding = sentinel_export_finding(&record);
        let output = tmp.path().join("bundle");

        super::super::application::write_markdown_bundle(
            &workspace,
            std::slice::from_ref(&finding),
            std::slice::from_ref(&record),
            &output,
            &WorkspaceExportOptions {
                format: Some(WorkspaceExportFormat::MarkdownBundle),
                ..WorkspaceExportOptions::default()
            },
            1,
        )
        .unwrap();

        let bundle = read_bundle_text(&output);
        let omitted = workspace_export_omitted_fields(WorkspaceExportFormat::MarkdownBundle);
        let mut probes = Vec::new();
        export_field_probes(
            &serde_json::to_value(&record).unwrap(),
            "",
            &omitted,
            &mut probes,
        );

        assert!(
            probes.len() > 40,
            "field walk collapsed to {} probes",
            probes.len()
        );
        for (name, sentinels) in &probes {
            let is_omitted = omitted.contains(&name.as_str());
            for sentinel in sentinels {
                assert_eq!(
                    bundle.contains(sentinel.as_str()),
                    !is_omitted,
                    "field {name:?} is {} in the manifest but {} in the bundle",
                    if is_omitted { "omitted" } else { "rendered" },
                    if is_omitted { "present" } else { "missing" }
                );
            }
        }

        let projected: std::collections::BTreeSet<&str> =
            probes.iter().map(|(name, _)| name.as_str()).collect();
        for name in &omitted {
            assert!(
                projected.contains(name)
                    || BUNDLE_FIELDS_THE_FIXTURE_CANNOT_POPULATE.contains(name),
                "manifest omits {name:?}, which the export projection no longer has"
            );
        }
    }

    /// Flatten the export projection into the dotted field names the manifest
    /// speaks, pairing each with the string values that carry it into the
    /// rendered bundle. Recursion stops at a name the manifest itself lists,
    /// so `dismissal` stays one field rather than four.
    fn export_field_probes(
        value: &serde_json::Value,
        prefix: &str,
        omitted: &[&str],
        out: &mut Vec<(String, Vec<String>)>,
    ) {
        for (key, child) in value.as_object().expect("export record is an object") {
            let name = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if child.is_object() && prefix.is_empty() && !omitted.contains(&name.as_str()) {
                export_field_probes(child, &name, omitted, out);
            } else {
                out.push((name, string_leaves(child)));
            }
        }
    }

    fn string_leaves(value: &serde_json::Value) -> Vec<String> {
        match value {
            serde_json::Value::String(text) => vec![text.clone()],
            serde_json::Value::Array(items) => items.iter().flat_map(string_leaves).collect(),
            serde_json::Value::Object(fields) => fields.values().flat_map(string_leaves).collect(),
            _ => Vec::new(),
        }
    }

    fn read_bundle_text(output: &std::path::Path) -> String {
        let mut text = fs::read_to_string(output.join("README.md")).unwrap();
        text.push_str(&fs::read_to_string(output.join("manifest.json")).unwrap());
        for entry in fs::read_dir(output.join("findings")).unwrap() {
            text.push_str(&fs::read_to_string(entry.unwrap().path()).unwrap());
        }
        text
    }

    fn sentinel_export_finding(record: &WorkspaceFindingExportRecord) -> Finding {
        let mut finding = Finding::new_semgrep(
            &record.rule_id,
            &record.location.file,
            record.location.start_line,
            record.location.end_line,
            Severity::High,
            &record.message,
        );
        finding.fingerprint = record.fingerprint.clone();
        finding
    }

    fn sentinel_export_record() -> WorkspaceFindingExportRecord {
        WorkspaceFindingExportRecord {
            alias: "sentinel-alias".to_string(),
            identity_id: Some("sentinel-identity-id".to_string()),
            fingerprint: "sentinel-fingerprint".to_string(),
            kind: "sentinel-kind".to_string(),
            rule_id: "sentinel-rule-id".to_string(),
            title: "sentinel-title".to_string(),
            cwe: Some("sentinel-cwe".to_string()),
            location: WorkspaceFindingExportLocation {
                file: "sentinel-location-file".to_string(),
                start_line: 41,
                end_line: Some(42),
            },
            severity: "sentinel-severity".to_string(),
            confidence: Some(0.5),
            priority: "sentinel-priority".to_string(),
            lifecycle_status: "sentinel-lifecycle-status".to_string(),
            review_decision: "sentinel-review-decision".to_string(),
            relationships: Vec::new(),
            lessons: Vec::new(),
            triage_state: "sentinel-triage-state".to_string(),
            observation_gap: Some(crate::findings::FindingObservationGap {
                event_seq: 7,
                event_hash: "sentinel-observation-event-hash".to_string(),
                last_seen_run_id: Some("sentinel-observation-last-run".to_string()),
                compared_run_id: Some("sentinel-observation-compared-run".to_string()),
            }),
            observation_note: Some("sentinel-observation-note".to_string()),
            dismissal: None,
            review_decision_conflict: Some("sentinel-review-decision-conflict".to_string()),
            review_decision_reason: Some("sentinel-review-decision-reason".to_string()),
            review_decision_author: Some("sentinel-review-decision-author".to_string()),
            reviewed_source: None,
            review_decision_basis: Some(crate::workspace::WorkspaceReviewDecisionBasis {
                run_id: "sentinel-decision-basis-run".to_string(),
                snapshot_hash: "sentinel-decision-basis-snapshot".to_string(),
                source_git: Some(crate::RunTargetGitMetadata {
                    sha: "1".repeat(40),
                    branch: Some("sentinel-decision-branch".into()),
                    dirty: false,
                }),
                later_observation: Some(crate::workspace::WorkspaceObservedSource {
                    run_id: "sentinel-decision-later-run".to_string(),
                    snapshot_hash: "sentinel-decision-later-snapshot".to_string(),
                    source_git: Some(crate::RunTargetGitMetadata {
                        sha: "2".repeat(40),
                        branch: Some("sentinel-later-branch".into()),
                        dirty: true,
                    }),
                }),
                source_changed_since_decision: true,
                source_comparison:
                    crate::workspace::WorkspaceReviewSourceComparison::DifferentCitedSource,
                source_applicability:
                    crate::workspace::WorkspaceReviewSourceApplicability::ReassessmentRequired,
            }),
            triage_verdict: Some("sentinel-triage-verdict".to_string()),
            suppressed: true,
            snoozed_until: Some("sentinel-snoozed-until".to_string()),
            evidence: WorkspaceEvidenceExportSummary {
                state: "sentinel-evidence-state".to_string(),
                observed_evidence_present: true,
                observed_count: 3,
                observed_code_count: 1,
                observed_capture_count: 1,
                observed_other_count: 1,
                model_generated_reasoning_present: true,
                model_generated_reasoning_count: 2,
                derived_source_present: true,
                source_count: 4,
                raw_http_blob_present: true,
                evidence_confidence_max: Some(7),
            },
            analysis: WorkspaceAnalysisExportSummary {
                static_proof_recorded: true,
                automated_reasoning_present: true,
                human_review_present: true,
                imported_review_present: true,
            },
            static_proof_state: "sentinel-static-proof-state".to_string(),
            static_proof_label: "sentinel-static-proof-label".to_string(),
            proof_confidence: "sentinel-proof-confidence".to_string(),
            verification: WorkspaceVerificationExportSummary {
                label: "sentinel-verification-label".to_string(),
                verdict: Some("sentinel-verification-verdict".to_string()),
                proof_level: Some(3),
                backend: Some("sentinel-verification-backend".to_string()),
                language: Some("sentinel-verification-language".to_string()),
                source_identity: Some(
                    crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
                        snapshot_hash: crate::run_lifecycle::SafeText::operator_visible(
                            "sentinel-source-identity-hash",
                        ),
                        tree_hash: None,
                    },
                ),
                reproducer: Some(
                    serde_json::from_value(serde_json::json!({
                        "kind": "proof-snapshot",
                        "hash": "sentinel-reproducer-hash",
                        "sizeBytes": 1
                    }))
                    .expect("test proof-snapshot reference"),
                ),
            },
            tool: "sentinel-tool".to_string(),
            vuln_source: "sentinel-vuln-source".to_string(),
            source_signature: Some("sentinel-source-signature".to_string()),
            corroboration_count: 5,
            run_id: Some("sentinel-run-id".to_string()),
            provenance: WorkspaceFindingProvenanceSummary {
                tool: "sentinel-provenance-tool".to_string(),
                vuln_source: "sentinel-provenance-vuln-source".to_string(),
                source_signature: Some("sentinel-provenance-source-signature".to_string()),
                corroboration_count: 6,
                source_history: Vec::new(),
                run_id: Some("sentinel-provenance-run-id".to_string()),
                run_status: Some("sentinel-provenance-run-status".to_string()),
                kuzushi_version: Some("sentinel-provenance-kuzushi-version".to_string()),
                model: Some("sentinel-provenance-model".to_string()),
                runtime_platform: Some("sentinel-provenance-runtime-platform".to_string()),
            },
            remediation: Some(WorkspaceRemediationExportSummary {
                application_id: "sentinel-remediation-application-id".to_string(),
                patch_run_id: "sentinel-remediation-patch-run-id".to_string(),
                finding_scan_id: Some("sentinel-remediation-finding-scan-id".to_string()),
                application_state: "sentinel-remediation-application-state".to_string(),
                empirically_verified: true,
                reverify_outcome: Some("sentinel-remediation-reverify-outcome".to_string()),
                reverify_run_id: Some("sentinel-remediation-reverify-run-id".to_string()),
                diff_hash: "sentinel-remediation-diff-hash".to_string(),
                touched_paths: vec!["sentinel-remediation-touched-path".to_string()],
            }),
            recommendation: Some("sentinel-recommendation".to_string()),
            impact: Some("sentinel-impact".to_string()),
            category: Some("sentinel-category".to_string()),
            exploit_scenario: Some("sentinel-exploit-scenario".to_string()),
            preconditions: vec!["sentinel-precondition".to_string()],
            references: vec!["sentinel-reference".to_string()],
            message: "sentinel-message".to_string(),
        }
    }

    #[test]
    fn markdown_bundle_renders_producer_security_context_without_fabricating_empty_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        write_fixture_source(workspace.root());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-enriched", workspace.root(), "completed")
            .unwrap();
        let mut enriched = fixture_finding("fixture/enriched", Severity::High, 10);
        enriched.remediation = Some("Bind `id` and notify @security\nthen retest".to_string());
        enriched.impact = Some("An attacker can read [private] rows".to_string());
        enriched.exploit_scenario = Some("A crafted id reaches the query".to_string());
        enriched.category = Some("injection".to_string());
        enriched.preconditions = vec!["Network access to `GET /orders`".to_string()];
        store.insert_finding("run-enriched", &enriched).unwrap();
        let mut sparse = fixture_finding("fixture/sparse", Severity::Low, 20);
        sparse.remediation = Some("  \n".to_string());
        sparse.preconditions = vec!["  ".to_string()];
        store.insert_finding("run-enriched", &sparse).unwrap();

        let output = tmp.path().join("enriched-bundle");
        export_workspace_findings(
            &workspace,
            &output,
            Some(WorkspaceExportFormat::MarkdownBundle),
        )
        .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output.join("manifest.json")).unwrap())
                .unwrap();
        let entries = manifest["findings"].as_array().unwrap();
        let enriched_path = entries
            .iter()
            .find(|entry| entry["ruleId"] == "fixture/enriched")
            .unwrap()["path"]
            .as_str()
            .unwrap();
        let sparse_path = entries
            .iter()
            .find(|entry| entry["ruleId"] == "fixture/sparse")
            .unwrap()["path"]
            .as_str()
            .unwrap();
        let markdown = fs::read_to_string(output.join(enriched_path)).unwrap();
        assert!(markdown.contains("## Security context"), "{markdown}");
        assert!(
            markdown
                .contains("**Recommended change:** Bind `id` and notify &#64;security then retest"),
            "{markdown}"
        );
        assert!(
            markdown.contains("**Impact:** An attacker can read \\[private\\] rows"),
            "{markdown}"
        );
        assert!(
            markdown.contains("**Exploit scenario:** A crafted id reaches the query"),
            "{markdown}"
        );
        assert!(markdown.contains("**Category:** injection"), "{markdown}");
        assert!(
            markdown.contains("  - Network access to `GET /orders`"),
            "{markdown}"
        );
        let sparse_markdown = fs::read_to_string(output.join(sparse_path)).unwrap();
        assert!(
            !sparse_markdown.contains("## Security context"),
            "{sparse_markdown}"
        );
    }

    #[test]
    fn markdown_bundle_records_filtered_completeness_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        write_fixture_source(workspace.root());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();

        let confirmed = fixture_finding("fixture/confirmed", Severity::High, 10);
        let open = fixture_finding("fixture/open", Severity::Medium, 20);
        let confirmed_id = store.insert_finding("run-1", &confirmed).unwrap();
        store.insert_finding("run-1", &open).unwrap();
        store
            .record_auto_triage(
                confirmed_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "operator confirmed".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
            )
            .unwrap();

        let output = tmp.path().join("complete-bundle");
        let report = export_workspace_findings_with_options(
            &workspace,
            &output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::MarkdownBundle))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();
        assert_eq!(report.count, 1);

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["completeness"], "complete");
        assert_eq!(manifest["includedCount"], 1);
        assert_eq!(manifest["totalCount"], 2);
        assert_eq!(manifest["metadata"]["completeness"], "complete");
        assert_eq!(manifest["metadata"]["includedCount"], 1);
        assert_eq!(manifest["metadata"]["totalCount"], 2);
        assert_eq!(manifest["findings"][0]["ruleId"], "fixture/confirmed");
        let readme = fs::read_to_string(output.join("README.md")).unwrap();
        assert!(readme.contains("**Finding selection:** `complete`"));
        assert!(readme.contains("**Included:** 1 of 2 finding(s)"));
        assert!(readme.contains("**Review decisions:** confirmed=1"));
        let alias = manifest["findings"][0]["alias"].as_str().unwrap();
        let finding_markdown =
            fs::read_to_string(output.join("findings").join(format!("{alias}.md"))).unwrap();
        assert!(
            finding_markdown.contains("**Review decision:** confirmed"),
            "{finding_markdown}"
        );
        assert!(
            finding_markdown.contains("**Lifecycle status:** seen"),
            "{finding_markdown}"
        );
        assert!(
            finding_markdown.contains("**Evidence state:** observed (1 observed)"),
            "{finding_markdown}"
        );
        assert!(finding_markdown.contains(
            "**Evidence origin:** observed=true code=1 capture=0 other=0 model-generated-reasoning=0 derived-source=false"
        ), "{finding_markdown}");
        assert!(
            finding_markdown.contains("**Automated reasoning:** true"),
            "{finding_markdown}"
        );
        assert!(
            finding_markdown.contains("**Static proof:** not recorded"),
            "{finding_markdown}"
        );
        assert!(
            finding_markdown.contains("**Verification:** not attempted"),
            "{finding_markdown}"
        );
    }

    #[test]
    fn markdown_bundle_refuses_non_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 1);

        let output = tmp.path().join("bundle");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("stale.txt"), "old").unwrap();

        let err = export_workspace_findings(
            &workspace,
            &output,
            Some(WorkspaceExportFormat::MarkdownBundle),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("must be empty"));
    }

    #[test]
    fn human_confirmed_decision_masks_later_auto_retriage_in_export() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .unwrap();

        // Create a finding and record human Confirmed decision
        let finding = fixture_finding("fixture/human-confirmed", Severity::High, 10);
        let finding_id = store.insert_finding("run-1", &finding).unwrap();
        store
            .record_triage_with_author(
                finding_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "human confirmed this is real".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
                TriageAuthor::Human,
            )
            .unwrap();

        // Simulate an automated re-triage that tries to change the verdict to FalsePositive
        // (e.g., a later LLM run changing its mind)
        store
            .record_triage_with_author(
                finding_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.7,
                    rationale: "auto re-triage thinks this is fp".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
                TriageAuthor::Auto,
            )
            .unwrap();

        // Export should use the human decision (Confirmed), not the auto re-triage
        let output = tmp.path().join("export.json");
        export_workspace_findings_with_options(
            &workspace,
            &output,
            &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();

        let export_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        let exported = &export_json["findings"][0];

        // The exported triage_state must reflect the human decision (confirmed),
        // not the auto re-triage (open). This is the core fix: the export path
        // now uses the latest HUMAN decision, not the latest ANY-author decision.
        assert_eq!(
            exported["triageState"], "confirmed",
            "human Confirmed decision must be preserved in export despite later auto re-triage"
        );
        // Verify the decision author is human, not auto
        assert_eq!(
            exported["reviewDecisionAuthor"], "human",
            "review decision author must be human, not auto"
        );
    }
}
