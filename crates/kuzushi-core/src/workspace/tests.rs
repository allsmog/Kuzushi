#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::findings::{
        DismissReason, Finding, FindingEvidence, FindingStore, ReviewDecision,
        ReviewDecisionVerdict, Severity, StaticProofState, TriageAuthor, TriageOutcome,
        TriageVerdict,
    };
    use crate::run_artifacts::{write_run_summary, RunSummary};
    use std::fs;

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
    fn resolves_codeql_database_paths_under_project() {
        let tmp = tempfile::tempdir().unwrap();

        assert_eq!(
            workspace_codeql_db_path(tmp.path()),
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
            serde_json::json!(true)
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

        let error = export_workspace_findings_with_options(&workspace, &output, options)
            .unwrap_err()
            .to_string();

        assert!(error.contains("selected 0 findings"));
        assert!(!workspace.root().join("exports").exists());

        let report = export_workspace_findings_with_options(
            &workspace,
            &output,
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)).with_allow_empty(true),
        )
        .unwrap();
        assert_eq!(report.count, 0);
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(exported["count"], serde_json::json!(0));
        assert_eq!(exported["metadata"]["includedCount"], 0);
        assert_eq!(exported["metadata"]["totalCount"], 0);
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

            let preview = preview_workspace_findings_export(&workspace, format, options).unwrap();
            let output = tmp.path().join(format!("preview-equivalent.{extension}"));
            let report =
                export_workspace_findings_with_options(&workspace, &output, options).unwrap();

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
            preview_workspace_findings_export(&workspace, WorkspaceExportFormat::Json, options)
                .unwrap_err()
                .to_string();

        assert!(error.contains("selected 0 findings"));

        let preview = preview_workspace_findings_export(
            &workspace,
            WorkspaceExportFormat::Json,
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)).with_allow_empty(true),
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
            options,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("markdown-bundle preview is directory-shaped"));
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
        // Non-suppressed findings carry no SARIF result.suppressions array.
        assert!(first.get("suppressions").is_none());
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
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.8,
                    rationale: "model believes this is a false positive".to_string(),
                    cost_usd: 0.0,
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
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "reviewed source-linked evidence".to_string(),
                    cost_usd: 0.0,
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
        assert!(body.contains(
            "all,2,2,reviewDecisionReason;snoozedUntil;evidence.sourceCount;evidence.rawHttpBlobPresent"
        ));
        assert!(body.contains("fixture/rule-0"));
        assert!(body.contains("fixture/rule-1"));
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
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "operator confirmed evidence".to_string(),
                    cost_usd: 0.0,
                },
                TriageAuthor::Human,
            )
            .unwrap();
        store
            .record_auto_triage(
                needs_review_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.5,
                    rationale: "more evidence required".to_string(),
                    cost_usd: 0.0,
                },
            )
            .unwrap();

        let complete_output = tmp.path().join("complete.json");
        let complete = export_workspace_findings_with_options(
            &workspace,
            &complete_output,
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
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
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Csv))
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
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "operator confirmed the durable finding".to_string(),
                    cost_usd: 0.0,
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
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();
        assert_eq!(complete.count, 2);

        let complete_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(complete_output).unwrap()).unwrap();
        let decisions = complete_json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["reviewDecision"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(decisions, vec!["confirmed", "confirmed"]);
        assert!(complete_json["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["reviewDecisionAuthor"] == serde_json::json!("human")));

        let open_output = tmp.path().join("identity-open.csv");
        let open = export_workspace_findings_with_options(
            &workspace,
            &open_output,
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Csv))
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
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.91,
                    rationale: "operator rejected prior occurrence".to_string(),
                    cost_usd: 0.0,
                },
                TriageAuthor::Human,
            )
            .unwrap();

        let complete_output = tmp.path().join("reappeared-complete.json");
        let complete = export_workspace_findings_with_options(
            &workspace,
            &complete_output,
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
                .with_completeness(WorkspaceExportCompleteness::Complete),
        )
        .unwrap();
        assert_eq!(complete.count, 1);

        let open_output = tmp.path().join("reappeared-open.json");
        let open = export_workspace_findings_with_options(
            &workspace,
            &open_output,
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
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
        assert!(readme.contains("**Projection:** `WorkspaceFindingExportRecord`"));
        assert!(readme.contains("**Completeness:** `all`"));
        assert!(readme.contains("**Included:** 2 of 2 finding(s)"));
        assert!(readme.contains("**Review decisions:** needs_review=2"));
        assert!(readme.contains(
            "| Alias | Severity | Confidence | Decision | Lifecycle | Evidence | Location |"
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
        assert!(manifest["metadata"]["omittedFields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field.as_str() == Some("evidence.rawHttpBlobPresent")));
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
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "operator confirmed".to_string(),
                    cost_usd: 0.0,
                },
            )
            .unwrap();

        let output = tmp.path().join("complete-bundle");
        let report = export_workspace_findings_with_options(
            &workspace,
            &output,
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::MarkdownBundle))
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
        assert!(readme.contains("**Completeness:** `complete`"));
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
            "**Evidence origin:** observed=true code=1 capture=0 other=0 model-generated-reasoning=0 derived-source=true"
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
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "human confirmed this is real".to_string(),
                    cost_usd: 0.0,
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
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.7,
                    rationale: "auto re-triage thinks this is fp".to_string(),
                    cost_usd: 0.0,
                },
                TriageAuthor::Auto,
            )
            .unwrap();

        // Export should use the human decision (Confirmed), not the auto re-triage
        let output = tmp.path().join("export.json");
        export_workspace_findings_with_options(
            &workspace,
            &output,
            WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json))
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
