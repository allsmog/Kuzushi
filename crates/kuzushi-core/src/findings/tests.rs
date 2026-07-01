#[cfg(test)]
mod tests {
    use super::super::domain::fingerprint_parts;
    use super::super::persistence::merge_tool_list;
    use super::super::*;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn extract_cwe_finds_first_cwe_in_message() {
        assert_eq!(
            extract_cwe("rule-x", "OOB write", "user-controlled length, see CWE-787"),
            Some("CWE-787".to_string())
        );
    }

    #[test]
    fn extract_cwe_handles_lowercase_and_multiple() {
        assert_eq!(
            extract_cwe("cwe-125/rule", "title", "msg"),
            Some("CWE-125".to_string())
        );
        assert_eq!(
            extract_cwe(
                "rule",
                "title",
                "could be CWE-787 or CWE-125 — needs review"
            ),
            Some("CWE-787".to_string()) // first hit wins
        );
    }

    #[test]
    fn extract_cwe_accepts_common_separator_variants() {
        assert_eq!(
            extract_cwe("rule", "CWE 89 SQL injection", "msg"),
            Some("CWE-89".to_string())
        );
        assert_eq!(
            extract_cwe("rule", "title", "maps to CWE_787"),
            Some("CWE-787".to_string())
        );
    }

    #[test]
    fn normalize_cwe_collapses_variants() {
        assert_eq!(normalize_cwe("CWE-787"), "787");
        assert_eq!(normalize_cwe("cwe_787"), "787");
        assert_eq!(normalize_cwe("CWE787"), "787");
        assert_eq!(normalize_cwe(" 787 "), "787");
    }

    #[test]
    fn compute_dedup_key_buckets_nearby_lines_by_8() {
        let a = compute_dedup_key("src/foo.c", 42, Some("CWE-787"));
        let b = compute_dedup_key("src/foo.c", 43, Some("CWE-787"));
        let c = compute_dedup_key("src/foo.c", 48, Some("CWE-787"));
        assert_eq!(a, b, "lines 42 and 43 share the bucket 42/8=5");
        assert_ne!(a, c, "line 48 is in the next 8-line bucket");
    }

    #[test]
    fn root_cause_key_groups_call_sites_the_dedup_key_separates() {
        // Two call sites of one CWE-89 defect, far enough apart that the
        // line-bucketed dedup key keeps them distinct...
        let near = compute_dedup_key("src/db.rs", 10, Some("CWE-89"));
        let far = compute_dedup_key("src/db.rs", 200, Some("CWE-89"));
        assert_ne!(near, far, "distant lines get separate dedup keys");

        // ...but they share one root cause.
        let root_a = compute_root_cause_key("src/db.rs", Some("CWE-89"));
        let root_b = compute_root_cause_key("./src/db.rs", Some("cwe-89"));
        assert_eq!(root_a, root_b, "path prefix and CWE formatting normalize");

        // Different CWE or different file is a different root cause.
        assert_ne!(root_a, compute_root_cause_key("src/db.rs", Some("CWE-79")));
        assert_ne!(root_a, compute_root_cause_key("src/api.rs", Some("CWE-89")));
    }

    #[test]
    fn finding_projection_centralizes_common_labels() {
        let finding = Finding::new_tool(
            "semgrep",
            "rules/cwe-89",
            "src/app.ts",
            10,
            Some(12),
            Severity::High,
            "SQL injection\nEvidence: request query reaches raw SQL",
        );

        let projection = project_finding(&finding, Some("F-0001".to_string()));

        assert_eq!(projection.alias.as_deref(), Some("F-0001"));
        assert_eq!(projection.location, "src/app.ts:10-12");
        assert_eq!(projection.verdict_label, "untriaged");
        assert_eq!(projection.confidence_label, "-");
        assert_eq!(projection.cwe_label, "CWE-89");
        assert_eq!(projection.evidence_preview, "request query reaches raw SQL");
        assert_eq!(severity_badge(projection.severity), "🟧 HIGH");
    }

    #[test]
    fn vuln_source_round_trips_through_parse() {
        for src in [
            VulnSource::Sarif,
            VulnSource::Ainalysis,
            VulnSource::AinalysisMulti,
            VulnSource::DiffAnalyzer,
            VulnSource::Infer,
            VulnSource::Fuzzing,
        ] {
            assert_eq!(VulnSource::parse(src.as_str()), Some(src));
        }
    }

    #[test]
    fn vuln_source_from_tool_classifies_known_tools() {
        assert_eq!(VulnSource::from_tool("semgrep"), VulnSource::Sarif);
        assert_eq!(VulnSource::from_tool("codeql"), VulnSource::Sarif);
        assert_eq!(VulnSource::from_tool("systems-hunt"), VulnSource::Ainalysis);
        assert_eq!(
            VulnSource::from_tool("full-mode-multi"),
            VulnSource::AinalysisMulti
        );
        assert_eq!(
            VulnSource::from_tool("variant-ndiff"),
            VulnSource::DiffAnalyzer
        );
    }

    #[test]
    fn new_tool_only_sets_dedup_key_when_cwe_was_extracted() {
        let with_cwe = Finding::new_tool(
            "semgrep",
            "rule",
            "src/foo.c",
            10,
            Some(15),
            Severity::High,
            "OOB write CWE-787 in handler",
        );
        assert!(with_cwe.dedup_key.is_some());
        let without_cwe = Finding::new_tool(
            "semgrep",
            "rule",
            "src/foo.c",
            10,
            Some(15),
            Severity::High,
            "Hardcoded credential in source",
        );
        assert!(without_cwe.dedup_key.is_none());
    }

    #[test]
    fn merge_tool_list_is_set_union() {
        assert_eq!(merge_tool_list("semgrep", "codeql"), "codeql,semgrep");
        assert_eq!(
            merge_tool_list("semgrep,codeql", "semgrep"),
            "codeql,semgrep"
        );
        assert_eq!(merge_tool_list("", "semgrep"), "semgrep");
    }

    #[test]
    fn cross_channel_dedup_merges_higher_severity_finding() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-dedup";
        store
            .insert_scan_run(run, std::path::Path::new("/tmp"), "running")
            .unwrap();

        // Two findings on the same file/line/CWE from different channels.
        let semgrep = Finding::new_tool(
            "semgrep",
            "java.injection.tainted-system-call",
            "src/foo.c",
            42,
            Some(42),
            Severity::Medium,
            "user-controlled exec, CWE-78",
        );
        let id1 = store.insert_finding(run, &semgrep).unwrap();

        // Higher-severity collision from full-mode-multi.
        let chunked = Finding::new_tool(
            "full-mode-multi",
            "full-mode-multi/cwe-78",
            "src/foo.c",
            43, // same 8-line bucket as 42
            Some(45),
            Severity::High,
            "exec with attacker-controlled argv, CWE-78",
        );
        // Make sure both have the same dedup_key.
        assert_eq!(semgrep.dedup_key, chunked.dedup_key);
        // …but different fingerprints (rule_id differs).
        assert_ne!(semgrep.fingerprint, chunked.fingerprint);

        let id2 = store.insert_finding(run, &chunked).unwrap();

        // Merge means same row id is returned.
        assert_eq!(id1, id2);

        let listed = store.list_findings(10).unwrap();
        assert_eq!(listed.len(), 1, "merged into a single row");
        let row = &listed[0];
        // High wins.
        assert_eq!(row.severity, Severity::High);
        // Tool list merged.
        assert!(row.tool.contains("semgrep"));
        assert!(row.tool.contains("full-mode-multi"));
        assert_eq!(row.dedup_key, semgrep.dedup_key);
    }

    #[test]
    fn cross_channel_dedup_preserves_existing_when_lower_severity_arrives() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-dedup-2";
        store
            .insert_scan_run(run, std::path::Path::new("/tmp"), "running")
            .unwrap();

        let high = Finding::new_tool(
            "full-mode-multi",
            "full-mode-multi/cwe-787",
            "src/foo.c",
            42,
            Some(42),
            Severity::Critical,
            "OOB write CWE-787",
        );
        store.insert_finding(run, &high).unwrap();
        let low = Finding::new_tool(
            "semgrep",
            "rule",
            "src/foo.c",
            43, // same bucket as 42 (both in 40..47)
            Some(47),
            Severity::Low,
            "weakish suspicion CWE-787",
        );
        store.insert_finding(run, &low).unwrap();
        let listed = store.list_findings(10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].severity, Severity::Critical);
        // Tool list still merges even when severity didn't change.
        assert!(listed[0].tool.contains("semgrep"));
        assert!(listed[0].tool.contains("full-mode-multi"));
    }

    #[test]
    fn stores_and_lists_findings_with_triage() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-1";
        store
            .insert_scan_run(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        let finding_id = store.insert_finding(run_id, &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.42,
                    rationale: "needs dataflow confirmation".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let rows = store.list_findings(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule_id, "demo.rule");
        assert_eq!(
            rows[0].triage.as_ref().unwrap().verdict,
            TriageVerdict::NeedsReview
        );
    }

    #[test]
    fn stores_lists_and_replaces_structured_finding_evidence() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-evidence";
        store
            .insert_scan_run(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "exploit-chain",
            "exploit-chain/path-traversal-to-parser-abuse",
            "app.py",
            62,
            None,
            Severity::Critical,
            "Path traversal reaches image parser plugin loading",
        )
        .with_evidence(vec![
            FindingEvidence {
                kind: "attacker_input".to_string(),
                file_path: "app.py".to_string(),
                line: 48,
                snippet: "filename = file.filename".to_string(),
                rationale: "The upload filename comes directly from the request".to_string(),
                confidence: 90,
                ..Default::default()
            },
            FindingEvidence {
                kind: "filesystem_sink".to_string(),
                file_path: "app.py".to_string(),
                line: 63,
                snippet: "file.save(filepath)".to_string(),
                rationale: "The attacker-controlled filename reaches a write sink".to_string(),
                confidence: 94,
                ..Default::default()
            },
        ]);

        store.insert_finding(run_id, &finding).unwrap();
        let listed = store.list_findings_for_scan_id(run_id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].evidence.len(), 2);
        assert_eq!(listed[0].evidence[0].kind, "attacker_input");
        assert_eq!(listed[0].evidence[1].line, 63);

        let replacement = finding.clone().with_evidence(vec![FindingEvidence {
            kind: "parser_boundary".to_string(),
            file_path: "helpers.py".to_string(),
            line: 15,
            snippet: "Image.open(input_path)".to_string(),
            rationale: "Pillow plugin initialization is the parser boundary".to_string(),
            confidence: 88,
            ..Default::default()
        }]);
        store.insert_finding(run_id, &replacement).unwrap();

        let resolved = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.evidence.len(), 1);
        assert_eq!(resolved.evidence[0].kind, "parser_boundary");
        assert_eq!(resolved.evidence[0].file_path, "helpers.py");
    }

    #[test]
    fn stores_optional_finding_lifecycle_metadata() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-finding-metadata";
        store
            .insert_scan_run(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let mut finding = Finding::new_tool(
            "semgrep",
            "rules/cwe-601",
            "src/redirect.rs",
            18,
            None,
            Severity::Medium,
            "Open redirect",
        )
        .with_remediation("allowlist redirect targets");
        finding.suppressed = true;
        finding.snoozed_until = Some("2026-06-01T00:00:00Z".to_string());
        finding.references = vec!["https://cwe.mitre.org/data/definitions/601.html".to_string()];

        store.insert_finding(run_id, &finding).unwrap();
        let stored = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();

        assert!(stored.suppressed);
        assert_eq!(
            stored.snoozed_until.as_deref(),
            Some("2026-06-01T00:00:00Z")
        );
        assert_eq!(
            stored.remediation.as_deref(),
            Some("allowlist redirect targets")
        );
        assert_eq!(stored.references, finding.references);
    }

    #[test]
    fn static_proof_taxonomy_parses_and_serializes_expected_states() {
        let states = [
            ("signal_only", StaticProofState::SignalOnly),
            ("code_cited", StaticProofState::CodeCited),
            ("source_sink_linked", StaticProofState::SourceSinkLinked),
            ("sanitizer_checked", StaticProofState::SanitizerChecked),
            (
                "statically_confirmed",
                StaticProofState::StaticallyConfirmed,
            ),
            ("statically_rejected", StaticProofState::StaticallyRejected),
            (
                "needs_runtime_evidence",
                StaticProofState::NeedsRuntimeEvidence,
            ),
        ];

        for (raw, state) in states {
            assert_eq!(StaticProofState::try_from(raw).unwrap(), state);
            assert_eq!(state.as_str(), raw);
        }

        assert!(StaticProofState::StaticallyConfirmed.is_static_terminal_state());
        assert!(!StaticProofState::SourceSinkLinked.is_static_terminal_state());
    }

    #[test]
    fn static_proof_taxonomy_rejects_execution_confirmed_states() {
        for raw in [
            "execution_confirmed",
            "runtime_confirmed",
            "dynamic_confirmed",
            "exploit_confirmed",
            "poc_confirmed",
            "runtime_reviewed",
            "execution_attempted",
            "execution_rejected",
        ] {
            let error = StaticProofState::try_from(raw).unwrap_err().to_string();
            assert!(error.contains("not valid static proof"));
        }
    }

    #[test]
    fn static_proof_state_round_trips_through_findings_store() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-static", Path::new("/tmp/repo"), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.static",
            "src/app.ts",
            9,
            Some(10),
            Severity::High,
            "scanner signal",
        )
        .with_static_proof_state(StaticProofState::SignalOnly);

        store.insert_finding("run-static", &finding).unwrap();
        let stored = store.list_findings_for_scan_id("run-static").unwrap();

        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        let serialized = serde_json::to_value(&stored[0]).unwrap();
        assert_eq!(serialized["staticProofState"], json!("signal_only"));
    }

    #[test]
    fn resolves_finding_by_fingerprint_prefix() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-1";
        store
            .insert_scan_run(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        store.insert_finding(run_id, &finding).unwrap();

        let prefix = &finding.fingerprint[..8];
        let resolved = store.get_finding_by_reference(prefix).unwrap().unwrap();

        assert_eq!(resolved.fingerprint, finding.fingerprint);
    }

    #[test]
    fn reference_resolution_attaches_latest_verification_for_prefix() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-verify-prefix", Path::new("/tmp/repo"), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.verify",
            "src/app.ts",
            44,
            Some(45),
            Severity::High,
            "User input reaches sink",
        );
        let finding_id = store.insert_finding("run-verify-prefix", &finding).unwrap();
        store
            .save_verification(
                finding_id,
                &PersistedVerification {
                    proof_level: 4,
                    proof_verdict: PersistedProofVerdict::Exploited,
                    backend: PersistedSandboxBackend::Plain,
                    language: Some("javascript".to_string()),
                    harness_path: None,
                    crash_evidence: Some("payload echoed".to_string()),
                    duration_ms: 88,
                    cost_usd: 0.0,
                    notes: vec!["confirmed by fixture".to_string()],
                    created_at: String::new(),
                },
            )
            .unwrap();

        let prefix = &finding.fingerprint[..8];
        let resolved = store.get_finding_by_reference(prefix).unwrap().unwrap();

        assert_eq!(
            resolved.verification.as_ref().map(|v| v.proof_verdict),
            Some(PersistedProofVerdict::Exploited)
        );
    }

    #[test]
    fn finding_detail_report_surfaces_proof_state_verification_and_next_action() {
        let mut finding = Finding::new_semgrep(
            "demo.xss",
            "src/app.ts",
            7,
            Some(8),
            Severity::High,
            "Request query data is rendered into HTML without escaping",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.91,
            rationale: "source and sink are linked".to_string(),
            cost_usd: 0.02,
        });
        finding.verification = Some(PersistedVerification {
            proof_level: 4,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Bwrap,
            language: Some("javascript".to_string()),
            harness_path: Some("/tmp/harness.js".to_string()),
            crash_evidence: Some("<script>alert(1)</script>".to_string()),
            duration_ms: 321,
            cost_usd: 0.0,
            notes: vec!["browser fixture confirmed execution".to_string()],
            created_at: "now".to_string(),
        });

        let report = FindingDetailReport::new(Some("F-0001".to_string()), finding, Vec::new());
        let output = report.output();

        assert!(output.contains("Finding F-0001"));
        assert!(output.contains("Proof state: source_sink_linked"));
        assert!(output.contains("Runtime validation: execution_confirmed"));
        assert!(output.contains("Proof ladder: verified"));
        assert!(output.contains("Next action: patch"));
        assert_eq!(report.next_action, FindingNextAction::Patch);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["proofState"], "source_sink_linked - Source and sink are linked in static evidence; runtime proof not recorded");
        assert_eq!(json["nextAction"], "patch");
    }

    #[test]
    fn stable_aliases_sort_by_severity_then_fingerprint() {
        let mut high_late = Finding::new_semgrep(
            "demo.high",
            "src/b.ts",
            2,
            Some(2),
            Severity::High,
            "high z",
        );
        high_late.fingerprint = "zzzz1111".to_string();
        let mut high_early = Finding::new_semgrep(
            "demo.high",
            "src/a.ts",
            1,
            Some(1),
            Severity::High,
            "high a",
        );
        high_early.fingerprint = "aaaa1111".to_string();
        let mut critical = Finding::new_semgrep(
            "demo.critical",
            "src/c.ts",
            3,
            Some(3),
            Severity::Critical,
            "critical",
        );
        critical.fingerprint = "mmmm1111".to_string();

        let input = vec![high_late.clone(), high_early.clone(), critical.clone()];
        let aliases = sorted_finding_aliases(&input);
        let alias_indices = sorted_finding_alias_indices(&input);

        assert_eq!(aliases[0].0, "F-0001");
        assert_eq!(aliases[0].1.fingerprint, critical.fingerprint);
        assert_eq!(alias_indices[0], ("F-0001".to_string(), 2));
        assert_eq!(aliases[1].0, "F-0002");
        assert_eq!(aliases[1].1.fingerprint, high_early.fingerprint);
        assert_eq!(alias_indices[1], ("F-0002".to_string(), 1));
        assert_eq!(
            stable_finding_alias(&input, &high_late.fingerprint).as_deref(),
            Some("F-0003")
        );
        assert_eq!(
            resolve_finding_alias(&input, "f-0002")
                .as_ref()
                .map(|finding| finding.fingerprint.as_str()),
            Some(high_early.fingerprint.as_str())
        );
        assert!(parse_finding_alias("F-0000").is_none());
    }

    #[test]
    fn finding_report_outputs_alias_with_secondary_fingerprint() {
        let mut high_late =
            Finding::new_semgrep("demo.b", "src/b.ts", 2, Some(2), Severity::High, "b");
        high_late.fingerprint = "zzzz1111".to_string();
        let mut high_early =
            Finding::new_semgrep("demo.a", "src/a.ts", 1, Some(1), Severity::High, "a");
        high_early.fingerprint = "aaaa1111".to_string();
        let report = FindingListReport {
            count: 2,
            findings: vec![high_late, high_early],
        };

        let output = report.output();

        assert!(output.contains("Alias"));
        assert!(output.contains("Fingerprint"));
        let first = output.find("F-0001").unwrap();
        let second = output.find("F-0002").unwrap();
        assert!(first < second);
        assert!(output[first..].contains("aaaa1111"));
        assert!(output[second..].contains("zzzz1111"));
    }

    #[test]
    fn finding_report_tool_json_omits_raw_http_blobs() {
        let mut finding = Finding::new_semgrep(
            "demo.http",
            "captures/login.har",
            1,
            Some(1),
            Severity::High,
            "http",
        );
        finding.evidence.push(FindingEvidence {
            kind: "http-request".to_string(),
            file_path: "captures/login.har".to_string(),
            line: 1,
            snippet: "POST /login".to_string(),
            rationale: "captured by HAR import".to_string(),
            confidence: 90,
            request_blob: Some("RAW REQUEST BODY".to_string()),
            response_blob: Some("RAW RESPONSE BODY".to_string()),
        });
        let report = FindingListReport {
            count: 1,
            findings: vec![finding],
        };

        let output = report.to_tool_json().to_string();

        assert!(output.contains("requestBlobPresent"));
        assert!(output.contains("responseBlobPresent"));
        assert!(!output.contains("RAW REQUEST BODY"));
        assert!(!output.contains("RAW RESPONSE BODY"));
    }

    #[test]
    fn filters_findings_by_severity_name_file_and_limit() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-1", Path::new("/tmp/repo"), "completed")
            .unwrap();

        for (rule, file, severity, message) in [
            (
                "demo.ssrf",
                "src/routes/fetch.ts",
                Severity::Critical,
                "SSRF in /fetch",
            ),
            (
                "demo.token",
                "tests/fixtures/token.ts",
                Severity::Low,
                "Hardcoded token in tests",
            ),
            (
                "demo.sql",
                "src/db/query.ts",
                Severity::High,
                "SQL injection in search",
            ),
        ] {
            let finding = Finding::new_semgrep(rule, file, 8, Some(8), severity, message);
            store.insert_finding("run-1", &finding).unwrap();
        }

        let report = store
            .list_findings_filtered(
                &FindingListFilter::from_parts(
                    vec!["critical,high".to_string()],
                    vec![],
                    Some("in".to_string()),
                    Some("src/".to_string()),
                    1,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(report.count, 2);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "demo.ssrf");
        assert!(report.output().contains("2 matching (showing 1)"));
    }

    #[test]
    fn filters_findings_by_legacy_verdict_values() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-1", Path::new("/tmp/repo"), "completed")
            .unwrap();

        let true_positive = Finding::new_semgrep(
            "demo.tp",
            "src/a.ts",
            1,
            Some(1),
            Severity::High,
            "confirmed issue",
        );
        let false_positive = Finding::new_semgrep(
            "demo.fp",
            "src/b.ts",
            1,
            Some(1),
            Severity::High,
            "dismissed issue",
        );
        let untriaged = Finding::new_semgrep(
            "demo.review",
            "src/c.ts",
            1,
            Some(1),
            Severity::High,
            "review issue",
        );
        let true_positive_id = store.insert_finding("run-1", &true_positive).unwrap();
        let false_positive_id = store.insert_finding("run-1", &false_positive).unwrap();
        store.insert_finding("run-1", &untriaged).unwrap();
        store
            .save_triage(
                true_positive_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .save_triage(
                false_positive_id,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.8,
                    rationale: "safe".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let tp = store
            .list_findings_filtered(
                &FindingListFilter::from_parts(vec![], vec!["tp".to_string()], None, None, 10)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(tp.count, 1);
        assert_eq!(tp.findings[0].rule_id, "demo.tp");

        let review = store
            .list_findings_filtered(
                &FindingListFilter::from_tool_input(&json!({"verdict": ["needs_review"]})).unwrap(),
            )
            .unwrap();
        assert_eq!(review.count, 1);
        assert_eq!(review.findings[0].rule_id, "demo.review");
    }

    #[test]
    fn filter_expression_matches_state_rank_text_run_and_source() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-2026-alpha", Path::new("/tmp/repo"), "completed")
            .unwrap();
        store
            .insert_scan_run("run-other", Path::new("/tmp/repo"), "completed")
            .unwrap();

        let wanted = Finding::new_semgrep(
            "demo.sql",
            "src/db/query.ts",
            12,
            Some(12),
            Severity::High,
            "SQL injection in search",
        );
        let other_run = Finding::new_semgrep(
            "demo.sql.other",
            "src/db/other.ts",
            12,
            Some(12),
            Severity::High,
            "SQL injection in other run",
        );
        let wrong_rank = Finding::new_semgrep(
            "demo.sql.low",
            "src/db/low.ts",
            12,
            Some(12),
            Severity::Low,
            "SQL injection low rank",
        );
        let wrong_text = Finding::new_semgrep(
            "demo.token",
            "src/db/token.ts",
            12,
            Some(12),
            Severity::High,
            "Hardcoded token",
        );
        store.insert_finding("run-2026-alpha", &wanted).unwrap();
        store.insert_finding("run-other", &other_run).unwrap();
        store.insert_finding("run-2026-alpha", &wrong_rank).unwrap();
        store.insert_finding("run-2026-alpha", &wrong_text).unwrap();

        let report = store
            .list_findings_filtered(
                &FindingListFilter::from_tool_input(&json!({
                    "filter": "state:new rank:high run:run-2026 source:sarif sql"
                }))
                .unwrap(),
            )
            .unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.findings[0].rule_id, "demo.sql");
    }

    #[test]
    fn filter_expression_rejects_future_provenance_keys_instead_of_ignoring_them() {
        let error = FindingListFilter::from_tool_input(&json!({
            "filter": "rev:abcdef1"
        }))
        .unwrap_err()
        .to_string();

        assert!(error.contains("not supported until provenance indexing is available"));
    }

    #[test]
    fn save_and_get_verification_round_trip() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-v1", Path::new("/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "verify-test",
            "rule.test",
            "src/x.rs",
            10,
            None,
            Severity::High,
            "test",
        );
        let finding_id = store.insert_finding("run-v1", &finding).unwrap();

        let record = PersistedVerification {
            proof_level: 4,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Bwrap,
            language: Some("rust".to_string()),
            harness_path: Some("/tmp/h".to_string()),
            crash_evidence: Some("SIGSEGV".to_string()),
            duration_ms: 1234,
            cost_usd: 0.05,
            notes: vec!["one".to_string(), "two".to_string()],
            created_at: String::new(),
        };
        let row_id = store.save_verification(finding_id, &record).unwrap();
        assert!(row_id > 0);

        let fetched = store
            .get_latest_verification(finding_id)
            .unwrap()
            .expect("should round-trip");
        assert_eq!(fetched.proof_level, 4);
        assert_eq!(fetched.proof_verdict, PersistedProofVerdict::Exploited);
        assert_eq!(fetched.backend, PersistedSandboxBackend::Bwrap);
        assert_eq!(fetched.language.as_deref(), Some("rust"));
        assert_eq!(fetched.harness_path.as_deref(), Some("/tmp/h"));
        assert_eq!(fetched.crash_evidence.as_deref(), Some("SIGSEGV"));
        assert_eq!(fetched.duration_ms, 1234);
        assert!((fetched.cost_usd - 0.05).abs() < 1e-9);
        assert_eq!(fetched.notes, vec!["one".to_string(), "two".to_string()]);
        assert!(!fetched.created_at.is_empty());
    }

    #[test]
    fn get_latest_verification_returns_most_recent_row() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-v2", Path::new("/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "verify-test",
            "rule.test",
            "src/x.rs",
            1,
            None,
            Severity::High,
            "test",
        );
        let finding_id = store.insert_finding("run-v2", &finding).unwrap();

        let earlier = PersistedVerification {
            proof_level: 2,
            proof_verdict: PersistedProofVerdict::NotReproduced,
            backend: PersistedSandboxBackend::Plain,
            language: Some("rust".to_string()),
            harness_path: None,
            crash_evidence: None,
            duration_ms: 100,
            cost_usd: 0.0,
            notes: vec![],
            created_at: String::new(),
        };
        let later = PersistedVerification {
            proof_level: 4,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Bwrap,
            language: Some("rust".to_string()),
            harness_path: None,
            crash_evidence: Some("SIGSEGV".to_string()),
            duration_ms: 200,
            cost_usd: 0.0,
            notes: vec![],
            created_at: String::new(),
        };
        store.save_verification(finding_id, &earlier).unwrap();
        store.save_verification(finding_id, &later).unwrap();

        let fetched = store.get_latest_verification(finding_id).unwrap().unwrap();
        assert_eq!(fetched.proof_level, 4);
        assert_eq!(fetched.proof_verdict, PersistedProofVerdict::Exploited);
    }

    #[test]
    fn save_triage_against_missing_finding_id_returns_clean_fk_error() {
        // M1 §1.5: this protects against the "triage:assertions FK fault"
        // family — historically the bus worker could call `save_triage`
        // with a finding_id that did not exist yet (race with the findings
        // insert). SQLite must enforce the FK so callers observe a clean
        // Err and never silently corrupt the triage table.
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-fk", Path::new("/repo"), "running")
            .unwrap();
        let stale_id: i64 = 9_999_999;
        let outcome = TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.5,
            rationale: "synthetic".to_string(),
            cost_usd: 0.0,
        };
        let result = store.save_triage(stale_id, &outcome);
        let err = match result {
            Ok(_) => panic!("FK constraint must reject orphan triage rows"),
            Err(err) => err.to_string(),
        };
        let lowered = err.to_lowercase();
        assert!(
            lowered.contains("foreign key") || lowered.contains("constraint"),
            "expected FK constraint error, got {err}"
        );
    }

    #[test]
    fn save_triage_after_finding_insert_succeeds_with_dedup_safe_id() {
        // Companion to the FK error test — confirms the happy path: when
        // a triage write follows its findings insert in the same scan,
        // the FK is satisfied. This is the contract callers must keep.
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-fk-ok", Path::new("/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "triage-test",
            "rule.test",
            "src/x.rs",
            1,
            None,
            Severity::Medium,
            "x",
        );
        let id = store.insert_finding("run-fk-ok", &finding).unwrap();
        store
            .save_triage(
                id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.7,
                    rationale: "ok".to_string(),
                    cost_usd: 0.0,
                },
            )
            .expect("triage insert must succeed when finding exists");
    }

    #[test]
    fn get_latest_verification_returns_none_when_no_rows() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-v3", Path::new("/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "verify-test",
            "rule.test",
            "src/x.rs",
            1,
            None,
            Severity::High,
            "test",
        );
        let finding_id = store.insert_finding("run-v3", &finding).unwrap();
        assert!(store.get_latest_verification(finding_id).unwrap().is_none());
    }

    #[test]
    fn legacy_fingerprints_migrate_to_stable_v2_identity() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-legacy", Path::new("/tmp"), "running")
            .unwrap();
        // Two legacy rows for the same rule/file/line whose 16-char
        // DefaultHasher fingerprints differed only because the message was
        // hashed: under v2 identity they are the same finding.
        for (legacy_fp, message) in [
            ("00000000aaaaaaaa", "SQLi reachable from request param"),
            ("00000000bbbbbbbb", "SQLi reachable (review pass wording)"),
        ] {
            store
                .conn
                .execute(
                    "insert into findings(scan_id, fingerprint, rule_id, title, severity,
                        file_path, start_line, message, tool, created_at)
                     values('run-legacy', ?1, 'demo.sqli', 'SQLi', 'high',
                        'src/db.rs', 42, ?2, 'semgrep', 'now')",
                    rusqlite::params![legacy_fp, message],
                )
                .unwrap();
        }

        // Re-running init applies the one-time migration.
        store.init().unwrap();

        let findings = store.list_findings_for_scan_id("run-legacy").unwrap();
        assert_eq!(findings.len(), 1, "colliding legacy rows must collapse");
        let migrated = &findings[0].fingerprint;
        assert_eq!(migrated.len(), 32, "v2 fingerprints are 32 hex chars");
        assert_eq!(
            *migrated,
            fingerprint_parts("demo.sqli", "src/db.rs", 42),
            "migrated identity must match what new_tool computes today"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_message_independent() {
        let one = Finding::new_tool(
            "semgrep",
            "demo.sqli",
            "src/db.rs",
            42,
            None,
            Severity::High,
            "first wording",
        );
        let two = Finding::new_tool(
            "semgrep",
            "demo.sqli",
            "src/db.rs",
            42,
            None,
            Severity::High,
            "completely different wording",
        );
        assert_eq!(one.fingerprint, two.fingerprint);
        assert_eq!(
            one.fingerprint,
            fingerprint_parts("demo.sqli", "src/db.rs", 42)
        );
        let other_line = Finding::new_tool(
            "semgrep",
            "demo.sqli",
            "src/db.rs",
            43,
            None,
            Severity::High,
            "first wording",
        );
        assert_ne!(one.fingerprint, other_line.fingerprint);
    }
}
