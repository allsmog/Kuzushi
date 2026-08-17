#[cfg(test)]
mod tests {
    use super::super::domain::{
        compute_finding_identity_id, finding_identity_key_for_finding, FindingEvidence,
    };
    use super::super::persistence::merge_tool_list;
    use super::super::*;
    use crate::run_artifacts::{RunSummary, RunTargetGitMetadata, ScanEngineStageOutcome};
    use serde_json::json;
    use std::collections::BTreeMap;
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
    fn dedup_key_falls_back_to_closed_class_when_no_cwe() {
        let classed = Finding::new_tool(
            "semgrep",
            "generic.download",
            "src/files.py",
            20,
            None,
            Severity::High,
            "Path traversal in download handler",
        );
        assert_eq!(
            classed.dedup_key.as_deref(),
            Some("src/files.py:2:class:path-traversal")
        );

        let unclassifiable = Finding::new_tool(
            "semgrep",
            "generic.rule",
            "src/files.py",
            20,
            None,
            Severity::High,
            "Something looks wrong around this handler",
        );
        assert_eq!(
            unclassifiable.dedup_key, None,
            "class Other never mints a wildcard key"
        );

        let with_cwe = Finding::new_tool(
            "semgrep",
            "generic.rule",
            "src/files.py",
            20,
            None,
            Severity::High,
            "Path traversal in download handler, CWE-22",
        );
        assert_eq!(
            with_cwe.dedup_key.as_deref(),
            Some("src/files.py:2:22"),
            "an extractable CWE stays primary over the class fallback"
        );
    }

    #[test]
    fn source_signature_keeps_basename_exact_line_and_cwe_or_title() {
        assert_eq!(
            compute_source_signature("src/foo.c", 42, Some("CWE-787")),
            "foo.c:42:787"
        );
        assert_eq!(
            compute_source_signature("./src/app.ts", 9, Some("SQL injection")),
            "app.ts:9:sql-injection"
        );
    }

    #[test]
    fn root_cause_key_groups_call_sites_the_dedup_key_separates() {
        let near = compute_dedup_key("src/db.rs", 10, Some("CWE-89"));
        let far = compute_dedup_key("src/db.rs", 200, Some("CWE-89"));
        assert_ne!(near, far, "distant lines get separate dedup keys");
        let root_a = compute_root_cause_key("src/db.rs", Some("CWE-89"));
        let root_b = compute_root_cause_key("./src/db.rs", Some("cwe-89"));
        assert_eq!(root_a, root_b, "path prefix and CWE formatting normalize");
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
        assert_eq!(VulnSource::parse("ainalysis"), Some(VulnSource::Ainalysis));
        assert_eq!(
            VulnSource::parse("ainalysis-multi"),
            Some(VulnSource::AinalysisMulti)
        );
        assert_eq!(serde_json::to_string(&VulnSource::Ainalysis).unwrap(), "\"analysis\"");
        assert_eq!(
            serde_json::from_str::<VulnSource>("\"ainalysis\"").unwrap(),
            VulnSource::Ainalysis
        );
    }

    #[test]
    fn vuln_source_from_tool_classifies_known_tools() {
        assert_eq!(VulnSource::from_tool("semgrep"), VulnSource::Sarif);
        assert_eq!(VulnSource::from_tool("codeql"), VulnSource::Sarif);
        assert_eq!(VulnSource::from_tool("systems-hunt"), VulnSource::Ainalysis);
        assert_eq!(VulnSource::from_tool("full-mode-multi"), VulnSource::AinalysisMulti);
        assert_eq!(VulnSource::from_tool("variant-ndiff"), VulnSource::DiffAnalyzer);
    }

    #[test]
    fn new_tool_dedup_key_prefers_cwe_then_closed_class() {
        let with_cwe = Finding::new_tool(
            "semgrep",
            "rule",
            "src/foo.c",
            10,
            Some(15),
            Severity::High,
            "OOB write CWE-787 in handler",
        );
        assert_eq!(with_cwe.dedup_key.as_deref(), Some("src/foo.c:1:787"));
        let classed = Finding::new_tool(
            "semgrep",
            "rule",
            "src/foo.c",
            10,
            Some(15),
            Severity::High,
            "Hardcoded credential in source",
        );
        assert_eq!(classed.dedup_key.as_deref(), Some("src/foo.c:1:class:secret-exposure"));
    }

    #[test]
    fn merge_tool_list_is_set_union() {
        assert_eq!(merge_tool_list("semgrep", "codeql"), "codeql,semgrep");
        assert_eq!(merge_tool_list("semgrep,codeql", "semgrep"), "codeql,semgrep");
        assert_eq!(merge_tool_list("", "semgrep"), "semgrep");
    }

    #[test]
    fn cross_channel_dedup_merges_higher_severity_finding() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-dedup";
        store.record_run_started(run, std::path::Path::new("/tmp"), "running").unwrap();
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
        let chunked = Finding::new_tool(
            "full-mode-multi",
            "full-mode-multi/cwe-78",
            "src/foo.c",
            42,
            Some(42),
            Severity::High,
            "exec with attacker-controlled argv, CWE-78",
        );
        assert_eq!(semgrep.dedup_key, chunked.dedup_key);
        assert_ne!(semgrep.fingerprint, chunked.fingerprint);
        let id2 = store.insert_finding(run, &chunked).unwrap();
        assert_eq!(id1, id2);
        let listed = store.list_findings(10).unwrap();
        assert_eq!(listed.len(), 1);
        let row = &listed[0];
        assert_eq!(row.severity, Severity::High);
        assert!(row.tool.contains("semgrep"));
        assert!(row.tool.contains("full-mode-multi"));
        assert_eq!(row.dedup_key, semgrep.dedup_key);
    }

    #[test]
    fn fingerprint_delta_splits_new_from_reobserved_distinct_fingerprints() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-delta";
        store.record_run_started(run, std::path::Path::new("/tmp"), "running").unwrap();
        let existing = Finding::new_tool(
            "full-mode",
            "rule-existing",
            "src/foo.c",
            10,
            None,
            Severity::High,
            "already in the store",
        );
        store.insert_finding(run, &existing).unwrap();
        let fresh = Finding::new_tool(
            "full-mode",
            "rule-fresh",
            "src/bar.c",
            20,
            None,
            Severity::Critical,
            "new this run",
        );
        let (added, updated) = store
            .fingerprint_delta(&[existing.clone(), fresh.clone(), fresh.clone()])
            .unwrap();
        assert_eq!((added, updated), (1, 1));
    }

    #[test]
    fn insert_findings_batches_projection_and_v3_observations() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-batch";
        store.record_run_started(run, Path::new("/tmp"), "running").unwrap();
        let findings = vec![
            Finding::new_tool("semgrep", "rule-a", "src/a.c", 10, Some(10), Severity::Medium, "first issue"),
            Finding::new_tool("codeql", "rule-b", "src/b.c", 20, Some(21), Severity::High, "second issue"),
        ];
        let ids = store.insert_findings(run, &findings).unwrap();
        assert_eq!(ids.len(), 2);
        let listed = store.list_findings(10).unwrap();
        assert_eq!(listed.len(), 2);
        let observation_count: i64 = store.conn.query_row("select count(*) from finding_observations", [], |row| row.get(0)).unwrap();
        assert_eq!(observation_count, 2);
    }

    // The remainder of this test module intentionally stays byte-for-byte equivalent
    // to main except for the structured evidence fixture below. This replacement is
    // kept complete because GitHub's Contents API has no partial-file update primitive.

    #[test]
    fn stores_lists_and_replaces_structured_finding_evidence() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("app.py"),
            format!(
                "{}filename = file.filename\n{}file.save(filepath)\n",
                "# fixture\n".repeat(47),
                "# fixture\n".repeat(14),
            ),
        )
        .unwrap();
        std::fs::write(
            temp.path().join("helpers.py"),
            format!("{}Image.open(input_path)\n", "# fixture\n".repeat(14)),
        )
        .unwrap();

        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-evidence";
        store
            .record_run_started(run_id, temp.path(), "running")
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
}
