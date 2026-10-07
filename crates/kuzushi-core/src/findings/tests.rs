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
        assert_eq!(VulnSource::parse("ainalysis"), Some(VulnSource::Ainalysis));
        assert_eq!(
            VulnSource::parse("ainalysis-multi"),
            Some(VulnSource::AinalysisMulti)
        );
        assert_eq!(
            serde_json::to_string(&VulnSource::Ainalysis).unwrap(),
            "\"analysis\""
        );
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
        assert_eq!(
            classed.dedup_key.as_deref(),
            Some("src/foo.c:1:class:secret-exposure"),
            "no CWE, but the closed class enum still keys the finding"
        );
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
            .record_run_started(run, std::path::Path::new("/tmp"), "running")
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
            42,
            Some(42),
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
    fn a_committed_delta_splits_new_from_reobserved_findings() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-delta";
        store
            .record_run_started(run, std::path::Path::new("/tmp"), "running")
            .unwrap();
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

        // The re-observed finding, one new finding, and a byte-duplicate of
        // the new finding (same fingerprint) — duplicates count once.
        let delta = store
            .insert_findings_measuring_delta(run, &[existing.clone(), fresh.clone(), fresh.clone()])
            .unwrap();

        assert_eq!((delta.added, delta.updated), (1, 1));
        assert_eq!(delta.row_ids.len(), 3, "one row id per observation");
        assert_eq!(delta.row_ids[1], delta.row_ids[2], "duplicates share a row");
    }

    /// A batch of 27 observations that dedup folds into 25 findings used to
    /// commit a delta of 27, which the RESULT READY banner printed as
    /// `findings +27` over a Review ledger holding 25. The delta has to count
    /// the findings the store gained, not the observations the run emitted.
    /// Issue #172, 2026-10-05 audit.
    #[test]
    fn a_committed_delta_counts_findings_the_store_gained_not_observations() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-fold";
        store
            .record_run_started(run, std::path::Path::new("/tmp"), "running")
            .unwrap();

        let (semgrep, full_mode) = collision_pair();
        let separate = Finding::new_tool(
            "semgrep",
            "rule-elsewhere",
            "src/bar.c",
            7,
            None,
            Severity::Low,
            "unrelated finding",
        );

        let delta = store
            .insert_findings_measuring_delta(
                run,
                &[semgrep.clone(), full_mode.clone(), separate.clone()],
            )
            .unwrap();

        // Three observations carrying three distinct fingerprints, two
        // findings: counting the fingerprints is the arithmetic that over-
        // reported the delta.
        let batch = [semgrep.clone(), full_mode.clone(), separate.clone()];
        assert_eq!(
            batch
                .iter()
                .map(|finding| finding.fingerprint.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        assert_eq!(store.list_findings(10).unwrap().len(), 2);
        assert_eq!((delta.added, delta.updated), (2, 0));
        assert_eq!(delta.row_ids[0], delta.row_ids[1], "the merged pair");
        assert_ne!(delta.row_ids[0], delta.row_ids[2]);
    }

    /// A later batch whose only finding merges into a row this run already
    /// holds added nothing: the ledger still has one finding. The incoming
    /// fingerprint is new, so asking the fingerprints alone would call it an
    /// addition — the row the insertion returned is what settles it.
    #[test]
    fn a_second_batch_merging_into_this_runs_row_adds_nothing() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-second-batch";
        store
            .record_run_started(run, std::path::Path::new("/tmp"), "running")
            .unwrap();
        let (semgrep, full_mode) = collision_pair();

        let first = store
            .insert_findings_measuring_delta(run, &[semgrep])
            .unwrap();
        let second = store
            .insert_findings_measuring_delta(run, &[full_mode])
            .unwrap();

        assert_eq!((first.added, first.updated), (1, 0));
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
        assert_eq!(
            (second.added, second.updated),
            (0, 1),
            "the second batch merged into the first batch's row"
        );
        assert_eq!(second.row_ids, first.row_ids);
    }

    /// One issue at one location reported by two channels: the shared
    /// file/line/CWE gives them one dedup key and one source signature, so the
    /// insertion merges them.
    fn collision_pair() -> (Finding, Finding) {
        let semgrep = Finding::new_tool(
            "semgrep",
            "java.injection.tainted-system-call",
            "src/foo.c",
            42,
            Some(42),
            Severity::Medium,
            "user-controlled exec, CWE-78",
        );
        let full_mode = Finding::new_tool(
            "full-mode-multi",
            "full-mode-multi/cwe-78",
            "src/foo.c",
            42,
            Some(42),
            Severity::High,
            "exec with attacker-controlled argv, CWE-78",
        );
        assert_eq!(semgrep.dedup_key, full_mode.dedup_key);
        assert_ne!(semgrep.fingerprint, full_mode.fingerprint);
        (semgrep, full_mode)
    }

    /// A merge whose surviving row was already in the store is an update, not
    /// an addition, even though the incoming fingerprint itself is new.
    #[test]
    fn a_merge_into_a_stored_finding_counts_as_an_update() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-merge-update";
        store
            .record_run_started(run, std::path::Path::new("/tmp"), "running")
            .unwrap();
        let (stored, collider) = collision_pair();
        store.insert_finding(run, &stored).unwrap();

        let delta = store
            .insert_findings_measuring_delta(run, &[stored.clone(), collider.clone()])
            .unwrap();

        assert_eq!(store.list_findings(10).unwrap().len(), 1);
        assert_eq!((delta.added, delta.updated), (0, 1));
    }

    #[test]
    fn insert_findings_batches_projection_and_v3_observations() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-batch";
        store
            .record_run_started(run, Path::new("/tmp"), "running")
            .unwrap();

        let findings = vec![
            Finding::new_tool(
                "semgrep",
                "rule-a",
                "src/a.c",
                10,
                Some(10),
                Severity::Medium,
                "first issue",
            ),
            Finding::new_tool(
                "codeql",
                "rule-b",
                "src/b.c",
                20,
                Some(21),
                Severity::High,
                "second issue",
            ),
        ];

        let ids = store.insert_findings(run, &findings).unwrap();

        assert_eq!(ids.len(), 2);
        let listed = store.list_findings(10).unwrap();
        assert_eq!(listed.len(), 2);
        let observation_count: i64 = store
            .conn
            .query_row("select count(*) from finding_observations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(observation_count, 2);
    }

    #[test]
    fn v3_observation_payload_uses_current_finding_json() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-v3-native-payload";
        store
            .record_run_started(run, Path::new("/tmp"), "running")
            .unwrap();

        let legacy_table_count: i64 = store
            .conn
            .query_row(
                "select count(*) from sqlite_master where type = 'table' and name = 'finding_projection_rows'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            legacy_table_count, 0,
            "new v3 stores must not create legacy finding rows"
        );
        let static_history_table_count: i64 = store
            .conn
            .query_row(
                "select count(*) from sqlite_master where type = 'table' and name = 'static_proof_history'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            static_history_table_count, 0,
            "static proof history is derived from observations, not a separate table"
        );

        let finding = Finding::new_tool(
            "semgrep",
            "rules/cwe-89",
            "src/app.rs",
            12,
            Some(12),
            Severity::High,
            "SQL injection reaches raw query, CWE-89",
        );
        let id = store.insert_finding(run, &finding).unwrap();

        let current_json: String = store
            .conn
            .query_row(
                "select finding_json from finding_current where id = ?1",
                rusqlite::params![id],
                |row| row.get(0),
            )
            .unwrap();
        let current: Finding = serde_json::from_str(&current_json).unwrap();
        assert_eq!(current.id, Some(id));
        assert_eq!(current.title, finding.title);
        assert_eq!(current.identity_match_tier.as_deref(), Some("stable_fp"));

        let rows = store.list_findings_for_scan_id(run).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, finding.title);
        assert_eq!(rows[0].severity, Severity::High);
        assert_eq!(rows[0].file_path, "src/app.rs");
        assert_eq!(rows[0].start_line, 12);
        assert_eq!(rows[0].message, finding.message);
        assert_eq!(rows[0].tool, "semgrep");
    }

    #[test]
    fn insert_finding_does_not_project_observation_when_projection_write_fails() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-rollback";
        store
            .record_run_started(run, Path::new("/tmp"), "running")
            .unwrap();

        // Force the primary projection statement to fail. The writer appends
        // the observation event first, then projects current finding state and
        // observation rows in one SQLite transaction; failure must leave the
        // read model behind the log, not half-updated.
        store
            .conn
            .execute_batch(
                r#"
                create trigger fail_current_finding_insert
                after insert on finding_current
                begin
                  select raise(fail, 'forced current finding failure');
                end;
                "#,
            )
            .unwrap();

        let mut finding = Finding::new_tool(
            "semgrep",
            "rule-x",
            "src/foo.c",
            10,
            Some(10),
            Severity::High,
            "boom CWE-89",
        );
        finding.evidence = vec![FindingEvidence {
            kind: "code".to_string(),
            file_path: "src/foo.c".to_string(),
            line: 10,
            snippet: "sink(x)".to_string(),
            rationale: "reaches sink".to_string(),
            confidence: 90,
            request_blob: None,
            response_blob: None,
        }];
        finding.static_proof_state = Some(StaticProofState::StaticallyConfirmed);

        let result = store.insert_finding(run, &finding);
        assert!(result.is_err(), "insert must fail when projection fails");

        // No orphan current row and no projected v3 observation.
        let current_count: i64 = store
            .conn
            .query_row("select count(*) from finding_current", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            current_count, 0,
            "current v3 finding must not survive a failed insert"
        );
        let observation_count: i64 = store
            .conn
            .query_row("select count(*) from finding_observations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            observation_count, 0,
            "v3 observation must not survive a failed insert"
        );
        let identity_count: i64 = store
            .conn
            .query_row("select count(*) from finding_identities", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            identity_count, 0,
            "identity projection must not survive a failed insert"
        );
    }

    #[test]
    fn cross_channel_dedup_preserves_existing_when_lower_severity_arrives() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-dedup-2";
        store
            .record_run_started(run, std::path::Path::new("/tmp"), "running")
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
            42,
            Some(42),
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
    fn same_bucket_dedup_does_not_merge_different_source_signatures() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-dedup-near-miss";
        store
            .record_run_started(run, std::path::Path::new("/tmp"), "running")
            .unwrap();

        let first = Finding::new_tool(
            "semgrep",
            "rule/cwe-89",
            "src/db.rs",
            40,
            Some(40),
            Severity::High,
            "first SQL sink, CWE-89",
        );
        let second = Finding::new_tool(
            "codeql",
            "query/cwe-89",
            "src/db.rs",
            43,
            Some(43),
            Severity::High,
            "second SQL sink, CWE-89",
        );
        assert_eq!(first.dedup_key, second.dedup_key);
        assert_ne!(first.source_signature, second.source_signature);

        let first_id = store.insert_finding(run, &first).unwrap();
        let second_id = store.insert_finding(run, &second).unwrap();

        assert_ne!(first_id, second_id);
        assert_eq!(store.list_findings_for_scan_id(run).unwrap().len(), 2);
    }

    #[test]
    fn cross_run_dedup_keeps_rows_visible_to_each_scan_id() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-source-1", Path::new("/tmp"), "completed")
            .unwrap();
        store
            .record_run_started("run-source-2", Path::new("/tmp"), "completed")
            .unwrap();

        let semgrep = Finding::new_tool(
            "semgrep",
            "rule/cwe-78",
            "src/foo.c",
            42,
            Some(42),
            Severity::Medium,
            "user-controlled exec, CWE-78",
        );
        let id1 = store.insert_finding("run-source-1", &semgrep).unwrap();
        let systems = Finding::new_tool(
            "systems-hunt",
            "systems/cwe-78",
            "src/foo.c",
            43,
            Some(43),
            Severity::High,
            "exec reaches shell with attacker input, CWE-78",
        );
        assert_eq!(semgrep.dedup_key, systems.dedup_key);
        assert_ne!(semgrep.source_signature, systems.source_signature);

        let id2 = store.insert_finding("run-source-2", &systems).unwrap();

        assert_ne!(id1, id2);
        let listed = store.list_findings(10).unwrap();
        assert_eq!(
            listed.len(),
            1,
            "cross-run dedup_key reuse converges the global identity view"
        );
        let rerun = store.list_findings_for_scan_id("run-source-2").unwrap();
        assert_eq!(rerun.len(), 1);
        assert_eq!(rerun[0].severity, Severity::High);
        assert_eq!(rerun[0].tool, "systems-hunt");
        assert!(rerun[0]
            .sources
            .iter()
            .any(|source| source.last_scan_id == "run-source-2"));
    }

    #[test]
    fn global_projection_collapses_identity_and_merges_cross_run_sources() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-global-a", Path::new("/tmp/repo"), "completed")
            .unwrap();
        store
            .record_run_started("run-global-b", Path::new("/tmp/repo"), "completed")
            .unwrap();

        let first = Finding::new_tool(
            "semgrep",
            "semgrep/cwe-79",
            "src/render.ts",
            20,
            Some(20),
            Severity::Medium,
            "user input reaches the HTML sink, CWE-79",
        );
        // Same 8-line dedup bucket as `first`, so the later run rediscovers the
        // finding through the shared dedup key and joins its identity with a
        // strong (cross-run) basis. Two uncorroborated file-fallback
        // observations would stay separate rows under the safe fold, however
        // close their lines are.
        let second = Finding::new_tool(
            "codeql",
            "codeql/cwe-79",
            "src/render.ts",
            22,
            Some(22),
            Severity::High,
            "user input reaches the HTML sink, CWE-79",
        );
        assert_eq!(first.dedup_key, second.dedup_key);
        let first_id = store.insert_finding("run-global-a", &first).unwrap();
        let second_id = store.insert_finding("run-global-b", &second).unwrap();

        let first_run = store.list_findings_for_scan_id("run-global-a").unwrap();
        let second_run = store.list_findings_for_scan_id("run-global-b").unwrap();
        assert_eq!(first_run.len(), 1);
        assert_eq!(second_run.len(), 1);
        assert_eq!(first_run[0].id, Some(first_id));
        assert_eq!(second_run[0].id, Some(second_id));
        assert_eq!(first_run[0].identity_id, second_run[0].identity_id);
        assert_ne!(first_run[0].fingerprint, second_run[0].fingerprint);
        assert!(!first_run[0].effective_identity_basis().is_strong());
        assert!(second_run[0].effective_identity_basis().is_strong());
        assert_eq!(first_run[0].corroboration_count, 1);
        assert_eq!(second_run[0].corroboration_count, 1);
        assert_eq!(first_run[0].sources.len(), 1);
        assert_eq!(second_run[0].sources.len(), 1);

        let global = store.list_findings(10).unwrap();
        assert_eq!(global.len(), 1);
        assert_eq!(global[0].id, Some(second_id));
        assert_eq!(global[0].severity, Severity::High);
        assert_eq!(global[0].corroboration_count, 2);
        let source_tools = global[0]
            .sources
            .iter()
            .map(|source| source.tool.as_str())
            .collect::<Vec<_>>();
        assert_eq!(source_tools, vec!["codeql", "semgrep"]);
        let semgrep_source = global[0]
            .sources
            .iter()
            .find(|source| source.tool == "semgrep")
            .unwrap();
        assert_eq!(semgrep_source.first_scan_id, "run-global-a");
        assert_eq!(semgrep_source.last_scan_id, "run-global-a");
        let codeql_source = global[0]
            .sources
            .iter()
            .find(|source| source.tool == "codeql")
            .unwrap();
        assert_eq!(codeql_source.first_scan_id, "run-global-b");
        assert_eq!(codeql_source.last_scan_id, "run-global-b");
        assert_eq!(
            stable_finding_alias(&global, &global[0].fingerprint).as_deref(),
            Some("F-0001")
        );
        let resolved = resolve_finding_alias(&global, "F-0001").unwrap();
        assert_eq!(resolved.id, global[0].id);
        assert_eq!(
            stable_finding_alias(&global, &resolved.fingerprint).as_deref(),
            Some("F-0001")
        );
        assert!(resolve_finding_alias(&global, "F-0002").is_none());
    }

    #[test]
    fn stores_and_lists_findings_with_triage() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-1";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
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
            .record_auto_triage(
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
    fn cross_run_dedup_key_reuses_identity_without_merging_rows() {
        let temp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(temp.path().join("findings.db")).unwrap();
        store
            .record_run_started("run-a", temp.path(), "running")
            .unwrap();
        let first = Finding::new_tool(
            "semgrep",
            "py.traversal",
            "webapp/files.py",
            20,
            None,
            Severity::High,
            "Path traversal in download",
        );
        store.insert_finding("run-a", &first).unwrap();

        store
            .record_run_started("run-b", temp.path(), "running")
            .unwrap();
        let second = Finding::new_tool(
            "agentic-sast",
            "download-escape",
            "webapp/files.py",
            22,
            None,
            Severity::High,
            "Path traversal lets clients escape the files dir",
        );
        store.insert_finding("run-b", &second).unwrap();

        let run_a = store.list_findings_for_scan_id("run-a").unwrap();
        let run_b = store.list_findings_for_scan_id("run-b").unwrap();
        assert_eq!(run_a.len(), 1);
        assert_eq!(run_b.len(), 1, "cross-run reuse never merges rows");
        assert_eq!(run_a[0].identity_id, run_b[0].identity_id);
        assert_eq!(
            run_b[0].identity_match_tier.as_deref(),
            Some("dedup_key_cross_run")
        );
    }

    #[test]
    fn identity_assignment_persists_the_distinct_safety_basis() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/db.rs"), "query(input);\n").unwrap();
        let store = FindingStore::open(temp.path().join("findings.db")).unwrap();
        let first = Finding::new_tool(
            "semgrep",
            "rules.cwe-89",
            "src/db.rs",
            1,
            Some(1),
            Severity::High,
            "SQL injection reaches query, CWE-89",
        );

        store
            .record_run_started("basis-a", temp.path(), "running")
            .unwrap();
        store.insert_finding("basis-a", &first).unwrap();
        store
            .record_run_started("basis-b", temp.path(), "running")
            .unwrap();
        store.insert_finding("basis-b", &first).unwrap();
        let mut cross_run = first.clone();
        cross_run.tool = "agentic-sast".to_string();
        cross_run.rule_id = "alternate.cwe-89".to_string();
        cross_run.fingerprint = "fp3_alternate-producer".to_string();
        store
            .record_run_started("basis-c", temp.path(), "running")
            .unwrap();
        store.insert_finding("basis-c", &cross_run).unwrap();

        let a = store.list_findings_for_scan_id("basis-a").unwrap();
        let b = store.list_findings_for_scan_id("basis-b").unwrap();
        let c = store.list_findings_for_scan_id("basis-c").unwrap();
        assert_eq!(
            a[0].identity_basis,
            Some(FindingIdentityBasis::FileFallback)
        );
        assert_eq!(
            b[0].identity_basis,
            Some(FindingIdentityBasis::ExactProducerFingerprint)
        );
        assert_eq!(
            c[0].identity_basis,
            Some(FindingIdentityBasis::CrossRunDedupKey)
        );
    }

    #[test]
    fn repeated_identical_sink_lines_do_not_fold_or_propagate_without_corroboration() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/db.rs"),
            "fn first() {\n    query(input);\n}\nfn second() {\n    query(input);\n}\n",
        )
        .unwrap();
        let store = FindingStore::open(temp.path().join("findings.db")).unwrap();
        let mut first = Finding::new_tool(
            "semgrep",
            "rules.cwe-89",
            "src/db.rs",
            2,
            Some(2),
            Severity::High,
            "SQL injection reaches the first query, CWE-89",
        );
        let mut second = Finding::new_tool(
            "semgrep",
            "rules.cwe-89",
            "src/db.rs",
            5,
            Some(5),
            Severity::High,
            "SQL injection reaches the second query, CWE-89",
        );
        first.fingerprint = "fp3_first-identical-line".to_string();
        first.dedup_key = None;
        first.source_signature = None;
        second.fingerprint = "fp3_second-identical-line".to_string();
        second.dedup_key = None;
        second.source_signature = None;

        store
            .record_run_started("identical-a", temp.path(), "running")
            .unwrap();
        let first_id = store.insert_finding("identical-a", &first).unwrap();
        store
            .record_run_started("identical-b", temp.path(), "running")
            .unwrap();
        let second_id = store.insert_finding("identical-b", &second).unwrap();
        let first = store
            .list_findings_for_scan_id("identical-a")
            .unwrap()
            .remove(0);
        let second = store
            .list_findings_for_scan_id("identical-b")
            .unwrap()
            .remove(0);

        assert_eq!(first.identity_id, second.identity_id);
        assert_eq!(
            first.identity_basis,
            Some(FindingIdentityBasis::FileFallback)
        );
        assert_eq!(
            second.identity_basis,
            Some(FindingIdentityBasis::FileFallback)
        );
        assert_ne!(first.fingerprint, second.fingerprint);
        assert_ne!(first.source_signature, second.source_signature);
        assert_ne!(
            finding_projection_key(&first, IdentityFoldPolicy::Safe),
            finding_projection_key(&second, IdentityFoldPolicy::Safe)
        );
        let updated = store
            .record_auto_triage_for_identity(
                second_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.5,
                    rationale: "inspect this sink independently".to_string(),
                    ..TriageOutcome::default()
                },
            )
            .unwrap();
        assert_eq!(updated, 1);
        assert!(store
            .v3_finding_by_projected_id(first_id)
            .unwrap()
            .unwrap()
            .triage
            .is_none());
    }

    #[test]
    fn auto_triage_propagates_strong_identity_and_records_its_source() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/db.rs"), "query(input);\n").unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "rules.cwe-89",
            "src/db.rs",
            1,
            Some(1),
            Severity::High,
            "SQL injection reaches query, CWE-89",
        );
        store
            .record_run_started("prop-a", temp.path(), "running")
            .unwrap();
        let first_id = store.insert_finding("prop-a", &finding).unwrap();
        store
            .record_run_started("prop-b", temp.path(), "running")
            .unwrap();
        let source_id = store.insert_finding("prop-b", &finding).unwrap();
        let outcome = TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.91,
            rationale: "source and sink are connected".to_string(),
            cost_usd: 0.125,
            cost_usd_exact: false,
            ..TriageOutcome::default()
        };

        assert_eq!(
            store
                .record_auto_triage_for_identity(source_id, &outcome)
                .unwrap(),
            2
        );
        let propagated = store
            .v3_finding_by_projected_id(first_id)
            .unwrap()
            .unwrap()
            .triage
            .unwrap();
        let source = store
            .v3_finding_by_projected_id(source_id)
            .unwrap()
            .unwrap()
            .triage
            .unwrap();
        assert_eq!(
            propagated.cost_usd, 0.0,
            "propagation cannot duplicate spend"
        );
        assert!(propagated.cost_usd_exact);
        assert_eq!(source.cost_usd, 0.125);
        assert!(!source.cost_usd_exact);
        let events = crate::event_log::EventLog::open(temp.path().join(".kuzushi/v3/log"))
            .unwrap()
            .read_all()
            .unwrap();
        let decisions = events
            .iter()
            .filter(|event| event.event_kind == crate::event_log::EventKind::TriageDecided)
            .collect::<Vec<_>>();
        assert_eq!(decisions.len(), 2);
        assert!(decisions
            .iter()
            .all(|event| event.payload["sourceFindingIds"] == json!([source_id])));
        let mut bases = decisions
            .iter()
            .map(|event| event.payload["propagationBasis"].as_str().unwrap())
            .collect::<Vec<_>>();
        bases.sort_unstable();
        assert_eq!(bases, vec!["exact_producer_fingerprint", "file_fallback"]);

        let projected: (String, String) = rusqlite::Connection::open(db_path)
            .unwrap()
            .query_row(
                "select propagation_basis, source_finding_ids_json from review_decisions where finding_id = ?1",
                [source_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(projected.0, "exact_producer_fingerprint");
        assert_eq!(projected.1, format!("[{source_id}]"));
    }

    #[test]
    fn file_fallback_does_not_propagate_across_distinct_source_signatures() {
        let temp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(temp.path().join("findings.db")).unwrap();
        let mut first = Finding::new_tool(
            "semgrep",
            "rules.cwe-89",
            "src/missing.rs",
            8,
            Some(8),
            Severity::High,
            "SQL injection at first sink, CWE-89",
        );
        let mut second = first.clone();
        second.start_line = 80;
        second.end_line = Some(80);
        second.fingerprint = "fp3_second-sink".to_string();
        second.dedup_key = Some(compute_dedup_key("src/missing.rs", 80, Some("CWE-89")));
        second.source_signature = Some(compute_source_signature(
            "src/missing.rs",
            80,
            Some("CWE-89"),
        ));
        first.fingerprint = "fp3_first-sink".to_string();
        store
            .record_run_started("fallback-a", temp.path(), "running")
            .unwrap();
        let first_id = store.insert_finding("fallback-a", &first).unwrap();
        store
            .record_run_started("fallback-b", temp.path(), "running")
            .unwrap();
        let second_id = store.insert_finding("fallback-b", &second).unwrap();
        let first_stored = store.list_findings_for_scan_id("fallback-a").unwrap();
        let second_stored = store.list_findings_for_scan_id("fallback-b").unwrap();
        assert_eq!(first_stored[0].identity_id, second_stored[0].identity_id);
        assert_eq!(
            first_stored[0].identity_basis,
            Some(FindingIdentityBasis::FileFallback)
        );
        assert_eq!(
            second_stored[0].identity_basis,
            Some(FindingIdentityBasis::FileFallback)
        );
        store
            .append_user_review_decision(
                first_id,
                &ReviewDecision {
                    verdict: ReviewDecisionVerdict::Confirmed,
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "operator reviewed the distinct first sink".to_string(),
                    dismiss_reason: None,
                    actor: Some("operator".to_string()),
                },
            )
            .unwrap();

        let updated = store
            .record_auto_triage_for_identity(
                second_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.5,
                    rationale: "inspect this sink".to_string(),
                    ..TriageOutcome::default()
                },
            )
            .unwrap();
        assert_eq!(updated, 1);
        assert!(store
            .v3_finding_by_projected_id(first_id)
            .unwrap()
            .unwrap()
            .triage
            .is_none());
        assert!(store
            .v3_finding_by_projected_id(second_id)
            .unwrap()
            .unwrap()
            .triage
            .is_some());
    }

    #[test]
    fn auto_triage_refuses_a_compatible_identity_with_any_human_history() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/db.rs"), "query(input);\n").unwrap();
        let store = FindingStore::open(temp.path().join("findings.db")).unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "rules.cwe-89",
            "src/db.rs",
            1,
            Some(1),
            Severity::High,
            "SQL injection reaches query, CWE-89",
        );
        store
            .record_run_started("human-a", temp.path(), "running")
            .unwrap();
        let human_id = store.insert_finding("human-a", &finding).unwrap();
        store
            .append_user_review_decision(
                human_id,
                &ReviewDecision {
                    verdict: ReviewDecisionVerdict::Confirmed,
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "operator reviewed the source".to_string(),
                    dismiss_reason: None,
                    actor: Some("operator".to_string()),
                },
            )
            .unwrap();
        store
            .record_run_started("human-b", temp.path(), "running")
            .unwrap();
        let source_id = store.insert_finding("human-b", &finding).unwrap();

        let updated = store
            .record_auto_triage_for_identity(
                source_id,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.9,
                    rationale: "automated rerun disagreed".to_string(),
                    ..TriageOutcome::default()
                },
            )
            .unwrap();
        assert_eq!(updated, 0);
        assert_eq!(store.list_review_decisions(human_id).unwrap().len(), 1);
        assert!(store.list_review_decisions(source_id).unwrap().is_empty());
        let dominant = store
            .latest_human_review_decision_for_finding_identity(source_id)
            .unwrap()
            .expect("the human identity decision remains visible");
        assert_eq!(dominant.decision.verdict, ReviewDecisionVerdict::Confirmed);
        assert!(store
            .v3_finding_by_projected_id(source_id)
            .unwrap()
            .unwrap()
            .triage
            .is_none());
    }

    #[test]
    fn suppressed_and_rekeyed_prior_rows_do_not_donate_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = FindingStore::open(temp.path().join("findings.db")).unwrap();
        store
            .record_run_started("run-a", temp.path(), "running")
            .unwrap();
        let mut suppressed = Finding::new_tool(
            "semgrep",
            "py.traversal",
            "webapp/files.py",
            20,
            None,
            Severity::High,
            "Path traversal in download",
        );
        suppressed.suppressed = true;
        store.insert_finding("run-a", &suppressed).unwrap();

        store
            .record_run_started("run-b", temp.path(), "running")
            .unwrap();
        let rediscovery = Finding::new_tool(
            "agentic-sast",
            "download-escape",
            "webapp/files.py",
            22,
            None,
            Severity::High,
            "Path traversal lets clients escape the files dir",
        );
        store.insert_finding("run-b", &rediscovery).unwrap();
        let run_b = store.list_findings_for_scan_id("run-b").unwrap();
        let run_a = store.list_findings_for_scan_id("run-a").unwrap();
        assert_ne!(
            run_a[0].identity_id, run_b[0].identity_id,
            "a suppressed prior row does not donate its identity"
        );

        // Rekey the run-b row away; a third run must mint a fresh identity
        // instead of reusing the rekeyed row's.
        let run_b_key = run_b[0]
            .identity_id
            .clone()
            .unwrap_or_else(|| run_b[0].fingerprint.clone());
        store
            .record_model_rekey(&ModelRekeyRequest {
                duplicate_stable_key: run_b_key,
                canonical_stable_key: "fp3_elsewhere".to_string(),
                duplicate_fingerprint: run_b[0].fingerprint.clone(),
                canonical_fingerprint: "fp3_elsewhere".to_string(),
                canonical_identity_id: None,
                root_cause_summary: "test rekey".to_string(),
                confidence: 0.9,
                run_id: Some("run-b".to_string()),
            })
            .unwrap();
        store
            .record_run_started("run-c", temp.path(), "running")
            .unwrap();
        let third = Finding::new_tool(
            "shinsa",
            "traversal-again",
            "webapp/files.py",
            21,
            None,
            Severity::High,
            "Path traversal in the download route",
        );
        store.insert_finding("run-c", &third).unwrap();
        let run_c = store.list_findings_for_scan_id("run-c").unwrap();
        assert_ne!(
            run_c[0].identity_id, run_b[0].identity_id,
            "a rekeyed prior row does not donate its identity"
        );
        assert_eq!(
            run_c[0].identity_match_tier.as_deref(),
            Some("stable_fp"),
            "with no reusable prior row the pure identity path applies"
        );
    }

    #[test]
    fn file_backed_insert_records_v3_observation_event_and_projection() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let log_path = temp.path().join(".kuzushi/v3/log");
        let source_path = temp.path().join("src/app.rs");
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::write(
            &source_path,
            "fn search(term: &str) {\n    let sql = format!(\"select * from users where name = {}\", term);\n    db.query(&sql);\n}\n",
        )
        .unwrap();
        let store = FindingStore::open(&db_path).unwrap();
        let run_id = "run-v3-observation";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();

        let finding = Finding::new_tool(
            "semgrep",
            "rules.cwe-89",
            "src/app.rs",
            2,
            Some(2),
            Severity::High,
            "SQL injection reaches query builder, CWE-89",
        );
        store.insert_finding(run_id, &finding).unwrap();
        let stored = store.list_findings_for_scan_id(run_id).unwrap();
        let stable_fp = stored[0]
            .identity_id
            .as_deref()
            .expect("stored finding should have a v3 identity");

        let log = crate::event_log::EventLog::open(&log_path).unwrap();
        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(
            events[0].event_kind,
            crate::event_log::EventKind::RunStarted
        );
        assert_eq!(
            events[1].event_kind,
            crate::event_log::EventKind::SnapshotIndexed
        );
        assert_eq!(
            events[2].event_kind,
            crate::event_log::EventKind::FileIndexed
        );
        assert_eq!(
            events[3].event_kind,
            crate::event_log::EventKind::FindingObserved
        );
        assert_eq!(events[3].payload["stableFp"].as_str(), Some(stable_fp));
        assert_eq!(
            events[3].payload["identityId"].as_str(),
            stored[0].identity_id.as_deref()
        );
        assert_eq!(
            events[3].payload["identityMatchTier"].as_str(),
            Some("stable_fp")
        );
        assert_eq!(
            events[3].payload["identityMatchBasis"].as_str(),
            Some("file_fallback")
        );
        assert_eq!(
            events[3].payload["displayPath"].as_str(),
            Some("src/app.rs")
        );
        assert_eq!(events[3].payload["byteStart"].as_u64(), Some(24));
        assert_eq!(events[3].payload["byteEnd"].as_u64(), Some(91));
        let blob_hash = events[3].payload["blobHash"].as_str().unwrap();
        assert!(temp
            .path()
            .join(".kuzushi/v3/objects/blake3")
            .join(&blob_hash[0..2])
            .join(&blob_hash[2..4])
            .join(blob_hash)
            .is_file());

        let conn = rusqlite::Connection::open(db_path).unwrap();
        let observation: (i64, String, i64, i64) = conn
            .query_row(
                "select count(*), blob_hash, byte_start, byte_end from finding_observations where stable_fp = ?1",
                rusqlite::params![stable_fp],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        let indexed_file: (String, i64, String) = conn
            .query_row(
                "select blob_hash, file_size, language from indexed_files where path = 'src/app.rs'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let applied_seq: String = conn
            .query_row(
                "select value from meta where key = 'applied_seq'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let current_id: i64 = conn
            .query_row("select id from finding_current", [], |row| row.get(0))
            .unwrap();
        let identity_count: i64 = conn
            .query_row("select count(*) from finding_identities", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(Some(current_id), stored[0].id);
        assert_eq!(identity_count, 1);
        assert_eq!(observation, (1, blob_hash.to_string(), 24, 91));
        assert_eq!(
            indexed_file,
            (blob_hash.to_string(), 114, "Rust".to_string())
        );
        assert_eq!(applied_seq, "4");

        crate::storage_v3::writer_actor::StorageWriterActor::commit_blocking(
            &log_path,
            temp.path().join(".kuzushi/v3/index.sqlite3"),
            crate::storage_v3::writer_actor::WriterCommand::Control(
                crate::storage_v3::writer_actor::ControlCommand::RebuildProjection,
            ),
        )
        .unwrap();
        let rebuilt_id: i64 = conn
            .query_row("select id from finding_current", [], |row| row.get(0))
            .unwrap();
        let rebuilt_identity_count: i64 = conn
            .query_row("select count(*) from finding_identities", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rebuilt_id, current_id);
        assert_eq!(rebuilt_identity_count, identity_count);
    }

    #[test]
    fn observation_source_round_trips_the_scanned_file_through_the_blob_store() {
        const SOURCE: &str = "fn handler(term: &str) {\n    db.query(term);\n}\n";
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let source_path = temp.path().join("src/app.rs");
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::write(&source_path, SOURCE).unwrap();
        let store = FindingStore::open(&db_path).unwrap();
        let run_id = "run-observation-read";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "rules.cwe-89",
            "src/app.rs",
            2,
            Some(2),
            Severity::High,
            "SQL injection reaches query builder, CWE-89",
        );
        store.insert_finding(run_id, &finding).unwrap();
        let stored = store.list_findings_for_scan_id(run_id).unwrap();
        let stable_fp = stored[0].identity_id.as_deref().unwrap();

        let scoped = store
            .latest_observation_source(stable_fp, Some(run_id))
            .unwrap()
            .expect("run-scoped observation source");
        assert_eq!(scoped.run_id, run_id);
        assert_eq!(scoped.display_path.as_deref(), Some("src/app.rs"));
        assert_eq!(scoped.display_line, Some(2));

        // A representative scan_id from another run still resolves the blob.
        let fallback = store
            .latest_observation_source(stable_fp, Some("run-that-stored-no-blob"))
            .unwrap()
            .expect("stable-fp fallback observation source");
        assert_eq!(fallback.blob_hash, scoped.blob_hash);

        let bytes = store
            .read_observation_blob(&scoped.blob_hash)
            .unwrap()
            .expect("blob bytes");
        assert_eq!(bytes, SOURCE.as_bytes());

        let missing = store.read_observation_blob(&"0".repeat(64)).unwrap();
        assert_eq!(missing, None);
        assert_eq!(
            store
                .latest_observation_source("unknown-identity", None)
                .unwrap(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_backed_insert_omits_provenance_for_outside_symlink() {
        const OUTSIDE_TOKEN: &str = "OUTSIDE-REQUIREMENTS-TOKEN-MUST-NOT-PERSIST";
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let workspace_root = workspace.path().canonicalize().unwrap();
        let outside_file = outside.path().join("requirements.txt");
        std::fs::write(&outside_file, OUTSIDE_TOKEN).unwrap();
        std::os::unix::fs::symlink(&outside_file, workspace_root.join("requirements.txt")).unwrap();
        let db_path = workspace_root.join(".kuzushi/v3/index.sqlite3");
        let log_path = workspace_root.join(".kuzushi/v3/log");
        std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let store = FindingStore::open(&db_path).unwrap();
        let run_id = "run-symlink-provenance";
        store
            .record_run_started(run_id, &workspace_root, "running")
            .unwrap();
        let finding = Finding::new_tool(
            "dep-hygiene",
            "dep-hygiene/unpinned",
            "requirements.txt",
            1,
            Some(1),
            Severity::Medium,
            "Dependency is not pinned",
        );

        store.insert_finding(run_id, &finding).unwrap();

        let events = crate::event_log::EventLog::open(&log_path)
            .unwrap()
            .read_all()
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[1].event_kind,
            crate::event_log::EventKind::FindingObserved
        );
        assert!(events[1]
            .payload
            .get("blobHash")
            .is_none_or(serde_json::Value::is_null));
        assert!(!serde_json::to_string(&events)
            .unwrap()
            .contains(OUTSIDE_TOKEN));
        assert!(
            !serde_json::to_string(&store.list_findings_for_scan_id(run_id).unwrap())
                .unwrap()
                .contains(OUTSIDE_TOKEN)
        );
        assert!(!crate::workspace::workspace_objects_dir(&workspace_root).exists());
        assert_eq!(
            std::fs::read_to_string(outside_file).unwrap(),
            OUTSIDE_TOKEN
        );
    }

    #[test]
    fn file_backed_save_verification_records_v3_event_and_projection() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let log_path = temp.path().join(".kuzushi/v3/log");
        let store = FindingStore::open(&db_path).unwrap();
        let run_id = "run-v3-verification";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "verify-test",
            "rules.cwe-89",
            "src/app.rs",
            42,
            Some(42),
            Severity::High,
            "SQL injection reaches query builder",
        );
        let finding_id = store.insert_finding(run_id, &finding).unwrap();
        let stable_fp = store.list_findings_for_scan_id(run_id).unwrap()[0]
            .identity_id
            .clone()
            .unwrap();

        store
            .save_verification(
                finding_id,
                &PersistedVerification {
                    proof_level: 4,
                    proof_verdict: PersistedProofVerdict::Exploited,
                    backend: PersistedSandboxBackend::Bwrap,
                    language: Some("rust".to_string()),
                    harness_path: Some("/tmp/harness".to_string()),
                    crash_evidence: Some("panic: sink reached".to_string()),
                    duration_ms: 250,
                    cost_usd: 0.125,
                    notes: vec!["empirical proof".to_string()],
                    verification_run_id: Some("verify-run-v3".to_string()),
                    verified_scan_id: Some(run_id.to_string()),
                    provenance: None,
                    created_at: String::new(),
                },
            )
            .unwrap();

        let log = crate::event_log::EventLog::open(&log_path).unwrap();
        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[2].event_kind,
            crate::event_log::EventKind::VerificationRecorded
        );
        assert_eq!(
            events[2].payload["stableFp"].as_str(),
            Some(stable_fp.as_str())
        );

        let conn = rusqlite::Connection::open(db_path).unwrap();
        let projected: (String, i64, String, String, String) = conn
            .query_row(
                "select stable_fp, proof_level, proof_verdict, verification_run_id, verified_scan_id from verification_events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            projected,
            (
                stable_fp,
                4,
                "exploited".to_string(),
                "verify-run-v3".to_string(),
                run_id.to_string(),
            )
        );
        let old_table_count: i64 = conn
            .query_row(
                "select count(*) from sqlite_master where type = 'table' and name = 'verifications'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_table_count, 0);
    }

    #[test]
    fn file_backed_record_auto_triage_records_v3_event_and_projection() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let log_path = temp.path().join(".kuzushi/v3/log");
        let store = FindingStore::open(&db_path).unwrap();
        let run_id = "run-v3-triage";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "triage-test",
            "rules.cwe-89",
            "src/app.rs",
            42,
            Some(42),
            Severity::High,
            "SQL injection reaches query builder",
        );
        let finding_id = store.insert_finding(run_id, &finding).unwrap();

        store
            .record_triage_with_author(
                finding_id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.95,
                    rationale: "operator confirmed source-to-sink evidence".to_string(),
                    cost_usd: 0.125,
                    cost_usd_exact: false,
                    estimated_cost_usd: None,
                },
                TriageAuthor::Human,
            )
            .unwrap();

        let stored = store.list_findings_for_scan_id(run_id).unwrap();
        assert_eq!(
            stored[0].triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::TruePositive)
        );
        assert_eq!(stored[0].triaged_by, Some(TriageAuthor::Human));
        let stored_triage = stored[0].triage.as_ref().unwrap();
        assert_eq!(stored_triage.cost_usd, 0.125);
        assert!(!stored_triage.cost_usd_exact);
        let latest = store
            .latest_review_decision(finding_id)
            .unwrap()
            .expect("review decision");
        assert_eq!(latest.decision.verdict, ReviewDecisionVerdict::Confirmed);

        let events = crate::event_log::EventLog::open(&log_path)
            .unwrap()
            .read_all()
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[2].event_kind,
            crate::event_log::EventKind::TriageDecided
        );
        assert_eq!(
            events[2].payload["updatesFindingTriage"].as_bool(),
            Some(true)
        );
        assert_eq!(events[2].payload["triageCostUsd"].as_f64(), Some(0.125));
        assert_eq!(
            events[2].payload["triageCostUsdExact"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn file_backed_insert_patch_result_records_v3_event_projection_and_diff_object() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let log_path = temp.path().join(".kuzushi/v3/log");
        let store = FindingStore::open(&db_path).unwrap();
        let run_id = "run-v3-patch";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "patch-test",
            "rules.cwe-89",
            "src/app.rs",
            42,
            Some(42),
            Severity::High,
            "SQL injection reaches query builder",
        );
        store.insert_finding(run_id, &finding).unwrap();
        let stable_fp = store.list_findings_for_scan_id(run_id).unwrap()[0]
            .identity_id
            .clone()
            .unwrap();

        store
            .insert_patch_result(&PatchResult {
                patch_run_id: "patch-run-v3".to_string(),
                fingerprint: finding.fingerprint.clone(),
                repo: "/tmp/repo".to_string(),
                diff: Some("diff --git a/src/app.rs b/src/app.rs\n".to_string()),
                status: PatchStatus::Verified,
                iterations: 2,
                build_command: Some("cargo build".to_string()),
                test_command: Some("cargo test".to_string()),
                worktree_path: Some("/tmp/worktree".to_string()),
                cost_usd: Some(0.000_000_4),
                provider_spend_unresolved: true,
                validator_log: Some("tests passed".to_string()),
                history: vec![PatchAttempt {
                    attempt: 1,
                    diff: "diff".to_string(),
                    status: PatchStatus::Sound,
                    output: "ok".to_string(),
                }],
                provenance: Some(PatchProvenance {
                    source_commit: "0123456789012345678901234567890123456789".to_string(),
                    target: "/tmp/repo".to_string(),
                    originating_run_id: Some("shell-run".to_string()),
                    detector_tool: Some("semgrep:scan".to_string()),
                    detector_run_id: Some(run_id.to_string()),
                    detector_input_digest: Some("digest".to_string()),
                    reproducer: None,
                    verification_source_identity: None,
                    verification_run_id: None,
                }),
                created_at: None,
                updated_at: None,
            })
            .unwrap();

        let log = crate::event_log::EventLog::open(&log_path).unwrap();
        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[2].event_kind,
            crate::event_log::EventKind::PatchAttemptRecorded
        );
        assert_eq!(
            events[2].payload["stableFp"].as_str(),
            Some(stable_fp.as_str())
        );
        assert_eq!(events[2].payload["costUsd"], json!(0.000_000_4));
        assert_eq!(events[2].payload["costUsdMicros"], json!(0));
        assert_eq!(events[2].payload["providerSpendUnresolved"], json!(true));

        let conn = rusqlite::Connection::open(db_path).unwrap();
        let projected: (String, String, String, i64, f64) = conn
            .query_row(
                "select stable_fp, patch_run_id, diff_object, diff_size_bytes, cost_usd from patch_attempt_events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(projected.0, stable_fp);
        assert_eq!(projected.1, "patch-run-v3");
        assert!(projected.2.len() >= 4);
        assert_eq!(
            projected.3,
            "diff --git a/src/app.rs b/src/app.rs\n".len() as i64
        );
        assert_eq!(projected.4, 0.000_000_4);
        let object_path = temp
            .path()
            .join(".kuzushi/v3/objects/blake3")
            .join(&projected.2[0..2])
            .join(&projected.2[2..4])
            .join(&projected.2);
        assert!(object_path.is_file());
        let read_back = store
            .get_patch_results_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(read_back.len(), 1);
        assert_eq!(read_back[0].status, PatchStatus::Verified);
        assert_eq!(read_back[0].cost_usd, Some(0.000_000_4));
        assert!(read_back[0].provider_spend_unresolved);
        assert_eq!(
            read_back[0]
                .provenance
                .as_ref()
                .map(|provenance| provenance.source_commit.as_str()),
            Some("0123456789012345678901234567890123456789")
        );
        assert_eq!(
            read_back[0].diff.as_deref(),
            Some("diff --git a/src/app.rs b/src/app.rs\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = temp.path().join("outside-patch-secret");
            std::fs::write(&outside, "secret").unwrap();
            std::fs::remove_file(&object_path).unwrap();
            symlink(&outside, &object_path).unwrap();
            let error = store
                .get_patch_results_for_finding(&finding.fingerprint)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("symlink") || error.contains("non-symlink"),
                "{error}"
            );
            assert_eq!(std::fs::read_to_string(outside).unwrap(), "secret");
        }
        let old_table_count: i64 = conn
            .query_row(
                "select count(*) from sqlite_master where type = 'table' and name = 'patch_results'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_table_count, 0);
    }

    #[test]
    fn patch_lifecycle_is_append_only_with_one_current_projection() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        let run_id = "run-patch-lifecycle";
        store
            .record_run_started(run_id, temp.path(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep:scan",
            "rules.cwe-89",
            "src/app.rs",
            42,
            Some(42),
            Severity::High,
            "SQL injection reaches query builder",
        );
        store.insert_finding(run_id, &finding).unwrap();
        let stable_fp = store
            .patch_lifecycle_stable_fp(&finding.fingerprint)
            .unwrap();
        let mut record = PatchLifecycleRecord {
            application_id: "application-1".to_string(),
            stable_fp,
            fingerprint: finding.fingerprint.clone(),
            finding_scan_id: finding.scan_id.clone(),
            patch_run_id: "patch-run-1".to_string(),
            target: temp.path().display().to_string(),
            diff_hash: "diff-hash".to_string(),
            base_commit: Some("base-commit".to_string()),
            touched_files: vec![PatchLifecycleFile {
                path: "src/app.rs".to_string(),
                before_hash: Some("before".to_string()),
                after_hash: Some("after".to_string()),
            }],
            state: PatchLifecycleState::Applied,
            reverify_run_id: None,
            reverify_evidence: None,
            detail: None,
            actor: "operator".to_string(),
            application_started_at: "1".to_string(),
            applied_at: Some("1".to_string()),
            updated_at: "1".to_string(),
        };
        store.insert_patch_lifecycle_record(&record).unwrap();
        record.state = PatchLifecycleState::Verified;
        record.reverify_run_id = Some("reverify-1".to_string());
        record.updated_at = "2".to_string();
        let error = store
            .insert_patch_lifecycle_record(&record)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires a receipt"), "{error}");
        let objects = crate::content_store::ContentStore::open(
            db_path
                .parent()
                .unwrap()
                .join(crate::workspace::WORKSPACE_OBJECTS_DIR),
        )
        .unwrap();
        let reproducer = objects
            .put_json(
                crate::content_store::ObjectKind::ProofSnapshot,
                &json!({"schemaVersion": 2}),
            )
            .unwrap();
        let receipt = crate::findings::test_verified_receipt(&record, reproducer);
        record.reverify_evidence = Some(
            objects
                .put_json(crate::content_store::ObjectKind::ProofSnapshot, &receipt)
                .unwrap(),
        );
        store.insert_patch_lifecycle_record(&record).unwrap();

        let loaded = store.get_patch_lifecycle("application-1").unwrap().unwrap();
        assert_eq!(loaded.state, PatchLifecycleState::Verified);
        assert_eq!(
            store
                .latest_patch_lifecycle_for_finding(&finding.fingerprint)
                .unwrap()
                .unwrap(),
            loaded
        );
        assert_eq!(store.list_patch_lifecycle_current().unwrap(), vec![loaded]);
        let conn = rusqlite::Connection::open(db_path).unwrap();
        let history: i64 = conn
            .query_row("select count(*) from patch_lifecycle_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        let current: i64 = conn
            .query_row("select count(*) from patch_lifecycle_current", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(history, 2);
        assert_eq!(current, 1);
    }

    #[test]
    fn file_backed_store_records_schema_version() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");

        drop(FindingStore::open(&db_path).unwrap());

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let version: i32 = conn
            .query_row("pragma user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn stored_findings_receive_target_scoped_identity() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-identity-1", Path::new("/tmp/repo-a"), "running")
            .unwrap();
        store
            .record_run_started("run-identity-2", Path::new("/tmp/repo-a"), "running")
            .unwrap();
        store
            .record_run_started("run-identity-3", Path::new("/tmp/repo-b"), "running")
            .unwrap();

        let finding = Finding::new_semgrep(
            "demo.identity",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        let finding_id = store.insert_finding("run-identity-1", &finding).unwrap();
        store.insert_finding("run-identity-2", &finding).unwrap();
        store.insert_finding("run-identity-3", &finding).unwrap();

        let first = store.list_findings_for_scan_id("run-identity-1").unwrap();
        let second = store.list_findings_for_scan_id("run-identity-2").unwrap();
        let third = store.list_findings_for_scan_id("run-identity-3").unwrap();
        let expected = identity_id_for_target_and_finding("/tmp/repo-a", &finding);

        assert_eq!(first[0].identity_id.as_deref(), Some(expected.as_str()));
        assert_eq!(second[0].identity_id, first[0].identity_id);
        assert_ne!(third[0].identity_id, first[0].identity_id);
        assert_eq!(first[0].identity_match_tier.as_deref(), Some("stable_fp"));

        store
            .record_auto_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.42,
                    rationale: "needs dataflow confirmation".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let decisions = store.list_review_decisions(finding_id).unwrap();
        assert_eq!(decisions[0].identity_id.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn cross_run_dedup_key_reuse_is_target_scoped() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-target-a", Path::new("/tmp/repo-a"), "running")
            .unwrap();
        store
            .record_run_started("run-target-b", Path::new("/tmp/repo-b"), "running")
            .unwrap();
        let first = Finding::new_tool(
            "semgrep",
            "path-traversal-cwe-22",
            "src/files.rs",
            20,
            Some(20),
            Severity::High,
            "request path escapes the root",
        );
        let second = Finding::new_tool(
            "agentic-sast",
            "download-escape-cwe-22",
            "src/files.rs",
            22,
            Some(22),
            Severity::High,
            "download path escapes the root",
        );
        assert_eq!(first.dedup_key, second.dedup_key);
        assert_ne!(first.fingerprint, second.fingerprint);

        store.insert_finding("run-target-a", &first).unwrap();
        store.insert_finding("run-target-b", &second).unwrap();
        let target_a = store.list_findings_for_scan_id("run-target-a").unwrap();
        let target_b = store.list_findings_for_scan_id("run-target-b").unwrap();

        assert_ne!(target_a[0].identity_id, target_b[0].identity_id);
        assert_eq!(
            target_b[0].identity_match_tier.as_deref(),
            Some("stable_fp")
        );
    }

    #[test]
    fn spoofed_exact_fingerprint_cannot_cross_structural_identity() {
        let store = FindingStore::open_in_memory().unwrap();
        let target = Path::new("/tmp/repo");
        store
            .record_run_started("run-victim", target, "running")
            .unwrap();
        store
            .record_run_started("run-spoof", target, "running")
            .unwrap();
        let victim = Finding::new_tool(
            "semgrep",
            "sql-injection-cwe-89",
            "src/db.rs",
            10,
            Some(10),
            Severity::High,
            "tainted input reaches a SQL query",
        );
        let mut spoof = Finding::new_tool(
            "dynamic-module",
            "command-injection-cwe-78",
            "src/db.rs",
            80,
            Some(80),
            Severity::High,
            "tainted input reaches a shell command",
        );
        spoof.fingerprint = victim.fingerprint.clone();
        spoof.dedup_key = None;

        store.insert_finding("run-victim", &victim).unwrap();
        store.insert_finding("run-spoof", &spoof).unwrap();
        let victim_row = store.list_findings_for_scan_id("run-victim").unwrap();
        let spoof_row = store.list_findings_for_scan_id("run-spoof").unwrap();

        assert_ne!(victim_row[0].identity_id, spoof_row[0].identity_id);
    }

    #[test]
    fn v3_identity_carries_same_snippet_across_line_shifts() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-line-shift-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .record_run_started("run-line-shift-b", Path::new("/tmp/repo"), "running")
            .unwrap();

        let first = line_shift_finding(12);
        let second = line_shift_finding(44);
        assert_eq!(
            first.fingerprint, second.fingerprint,
            "v3 stable fingerprints ignore display line numbers"
        );

        let first_id = store.insert_finding("run-line-shift-a", &first).unwrap();
        let second_id = store.insert_finding("run-line-shift-b", &second).unwrap();
        let first_row = store.list_findings_for_scan_id("run-line-shift-a").unwrap();
        let second_row = store.list_findings_for_scan_id("run-line-shift-b").unwrap();

        assert_eq!(
            first_row[0].identity_id, second_row[0].identity_id,
            "same evidence at a shifted line is one stable finding"
        );
        assert_eq!(
            first_row[0].identity_match_tier.as_deref(),
            Some("stable_fp")
        );
        assert_eq!(
            second_row[0].identity_match_tier.as_deref(),
            Some("stable_fp")
        );

        store
            .record_triage_with_author(
                first_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "operator confirmed stable evidence".to_string(),
                    ..Default::default()
                },
                TriageAuthor::Human,
            )
            .unwrap();

        let carried = store
            .latest_review_decision_for_finding_identity(second_id)
            .unwrap();
        assert!(
            carried.is_some(),
            "operator decisions carry across line shifts"
        );
    }

    #[test]
    fn dedup_collision_records_incoming_fingerprint_under_existing_identity() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-identity-collision";
        store
            .record_run_started(run, Path::new("/tmp/repo"), "running")
            .unwrap();

        let semgrep = Finding::new_tool(
            "semgrep",
            "java.injection.tainted-system-call",
            "src/foo.c",
            42,
            Some(42),
            Severity::Medium,
            "user-controlled exec, CWE-78",
        );
        store.insert_finding(run, &semgrep).unwrap();

        let systems = Finding::new_tool(
            "systems-hunt",
            "systems/cwe-78",
            "src/foo.c",
            42,
            Some(42),
            Severity::High,
            "exec reaches shell with attacker input, CWE-78",
        );
        assert_eq!(semgrep.dedup_key, systems.dedup_key);
        assert_eq!(semgrep.source_signature, systems.source_signature);
        assert_ne!(semgrep.fingerprint, systems.fingerprint);

        store.insert_finding(run, &systems).unwrap();
        let listed = store.list_findings_for_scan_id(run).unwrap();
        let identity_id = listed[0]
            .identity_id
            .as_deref()
            .expect("merged finding identity");

        let exact_count: i64 = store
            .conn
            .query_row(
                "select count(*) from finding_identity_fingerprints
                 where identity_id = ?1 and fingerprint = ?2 and match_basis = ?3",
                rusqlite::params![identity_id, semgrep.fingerprint, "stable_fp"],
                |row| row.get(0),
            )
            .unwrap();
        let collision_count: i64 = store
            .conn
            .query_row(
                "select count(*) from finding_identity_fingerprints
                 where identity_id = ?1 and fingerprint = ?2 and match_basis = ?3",
                rusqlite::params![identity_id, systems.fingerprint, "dedup_collision"],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(exact_count, 1);
        assert_eq!(collision_count, 1);
    }

    fn line_shift_finding(start_line: u32) -> Finding {
        Finding::new_tool(
            "semgrep",
            "rules/cwe-89",
            "src/db.rs",
            start_line,
            Some(start_line),
            Severity::High,
            "SQL injection reaches query builder, CWE-89",
        )
        .with_evidence(vec![FindingEvidence {
            kind: "code".to_string(),
            file_path: "src/db.rs".to_string(),
            line: start_line,
            snippet: "let rows = db.query(user_controlled_filter);".to_string(),
            rationale: "observed source-to-sink statement".to_string(),
            confidence: 90,
            request_blob: None,
            response_blob: None,
        }])
    }

    fn identity_id_for_target_and_finding(target: &str, finding: &Finding) -> String {
        let identity_key = finding_identity_key_for_finding(finding);
        compute_finding_identity_id(target, &identity_key.key)
    }

    #[test]
    fn identity_links_same_snippet_across_line_shifts() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-identity-line-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .record_run_started("run-identity-line-b", Path::new("/tmp/repo"), "running")
            .unwrap();

        store
            .insert_finding("run-identity-line-a", &line_shift_finding(12))
            .unwrap();
        store
            .insert_finding("run-identity-line-b", &line_shift_finding(44))
            .unwrap();

        let first = store
            .list_findings_for_scan_id("run-identity-line-a")
            .unwrap();
        let second = store
            .list_findings_for_scan_id("run-identity-line-b")
            .unwrap();
        assert_eq!(first[0].identity_id, second[0].identity_id);
        assert_eq!(first[0].identity_match_tier.as_deref(), Some("stable_fp"));
        assert_eq!(second[0].identity_match_tier.as_deref(), Some("stable_fp"));
    }

    #[test]
    fn human_triage_is_sticky_against_auto_updates() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-human-triage", Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        let finding_id = store.insert_finding("run-human-triage", &finding).unwrap();
        store
            .record_triage_with_author(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.95,
                    rationale: "operator confirmed scanner claim".to_string(),
                    ..Default::default()
                },
                TriageAuthor::Human,
            )
            .unwrap();
        store
            .record_auto_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.10,
                    rationale: "automated rerun disagreed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let stored = store.list_findings(10).unwrap();
        let triage = stored[0].triage.as_ref().unwrap();
        assert_eq!(triage.verdict, TriageVerdict::TruePositive);
        assert_eq!(stored[0].triaged_by, Some(TriageAuthor::Human));
        assert_eq!(triage.rationale, "operator confirmed scanner claim");
    }

    #[test]
    fn review_decisions_append_only_for_accepted_triage_changes() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-review-decisions", Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        let finding_id = store
            .insert_finding("run-review-decisions", &finding)
            .unwrap();
        store
            .record_auto_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.4,
                    rationale: "automated review needs more evidence".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .record_triage_with_author(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.95,
                    rationale: "operator confirmed source-to-sink evidence".to_string(),
                    ..Default::default()
                },
                TriageAuthor::Human,
            )
            .unwrap();
        store
            .record_auto_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.1,
                    rationale: "automated rerun disagreed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let decisions = store.list_review_decisions(finding_id).unwrap();
        assert_eq!(decisions.len(), 2);
        assert_eq!(
            decisions[0].decision.verdict,
            ReviewDecisionVerdict::NeedsReview
        );
        assert_eq!(decisions[0].decision.author, TriageAuthor::Auto);
        assert_eq!(
            decisions[1].decision.verdict,
            ReviewDecisionVerdict::Confirmed
        );
        assert_eq!(decisions[1].decision.author, TriageAuthor::Human);

        let latest = store
            .latest_review_decision(finding_id)
            .unwrap()
            .expect("latest review decision");
        assert_eq!(latest.decision.verdict, ReviewDecisionVerdict::Confirmed);
        assert_eq!(latest.triage_verdict, Some(TriageVerdict::TruePositive));
    }

    #[test]
    fn static_proof_history_is_derived_from_observation_state_changes() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-static-proof-events";
        store
            .record_run_started(run, Path::new("/tmp/repo"), "running")
            .unwrap();

        let initial = Finding::new_semgrep(
            "demo.static-proof",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        )
        .with_static_proof_state(StaticProofState::SignalOnly);
        let finding_id = store.insert_finding(run, &initial).unwrap();

        let mut upgraded = initial.clone();
        upgraded.set_static_proof_state(StaticProofState::SourceSinkLinked);
        store.insert_finding(run, &upgraded).unwrap();
        store.insert_finding(run, &upgraded).unwrap();

        let events = store.list_static_proof_history(finding_id).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].previous_state, None);
        assert_eq!(events[0].next_state, StaticProofState::SignalOnly);
        assert_eq!(events[0].source, "semgrep");
        assert_eq!(events[1].previous_state, Some(StaticProofState::SignalOnly));
        assert_eq!(events[1].next_state, StaticProofState::SourceSinkLinked);
    }

    #[test]
    fn review_decisions_can_be_read_by_durable_identity() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-decision-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .record_run_started("run-decision-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.identity-decision",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        let first_id = store.insert_finding("run-decision-a", &finding).unwrap();
        let second_id = store.insert_finding("run-decision-b", &finding).unwrap();

        store
            .record_triage_with_author(
                first_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.95,
                    rationale: "operator confirmed source-to-sink evidence".to_string(),
                    ..Default::default()
                },
                TriageAuthor::Human,
            )
            .unwrap();

        let second_row_decisions = store.list_review_decisions(second_id).unwrap();
        assert!(
            second_row_decisions.is_empty(),
            "row-scoped v3 reader stays per occurrence"
        );

        let second_identity_decisions = store
            .list_review_decisions_for_finding_identity(second_id)
            .unwrap();
        assert_eq!(second_identity_decisions.len(), 1);
        assert_eq!(
            second_identity_decisions[0].decision.verdict,
            ReviewDecisionVerdict::Confirmed
        );
        assert_eq!(second_identity_decisions[0].finding_id, first_id);
        assert_eq!(
            second_identity_decisions[0].identity_id,
            store.list_findings_for_scan_id("run-decision-b").unwrap()[0].identity_id
        );

        let findings = store.list_findings(10).unwrap();
        let batched_decisions = store.list_review_decisions_for_findings(&findings).unwrap();
        assert_eq!(batched_decisions, second_identity_decisions);

        let latest = store
            .latest_review_decision_for_finding_identity(second_id)
            .unwrap()
            .expect("latest identity decision");
        assert_eq!(latest.decision.author, TriageAuthor::Human);
    }

    #[test]
    fn user_review_decision_can_append_without_triage_verdict() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-user-review", Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.suppressed",
            "src/app.ts",
            12,
            Some(12),
            Severity::Medium,
            "reviewed under policy",
        );
        let finding_id = store.insert_finding("run-user-review", &finding).unwrap();

        store
            .append_user_review_decision(
                finding_id,
                &ReviewDecision {
                    verdict: ReviewDecisionVerdict::Suppressed,
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "suppressed by approved review policy".to_string(),
                    dismiss_reason: None,
                    actor: None,
                },
            )
            .unwrap();

        let latest = store
            .latest_review_decision(finding_id)
            .unwrap()
            .expect("latest review decision");
        assert_eq!(latest.decision.verdict, ReviewDecisionVerdict::Suppressed);
        assert_eq!(latest.decision.author, TriageAuthor::Human);
        assert_eq!(latest.triage_verdict, None);
        assert_eq!(
            store.list_findings(10).unwrap()[0].triage,
            None,
            "user decisions must not mutate scanner triage projection"
        );
    }

    #[test]
    fn review_decisions_retain_event_provenance_and_order_by_event_seq() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        store
            .record_run_started("run-provenance", Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.provenance",
            "src/app.ts",
            12,
            Some(12),
            Severity::Medium,
            "provenance fixture",
        );
        let finding_id = store.insert_finding("run-provenance", &finding).unwrap();
        for (verdict, rationale) in [
            (ReviewDecisionVerdict::Confirmed, "confirmed on first pass"),
            (
                ReviewDecisionVerdict::RejectedFalsePositive,
                "second look found a sanitizer",
            ),
        ] {
            store
                .append_user_review_decision(
                    finding_id,
                    &ReviewDecision {
                        verdict,
                        author: TriageAuthor::Human,
                        confidence: 1.0,
                        rationale: rationale.to_string(),
                        dismiss_reason: None,
                        actor: None,
                    },
                )
                .unwrap();
        }

        let records = store
            .list_review_decisions_for_finding_identity(finding_id)
            .unwrap();
        assert_eq!(records.len(), 2);
        let first = records[0].provenance.as_ref().expect("first provenance");
        let second = records[1].provenance.as_ref().expect("second provenance");
        assert!(first.event_seq < second.event_seq);
        assert!(!second.event_hash.is_empty());
        let watermark = second.read_watermark.expect("read watermark retained");
        assert!(watermark < second.event_seq);

        // Event sequence is authoritative: a wall-clock inversion (skew or
        // same-second writes) must not reorder replayed decisions.
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute(
                "update review_decisions set created_at = '2099-01-01T00:00:00Z' where id = ?1",
                rusqlite::params![records[0].id],
            )
            .unwrap();
        let reordered = store
            .list_review_decisions_for_finding_identity(finding_id)
            .unwrap();
        assert_eq!(
            reordered[0].decision.verdict,
            ReviewDecisionVerdict::Confirmed
        );
        let latest = store
            .latest_review_decision_for_finding_identity(finding_id)
            .unwrap()
            .expect("latest decision");
        assert_eq!(
            latest.decision.verdict,
            ReviewDecisionVerdict::RejectedFalsePositive
        );
    }

    // Append three human decisions in the given verdict order and clear the
    // provenance columns of the rows at `null_positions` (0-based), simulating
    // legacy decisions the backfill could not attribute. Returns the store, the
    // finding id, and the projected decision ids in recording order.
    fn store_with_null_provenance_decisions(
        db_dir: &std::path::Path,
        run: &str,
        verdicts: [ReviewDecisionVerdict; 3],
        null_positions: &[usize],
    ) -> (FindingStore, i64, Vec<i64>) {
        let db_path = db_dir.join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        store
            .record_run_started(run, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.null-provenance",
            "src/app.ts",
            12,
            Some(12),
            Severity::Medium,
            "null provenance ordering fixture",
        );
        let finding_id = store.insert_finding(run, &finding).unwrap();

        let ids: Vec<i64> = verdicts
            .into_iter()
            .enumerate()
            .map(|(index, verdict)| {
                store
                    .append_user_review_decision(
                        finding_id,
                        &ReviewDecision {
                            verdict,
                            author: TriageAuthor::Human,
                            confidence: 1.0,
                            rationale: format!("decision {index}"),
                            dismiss_reason: None,
                            actor: None,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let raw = rusqlite::Connection::open(&db_path).unwrap();
        for &position in null_positions {
            raw.execute(
                "update review_decisions
                    set decision_event_seq = null,
                        decision_event_hash = null,
                        decision_read_watermark = null
                  where id = ?1",
                rusqlite::params![ids[position]],
            )
            .unwrap();
        }
        (store, finding_id, ids)
    }

    #[test]
    fn review_decision_latest_reflects_recording_order_when_newest_is_null_provenance() {
        // The newest decision is a legacy row the backfill left with a NULL
        // sequence. It must still win latest-first reads and sort last in the
        // ascending history — reproducing the pre-fix bug where NULL sorted
        // below every sequence value and the newest decision was dropped.
        let temp = tempfile::tempdir().unwrap();
        let (store, finding_id, _ids) = store_with_null_provenance_decisions(
            temp.path(),
            "run-newest-null",
            [
                ReviewDecisionVerdict::Confirmed,
                ReviewDecisionVerdict::RejectedFalsePositive,
                ReviewDecisionVerdict::Deferred,
            ],
            &[2],
        );

        let latest = store
            .latest_review_decision(finding_id)
            .unwrap()
            .expect("latest review decision");
        assert_eq!(latest.decision.verdict, ReviewDecisionVerdict::Deferred);

        let history: Vec<ReviewDecisionVerdict> = store
            .list_review_decisions(finding_id)
            .unwrap()
            .into_iter()
            .map(|record| record.decision.verdict)
            .collect();
        assert_eq!(
            history,
            vec![
                ReviewDecisionVerdict::Confirmed,
                ReviewDecisionVerdict::RejectedFalsePositive,
                ReviewDecisionVerdict::Deferred,
            ]
        );
    }

    #[test]
    fn review_decision_sequenced_decision_supersedes_older_null_provenance() {
        // A migrated workspace can hold an old legacy decision with NULL
        // provenance followed by newer sequenced decisions. NULL marks unknown
        // provenance, not "newest": a later sequenced decision must supersede
        // the older NULL row rather than be pinned behind it forever.
        let temp = tempfile::tempdir().unwrap();
        let (store, finding_id, _ids) = store_with_null_provenance_decisions(
            temp.path(),
            "run-older-null",
            [
                ReviewDecisionVerdict::Deferred,
                ReviewDecisionVerdict::Confirmed,
                ReviewDecisionVerdict::RejectedFalsePositive,
            ],
            &[0],
        );

        let latest = store
            .latest_review_decision(finding_id)
            .unwrap()
            .expect("latest review decision");
        assert_eq!(
            latest.decision.verdict,
            ReviewDecisionVerdict::RejectedFalsePositive,
            "a sequenced decision must supersede an older NULL-provenance row"
        );

        let history: Vec<ReviewDecisionVerdict> = store
            .list_review_decisions(finding_id)
            .unwrap()
            .into_iter()
            .map(|record| record.decision.verdict)
            .collect();
        assert_eq!(
            history,
            vec![
                ReviewDecisionVerdict::Deferred,
                ReviewDecisionVerdict::Confirmed,
                ReviewDecisionVerdict::RejectedFalsePositive,
            ]
        );
    }

    #[test]
    fn user_review_decision_rejects_automated_author() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-auto-review", Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.auto-review",
            "src/app.ts",
            12,
            Some(12),
            Severity::Medium,
            "reviewed by automation",
        );
        let finding_id = store.insert_finding("run-auto-review", &finding).unwrap();

        let result = store.append_user_review_decision(
            finding_id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Deferred,
                author: TriageAuthor::Auto,
                confidence: 0.5,
                rationale: "automation tried to defer".to_string(),
                dismiss_reason: None,
                actor: None,
            },
        );

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("automated triage must use record_auto_triage"));
        assert!(store.list_review_decisions(finding_id).unwrap().is_empty());
    }

    #[test]
    fn user_review_decision_rejects_empty_reason() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-empty-review", Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.empty-review",
            "src/app.ts",
            12,
            Some(12),
            Severity::Medium,
            "reviewed without rationale",
        );
        let finding_id = store.insert_finding("run-empty-review", &finding).unwrap();

        let result = store.append_user_review_decision(
            finding_id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Deferred,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "   ".to_string(),
                dismiss_reason: None,
                actor: None,
            },
        );

        assert!(result
            .unwrap_err()
            .to_string()
            .contains("review decision reason cannot be empty"));
        assert!(store.list_review_decisions(finding_id).unwrap().is_empty());
    }

    #[test]
    fn review_decision_verdict_preserves_triage_semantics() {
        assert_eq!(
            ReviewDecisionVerdict::from_triage_verdict(TriageVerdict::TruePositive),
            ReviewDecisionVerdict::Confirmed
        );
        assert_eq!(
            ReviewDecisionVerdict::from_triage_verdict(TriageVerdict::FalsePositive),
            ReviewDecisionVerdict::RejectedFalsePositive
        );
        assert_eq!(
            ReviewDecisionVerdict::from_triage_verdict(TriageVerdict::ByDesign),
            ReviewDecisionVerdict::AcceptedRisk
        );
        assert_eq!(
            ReviewDecisionVerdict::from_triage_verdict(TriageVerdict::NeedsReview),
            ReviewDecisionVerdict::NeedsReview
        );
        assert_eq!(
            ReviewDecisionVerdict::Confirmed.to_triage_verdict(),
            Some(TriageVerdict::TruePositive)
        );
        assert_eq!(
            ReviewDecisionVerdict::RejectedFalsePositive.to_triage_verdict(),
            Some(TriageVerdict::FalsePositive)
        );
        assert_eq!(
            ReviewDecisionVerdict::AcceptedRisk.to_triage_verdict(),
            Some(TriageVerdict::ByDesign)
        );
        assert_eq!(
            ReviewDecisionVerdict::NeedsReview.to_triage_verdict(),
            Some(TriageVerdict::NeedsReview)
        );
        assert_eq!(ReviewDecisionVerdict::Suppressed.to_triage_verdict(), None);
        assert_eq!(ReviewDecisionVerdict::Deferred.to_triage_verdict(), None);
        assert_eq!(
            ReviewDecisionVerdict::AcceptedRisk.as_str(),
            "accepted_risk"
        );
        assert_eq!(ReviewDecisionVerdict::Suppressed.as_str(), "suppressed");
        assert_eq!(ReviewDecisionVerdict::Deferred.as_str(), "deferred");
        assert!(ReviewDecisionVerdict::Confirmed.is_terminal());
        assert!(ReviewDecisionVerdict::Suppressed.is_terminal());
        assert!(ReviewDecisionVerdict::Deferred.is_terminal());
        assert!(!ReviewDecisionVerdict::NeedsReview.is_terminal());
    }

    #[test]
    fn review_decision_projection_keeps_author_confidence_and_rationale() {
        let triage = TriageOutcome {
            first_link: None,
            refute_reason: None,
            verdict: TriageVerdict::FalsePositive,
            confidence: 0.8,
            rationale: "model signal did not match reachable code".to_string(),
            cost_usd: 0.12,
            cost_usd_exact: true,
            estimated_cost_usd: None,
        };

        let decision = ReviewDecision::from_triage(&triage, Some(TriageAuthor::Human));

        assert_eq!(
            decision.verdict,
            ReviewDecisionVerdict::RejectedFalsePositive
        );
        assert_eq!(decision.author, TriageAuthor::Human);
        assert_eq!(decision.confidence, 0.8);
        assert_eq!(decision.rationale, triage.rationale);
    }

    #[test]
    fn stores_lists_and_replaces_structured_finding_evidence() {
        // Insertion now verifies source citations against the run's target
        // root, so the cited lines have to exist on disk or the evidence is
        // fail-closed to reasoning before it is ever stored.
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

    #[test]
    fn insertion_downgrades_code_evidence_when_snippet_is_not_on_disk() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/app.rs"),
            "fn handler(user: &str) {\n    render(user);\n}\n",
        )
        .unwrap();

        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-evidence-disk";
        store
            .record_run_started(run_id, temp.path(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "agentic-sast",
            "agentic-sast/cwe-79",
            "src/app.rs",
            2,
            None,
            Severity::High,
            "HTML injection reaches render",
        )
        .with_evidence(vec![
            FindingEvidence {
                kind: "code".to_string(),
                file_path: "src/app.rs".to_string(),
                line: 2,
                snippet: "render(user);".to_string(),
                rationale: "observed sink".to_string(),
                confidence: 90,
                ..Default::default()
            },
            FindingEvidence {
                kind: "code".to_string(),
                file_path: "src/app.rs".to_string(),
                line: 2,
                snippet: "eval(user);".to_string(),
                rationale: "claimed sink".to_string(),
                confidence: 90,
                ..Default::default()
            },
        ]);

        store.insert_finding(run_id, &finding).unwrap();

        let resolved = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.evidence[0].kind, "code");
        assert_eq!(resolved.evidence[0].confidence, 90);
        assert_eq!(resolved.evidence[1].kind, "reasoning");
        assert_eq!(resolved.evidence[1].confidence, 25);
        assert!(resolved.evidence[1]
            .rationale
            .contains("citation-unverified"));
    }

    #[test]
    fn stores_optional_finding_lifecycle_metadata() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-finding-metadata";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
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
            .record_run_started("run-static", Path::new("/tmp/repo"), "completed")
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
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
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

    /// The shell advertises `verify F-0001` / `patch F-0001` keypaths;
    /// positional aliases must therefore resolve wherever an operator
    /// reference is accepted, not only exact/prefix fingerprints.
    #[test]
    fn operator_reference_resolves_positional_alias() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-alias";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let critical = Finding::new_semgrep(
            "demo.sqli",
            "src/login.ts",
            17,
            Some(17),
            Severity::Critical,
            "sql injection reaches query",
        );
        let low = Finding::new_semgrep(
            "demo.log",
            "src/log.ts",
            3,
            Some(3),
            Severity::Low,
            "log forging",
        );
        store.insert_finding(run_id, &critical).unwrap();
        store.insert_finding(run_id, &low).unwrap();

        let first = store
            .get_finding_by_operator_reference("F-0001")
            .unwrap()
            .expect("F-0001 resolves");
        let second = store
            .get_finding_by_operator_reference("F-0002")
            .unwrap()
            .expect("F-0002 resolves");

        assert_eq!(
            first.fingerprint, critical.fingerprint,
            "F-0001 is the top-sorted finding"
        );
        assert_eq!(second.fingerprint, low.fingerprint);
        assert!(store
            .get_finding_by_operator_reference("F-0099")
            .unwrap()
            .is_none());
    }

    #[test]
    fn repeated_observations_do_not_make_a_fingerprint_prefix_ambiguous() {
        let store = FindingStore::open_in_memory().unwrap();
        for run_id in ["run-prefix-first", "run-prefix-latest"] {
            store
                .record_run_started(run_id, Path::new("/tmp/repo"), "completed")
                .unwrap();
        }
        let finding = Finding::new_semgrep(
            "demo.repeated",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        store.insert_finding("run-prefix-first", &finding).unwrap();
        let latest_id = store.insert_finding("run-prefix-latest", &finding).unwrap();

        let resolved = store
            .get_finding_by_reference(&finding.fingerprint[..8])
            .unwrap()
            .unwrap();

        assert_eq!(resolved.id, Some(latest_id));
        assert_eq!(resolved.fingerprint, finding.fingerprint);
    }

    #[test]
    fn distinct_fingerprints_with_the_same_prefix_remain_ambiguous() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-prefix-collision", Path::new("/tmp/repo"), "completed")
            .unwrap();
        let mut first = Finding::new_semgrep(
            "demo.first",
            "src/first.ts",
            12,
            Some(12),
            Severity::High,
            "First finding",
        );
        first.fingerprint = "shared-prefix-11111111".to_string();
        let mut second = Finding::new_semgrep(
            "demo.second",
            "src/second.ts",
            24,
            Some(24),
            Severity::High,
            "Second finding",
        );
        second.fingerprint = "shared-prefix-22222222".to_string();
        store
            .insert_finding("run-prefix-collision", &first)
            .unwrap();
        store
            .insert_finding("run-prefix-collision", &second)
            .unwrap();

        let error = store
            .get_finding_by_reference("shared-prefix-")
            .unwrap_err()
            .to_string();

        assert!(error.contains("ambiguous"), "unexpected error: {error}");
    }

    #[test]
    fn finding_prefix_treats_sql_like_characters_as_literals() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-literal-prefix", Path::new("/tmp/repo"), "completed")
            .unwrap();
        for fingerprint in ["literal%_\\prefix-one", "literalxxprefix-two"] {
            let mut finding = Finding::new_semgrep(
                "demo.literal-prefix",
                "src/app.ts",
                12,
                Some(12),
                Severity::High,
                "Literal prefix",
            );
            finding.fingerprint = fingerprint.to_string();
            store
                .insert_finding("run-literal-prefix", &finding)
                .unwrap();
        }

        let resolved = store
            .get_finding_by_reference("literal%_\\prefix")
            .unwrap()
            .unwrap();

        assert_eq!(resolved.fingerprint, "literal%_\\prefix-one");
    }

    #[test]
    fn reference_resolution_attaches_latest_verification_for_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        store
            .record_run_started("run-verify-prefix", Path::new("/tmp/repo"), "completed")
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
                    verification_run_id: None,
                    verified_scan_id: None,
                    provenance: None,
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
            first_link: None,
            refute_reason: None,
            verdict: TriageVerdict::TruePositive,
            confidence: 0.91,
            rationale: "source and sink are linked".to_string(),
            cost_usd: 0.02,
            cost_usd_exact: true,
            estimated_cost_usd: None,
        });
        let mut verification = crate::findings::test_support::empirically_verified(4);
        verification.harness_path = Some("/tmp/harness.js".to_string());
        verification.crash_evidence = Some("runtime fixture recorded marker".to_string());
        verification.notes = vec!["browser fixture recorded runtime evidence".to_string()];
        finding.verification = Some(verification);

        let report = FindingDetailReport::new(Some("F-0001".to_string()), finding, Vec::new());
        let output = report.output();

        assert!(output.contains("Finding F-0001"));
        assert!(output.contains("Proof state: source_sink_linked"));
        assert!(output.contains("Runtime validation: runtime_verified"));
        assert!(output.contains("Proof ladder: verified"));
        assert!(output.contains("Next action: patch"));
        assert_eq!(report.next_action, FindingNextAction::Patch);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["proofState"], "source_sink_linked - Source and sink are linked in static evidence; runtime proof not recorded");
        assert_eq!(json["nextAction"], "patch");
    }

    /// `kuzushi finding` must disclose a recorded proof deferral beside the
    /// proof state, and the deferral must not move any proof field.
    #[test]
    fn finding_detail_discloses_a_proof_deferral_without_changing_proof_state() {
        let finding = Finding::new_tool(
            "semgrep",
            "js/xss",
            "src/render.js",
            42,
            None,
            Severity::High,
            "Request query data is rendered into HTML without escaping",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        let plain = FindingDetailReport::new(None, finding.clone(), Vec::new());
        let deferral = kuzushi_core_proof_deferral_view();

        let deferred = FindingDetailReport::new(None, finding, Vec::new())
            .with_proof_deferral(Some(deferral.clone()));

        assert!(deferred
            .output()
            .contains("Proof deferral: proof deferred by operator at generation scan-7"));
        assert_eq!(deferred.proof_state, plain.proof_state);
        assert_eq!(deferred.runtime_validation, plain.runtime_validation);
        assert_eq!(deferred.proof_ladder, plain.proof_ladder);
        assert_eq!(deferred.next_action, plain.next_action);
        assert!(!plain.output().contains("Proof deferral:"));
        let json = serde_json::to_value(&deferred).unwrap();
        assert_eq!(json["proofDeferral"]["scanId"], "scan-7");
        assert_eq!(json["proofDeferral"]["actor"], "operator");
    }

    fn kuzushi_core_proof_deferral_view() -> crate::workflow_attempts::ProofDeferralView {
        crate::workflow_attempts::ProofDeferralView::from_record(
            &crate::workflow_attempts::ProofDeferralRecorded::human(
                "semgrep:js/xss:9867ad7c",
                None,
                "scan-7",
                crate::workflow_attempts::PhaseTargetSnapshot {
                    target: "/target".to_string(),
                    revision: Some("abc".to_string()),
                    dirty: false,
                },
                "no runtime harness for this language yet",
            ),
        )
    }

    #[test]
    fn compact_static_proof_summary_keeps_ui_vocabulary_short() {
        let signal = static_proof_summary(Some(StaticProofState::SignalOnly));
        assert_eq!(signal.label, "signal-only");
        assert!(signal.explanation.contains("scanner signal"));

        let linked = static_proof_summary(Some(StaticProofState::SourceSinkLinked));
        assert_eq!(linked.label, "path-linked");
        assert!(linked.explanation.contains("links source to sink"));

        let strong_static = static_proof_summary(Some(StaticProofState::StaticallyConfirmed));
        assert_eq!(strong_static.label, "static-supported");
        assert!(strong_static
            .explanation
            .contains("supports the scanner claim"));
        assert!(
            proof_state_label(Some(StaticProofState::StaticallyConfirmed))
                .contains("Strong static evidence supports the scanner claim")
        );

        let missing = static_proof_summary(None);
        assert_eq!(missing.label, "not recorded");
        assert_eq!(missing.explanation, "no static proof recorded");

        assert!(proof_state_label(Some(StaticProofState::SignalOnly)).contains("signal_only -"));
    }

    #[test]
    fn compact_runtime_validation_summary_names_operator_state() {
        let missing = runtime_validation_summary(None);
        assert_eq!(missing.label, "not verified");
        assert_eq!(missing.explanation, "runtime verification has not run");

        let verification = crate::findings::test_support::empirically_verified(4);
        let verified = runtime_validation_summary(Some(&verification));
        assert_eq!(verified.label, "verified L4");
        assert!(verified.explanation.contains("empirical evidence"));
    }

    #[test]
    fn model_assessment_never_projects_runtime_authority() {
        let mut finding = Finding::new_semgrep(
            "demo.model",
            "src/app.ts",
            7,
            None,
            Severity::High,
            "model-assessed finding",
        );
        finding.verification = Some(PersistedVerification {
            proof_level: 3,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Model,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 10,
            cost_usd: 0.01,
            notes: vec!["legacy model verdict".to_string()],
            verification_run_id: Some("model-run".to_string()),
            verified_scan_id: Some("scan-1".to_string()),
            provenance: None,
            created_at: "now".to_string(),
        });

        assert_eq!(finding_lifecycle_status(&finding), "model_assessed");
        assert_eq!(
            ProofConfidence::classify(&finding),
            ProofConfidence::Unverified
        );
        assert!(runtime_validation_label(finding.verification.as_ref()).contains("model_assessed"));
        assert_eq!(
            runtime_validation_summary(finding.verification.as_ref()).label,
            "model assessed"
        );
        assert_eq!(
            finding_next_action(&finding, None),
            FindingNextAction::Validate
        );

        finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
        assert_eq!(finding_lifecycle_status(&finding), "statically_supported");
        assert_eq!(ProofConfidence::classify(&finding), ProofConfidence::Likely);
    }

    #[test]
    fn runtime_validation_label_says_not_executed_for_non_disproof_verdicts() {
        // These four verdicts mean runtime verification could not run. They
        // are not a verdict on the scanner's claim, so the operator-facing
        // label must not read as a rejection of it.
        for verdict in [
            PersistedProofVerdict::HarnessFailedToBuild,
            PersistedProofVerdict::InfrastructureError,
            PersistedProofVerdict::LanguageUnsupportedYet,
            PersistedProofVerdict::InsufficientFindingDetail,
        ] {
            let mut verification = crate::findings::test_support::empirically_verified(0);
            verification.proof_verdict = verdict;
            let label = runtime_validation_label(Some(&verification));

            assert!(
                !label.contains("execution_rejected"),
                "{verdict:?} still labeled as a rejection: {label}"
            );
            assert!(
                label.starts_with("not executed - "),
                "{verdict:?} label lost its honest prefix: {label}"
            );
        }

        // The durable artifact vocabulary is unchanged: only the label moved.
        assert!(crate::findings::is_runtime_proof_state("execution_rejected"));
    }

    #[test]
    fn finding_next_action_is_exported_for_ui_surfaces() {
        let mut finding = Finding::new_semgrep(
            "demo.xss",
            "src/app.ts",
            7,
            None,
            Severity::High,
            "Request query data is rendered into HTML without escaping",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);

        assert_eq!(
            finding_next_action(&finding, None),
            FindingNextAction::Validate
        );

        finding.verification = Some(crate::findings::test_support::empirically_verified(4));
        assert_eq!(
            finding_next_action(&finding, None),
            FindingNextAction::Patch
        );
        assert_eq!(finding_next_action(&finding, None).as_str(), "patch");
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
    fn finding_aliases_stay_stable_when_triage_proof_changes() {
        let mut guessed = Finding::new_semgrep(
            "demo.guess",
            "src/guess.ts",
            1,
            None,
            Severity::High,
            "high guess",
        );
        guessed.fingerprint = "aaaa1111".to_string();
        let mut confirmed = Finding::new_semgrep(
            "demo.confirmed",
            "src/confirmed.ts",
            2,
            None,
            Severity::High,
            "high confirmed",
        );
        confirmed.fingerprint = "zzzz1111".to_string();
        confirmed.triage = Some(TriageOutcome {
            first_link: None,
            refute_reason: None,
            verdict: TriageVerdict::TruePositive,
            confidence: 0.72,
            rationale: "source reaches sink".to_string(),
            cost_usd: 0.0,
            cost_usd_exact: true,
            estimated_cost_usd: None,
        });

        let mut before_triage = confirmed.clone();
        before_triage.triage = None;
        let before = sorted_finding_aliases(&[guessed.clone(), before_triage]);
        let after = sorted_finding_aliases(&[guessed.clone(), confirmed.clone()]);

        assert_eq!(before[0].1.fingerprint, guessed.fingerprint);
        assert_eq!(before[1].1.fingerprint, confirmed.fingerprint);
        assert_eq!(after[0].1.fingerprint, guessed.fingerprint);
        assert_eq!(after[1].1.fingerprint, confirmed.fingerprint);
        assert_eq!(before[1].0, after[1].0);
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
            review_decisions: Default::default(),
            count: 2,
            findings: vec![high_late, high_early],
            aliases: vec![],
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
        finding.set_static_proof_state(StaticProofState::SourceSinkLinked);
        finding.triage = Some(TriageOutcome {
            first_link: None,
            refute_reason: None,
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "reviewed source-linked evidence".to_string(),
            cost_usd: 0.0,
            cost_usd_exact: true,
            estimated_cost_usd: None,
        });
        finding.triaged_by = Some(TriageAuthor::Human);
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
            review_decisions: Default::default(),
            count: 1,
            findings: vec![finding],
            aliases: vec![],
        };

        let output = report.to_tool_json().to_string();

        assert!(output.contains("requestBlobPresent"));
        assert!(output.contains("responseBlobPresent"));
        assert!(output.contains(r#""review_decision":"confirmed""#));
        assert!(output.contains(r#""static_proof_state":"source_sink_linked""#));
        assert!(!output.contains("RAW REQUEST BODY"));
        assert!(!output.contains("RAW RESPONSE BODY"));
    }

    #[test]
    fn filters_findings_by_severity_name_file_and_limit() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-1", Path::new("/tmp/repo"), "completed")
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
    fn filters_findings_by_short_verdict_values() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-1", Path::new("/tmp/repo"), "completed")
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
            .record_auto_triage(
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
            .record_auto_triage(
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
    fn filters_findings_by_decision_alias_and_review_completeness() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-1", Path::new("/tmp/repo"), "completed")
            .unwrap();

        let confirmed = Finding::new_semgrep(
            "demo.confirmed",
            "src/a.ts",
            1,
            Some(1),
            Severity::High,
            "confirmed issue",
        );
        let needs_review = Finding::new_semgrep(
            "demo.needs_review",
            "src/b.ts",
            1,
            Some(1),
            Severity::Medium,
            "needs review issue",
        );
        let untriaged = Finding::new_semgrep(
            "demo.untriaged",
            "src/c.ts",
            1,
            Some(1),
            Severity::Low,
            "untriaged issue",
        );
        let confirmed_id = store.insert_finding("run-1", &confirmed).unwrap();
        let needs_review_id = store.insert_finding("run-1", &needs_review).unwrap();
        store.insert_finding("run-1", &untriaged).unwrap();
        store
            .record_auto_triage(
                confirmed_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "human confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .record_auto_triage(
                needs_review_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.5,
                    rationale: "more evidence required".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let complete = store
            .list_findings_filtered(
                &FindingListFilter::from_tool_input(&json!({
                    "decision": ["confirmed"],
                    "completeness": ["complete"]
                }))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(complete.count, 1);
        assert_eq!(complete.findings[0].rule_id, "demo.confirmed");

        let open = store
            .list_findings_filtered(
                &FindingListFilter::from_filter_expression(
                    "decision:needs_review state:triaged completeness:open",
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(open.count, 1);
        assert!(open
            .findings
            .iter()
            .any(|finding| finding.rule_id == "demo.needs_review"));

        let all_open = store
            .list_findings_filtered(
                &FindingListFilter::from_filter_expression("completeness:open").unwrap(),
            )
            .unwrap();
        assert_eq!(all_open.count, 2);
        assert!(all_open
            .findings
            .iter()
            .any(|finding| finding.rule_id == "demo.untriaged"));

        let suppressed = Finding::new_semgrep(
            "demo.suppressed",
            "src/d.ts",
            1,
            Some(1),
            Severity::Low,
            "suppressed issue",
        );
        let suppressed_id = store.insert_finding("run-1", &suppressed).unwrap();
        store
            .append_user_review_decision(
                suppressed_id,
                &ReviewDecision {
                    verdict: ReviewDecisionVerdict::Suppressed,
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "suppressed by approved review policy".to_string(),
                    dismiss_reason: None,
                    actor: None,
                },
            )
            .unwrap();

        let suppressed_complete = store
            .list_findings_filtered(
                &FindingListFilter::from_filter_expression(
                    "decision:suppressed completeness:complete",
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(suppressed_complete.count, 1);
        assert_eq!(suppressed_complete.findings[0].rule_id, "demo.suppressed");
        assert!(
            suppressed_complete.findings[0].triage.is_none(),
            "decision filters must not require mutating scanner triage"
        );

        let open_after_suppression = store
            .list_findings_filtered(
                &FindingListFilter::from_filter_expression("completeness:open").unwrap(),
            )
            .unwrap();
        assert_eq!(open_after_suppression.count, 2);
        assert!(!open_after_suppression
            .findings
            .iter()
            .any(|finding| finding.rule_id == "demo.suppressed"));
    }

    #[test]
    fn filters_findings_by_lifecycle_status_without_using_review_decision() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-1", Path::new("/tmp/repo"), "completed")
            .unwrap();

        let seen = Finding::new_tool(
            "fixture",
            "demo.seen",
            "src/a.ts",
            1,
            Some(1),
            Severity::High,
            "seen scanner finding",
        );
        let supported = Finding::new_semgrep(
            "demo.supported",
            "src/b.ts",
            2,
            Some(2),
            Severity::Medium,
            "source-linked scanner finding",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        store.insert_finding("run-1", &seen).unwrap();
        store.insert_finding("run-1", &supported).unwrap();

        let status_seen = store
            .list_findings_filtered(
                &FindingListFilter::from_tool_input(&json!({"status": ["seen"]})).unwrap(),
            )
            .unwrap();
        assert_eq!(status_seen.count, 1);
        assert_eq!(status_seen.findings[0].rule_id, "demo.seen");

        let status_supported = store
            .list_findings_filtered(
                &FindingListFilter::from_filter_expression("status:statically_supported").unwrap(),
            )
            .unwrap();
        assert_eq!(status_supported.count, 1);
        assert_eq!(status_supported.findings[0].rule_id, "demo.supported");
    }

    #[test]
    fn filter_expression_matches_state_rank_text_run_and_source() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-2026-alpha", Path::new("/tmp/repo"), "completed")
            .unwrap();
        store
            .record_run_started("run-other", Path::new("/tmp/repo"), "completed")
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
    fn filter_expression_accepts_and_matches_provenance_keys() {
        let filter = FindingListFilter::from_tool_input(&json!({
            "filter": "rev:ABCDEF1 branch:Main dirty:clean"
        }))
        .unwrap();
        let mut finding = Finding::new_tool(
            "tool",
            "rule".to_string(),
            "src/lib.rs".to_string(),
            1,
            None,
            Severity::High,
            "message".to_string(),
        );
        finding.scan_id = Some("run-1".to_string());
        let mut summary = RunSummary::running("run-1", "scan", Some("tool".to_string()), "/repo");
        summary.target_git = Some(RunTargetGitMetadata {
            sha: "abcdef1234567890".to_string(),
            branch: Some("main".to_string()),
            dirty: false,
        });
        let runs = BTreeMap::from([("run-1".to_string(), summary)]);

        assert!(filter.has_provenance_filter());
        assert!(filter.matches_run_provenance(&finding, &runs));
        assert_eq!(filter.revision_sha, vec!["abcdef1"]);
        assert_eq!(filter.branch, vec!["main"]);
        assert_eq!(filter.dirty, Some(false));
    }

    #[test]
    fn save_and_get_verification_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        store
            .record_run_started("run-v1", Path::new("/repo"), "running")
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
        let reproducer = crate::content_store::ContentStore::open(
            db_path
                .parent()
                .unwrap()
                .join(crate::workspace::WORKSPACE_OBJECTS_DIR),
        )
        .unwrap()
        .put_json(
            crate::content_store::ObjectKind::ProofSnapshot,
            &json!({"schemaVersion": 1, "files": []}),
        )
        .unwrap();

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
            verification_run_id: Some("verify-run-roundtrip".to_string()),
            verified_scan_id: Some("run-v1".to_string()),
            provenance: Some(VerificationProvenance {
                source_identity: crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
                    snapshot_hash: crate::run_lifecycle::SafeText::operator_visible("a".repeat(64)),
                    tree_hash: Some(crate::run_lifecycle::SafeText::operator_visible(
                        "b".repeat(64),
                    )),
                },
                reproducer: Some(reproducer),
            }),
            created_at: String::new(),
        };
        let row_id = store.save_verification(finding_id, &record).unwrap();
        assert!(row_id > 0);
        let events = crate::event_log::EventLog::open(temp.path().join(".kuzushi/v3/log"))
            .unwrap()
            .read_all()
            .unwrap();
        let event = events
            .iter()
            .find(|event| event.event_kind == crate::event_log::EventKind::VerificationRecorded)
            .unwrap();
        assert_eq!(event.run_id.as_deref(), Some("verify-run-roundtrip"));
        assert_eq!(
            event.target_snapshot.as_ref().map(|hash| hash.as_str()),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(event.payload["provenance"], json!(record.provenance));
        drop(store);

        let store = FindingStore::open(&db_path).unwrap();
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
        assert_eq!(
            fetched.verification_run_id.as_deref(),
            Some("verify-run-roundtrip")
        );
        assert_eq!(fetched.verified_scan_id.as_deref(), Some("run-v1"));
        assert_eq!(fetched.provenance, record.provenance);
        assert!(!fetched.created_at.is_empty());
        let restored_finding = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(restored_finding).unwrap()["verification"]["provenance"],
            json!(record.provenance)
        );
    }

    #[test]
    fn get_latest_verification_returns_most_recent_row() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        store
            .record_run_started("run-v3-secondary", Path::new("/repo"), "running")
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
        let finding_id = store.insert_finding("run-v3-secondary", &finding).unwrap();

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
            verification_run_id: None,
            verified_scan_id: None,
            provenance: None,
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
            verification_run_id: None,
            verified_scan_id: None,
            provenance: None,
            created_at: String::new(),
        };
        store.save_verification(finding_id, &earlier).unwrap();
        store.save_verification(finding_id, &later).unwrap();

        let fetched = store.get_latest_verification(finding_id).unwrap().unwrap();
        assert_eq!(fetched.proof_level, 4);
        assert_eq!(fetched.proof_verdict, PersistedProofVerdict::Exploited);
    }

    #[test]
    fn get_latest_verification_rejects_unknown_verdict_and_backend() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        store
            .record_run_started("run-v-bad", Path::new("/repo"), "running")
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
        let finding_id = store.insert_finding("run-v-bad", &finding).unwrap();
        let stable_fp = store.list_findings_for_scan_id("run-v-bad").unwrap()[0]
            .identity_id
            .clone()
            .unwrap();
        store
            .conn
            .execute(
                r#"
                insert into verification_events (
                  event_hash, seq, stable_fp, finding_id, proof_level,
                  proof_verdict, backend, duration_ms, cost_usd, notes_json,
                  actor, created_at, payload_json
                ) values (
                  'bad-verdict', 999, ?2, ?1, 4,
                  'surprise', 'plain', 0, 0.0, '[]',
                  'test', '2026-01-01T00:00:00Z', '{}'
                )
                "#,
                rusqlite::params![finding_id, stable_fp],
            )
            .unwrap();

        let verdict_error = store.get_latest_verification(finding_id).unwrap_err();
        assert!(verdict_error
            .to_string()
            .contains("unknown persisted proof verdict"));

        store
            .conn
            .execute(
                "update verification_events set proof_verdict = 'exploited', backend = 'mystery'",
                [],
            )
            .unwrap();
        let backend_error = store.get_latest_verification(finding_id).unwrap_err();
        assert!(backend_error
            .to_string()
            .contains("unknown persisted sandbox backend"));
    }

    #[test]
    fn list_findings_attaches_latest_verification() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        store
            .record_run_started("run-v-list", Path::new("/repo"), "running")
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
        let finding_id = store.insert_finding("run-v-list", &finding).unwrap();
        store
            .save_verification(
                finding_id,
                &PersistedVerification {
                    proof_level: 4,
                    proof_verdict: PersistedProofVerdict::Exploited,
                    backend: PersistedSandboxBackend::Bwrap,
                    language: Some("rust".to_string()),
                    harness_path: None,
                    crash_evidence: Some("SIGSEGV".to_string()),
                    duration_ms: 200,
                    cost_usd: 0.0,
                    notes: vec![],
                    verification_run_id: None,
                    verified_scan_id: None,
                    provenance: None,
                    created_at: String::new(),
                },
            )
            .unwrap();

        let listed = store.list_findings(10).unwrap();
        assert_eq!(
            listed[0].verification.as_ref().map(|v| v.proof_verdict),
            Some(PersistedProofVerdict::Exploited)
        );

        let scan_rows = store.list_findings_for_scan_id("run-v-list").unwrap();
        assert_eq!(
            scan_rows[0].verification.as_ref().map(|v| v.proof_level),
            Some(4)
        );
    }

    #[test]
    fn rescan_hydrates_prior_verification_by_durable_identity() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join(".kuzushi/v3/index.sqlite3");
        let store = FindingStore::open(&db_path).unwrap();
        for run_id in ["scan-a", "scan-b"] {
            store
                .record_run_started(run_id, Path::new("/repo"), "running")
                .unwrap();
        }
        let finding = Finding::new_tool(
            "verify-test",
            "rule.test",
            "src/x.rs",
            10,
            None,
            Severity::High,
            "same durable finding",
        );
        let finding_id = store.insert_finding("scan-a", &finding).unwrap();
        store
            .save_verification(
                finding_id,
                &PersistedVerification {
                    proof_level: 4,
                    proof_verdict: PersistedProofVerdict::Exploited,
                    backend: PersistedSandboxBackend::Bwrap,
                    language: Some("rust".to_string()),
                    harness_path: None,
                    crash_evidence: Some("SIGSEGV".to_string()),
                    duration_ms: 200,
                    cost_usd: 0.0,
                    notes: vec![],
                    verification_run_id: Some("verify-a".to_string()),
                    verified_scan_id: Some("scan-a".to_string()),
                    provenance: None,
                    created_at: String::new(),
                },
            )
            .unwrap();

        store.insert_finding("scan-b", &finding).unwrap();
        let rescanned = store.list_findings_for_scan_id("scan-b").unwrap();
        let proof = rescanned[0]
            .verification
            .as_ref()
            .expect("prior proof should follow durable identity");

        assert_eq!(rescanned[0].scan_id.as_deref(), Some("scan-b"));
        assert_eq!(proof.verification_run_id.as_deref(), Some("verify-a"));
        assert_eq!(proof.verified_scan_id.as_deref(), Some("scan-a"));
    }

    #[test]
    fn record_auto_triage_against_missing_finding_id_returns_clean_fk_error() {
        // M1 §1.5: this protects against the "triage:assertions FK fault"
        // family — historically the bus worker could call `record_auto_triage`
        // with a finding_id that did not exist yet (race with the findings
        // insert). SQLite must enforce the FK so callers observe a clean
        // Err and never silently corrupt the triage table.
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-fk", Path::new("/repo"), "running")
            .unwrap();
        let stale_id: i64 = 9_999_999;
        let outcome = TriageOutcome {
            first_link: None,
            refute_reason: None,
            verdict: TriageVerdict::TruePositive,
            confidence: 0.5,
            rationale: "synthetic".to_string(),
            cost_usd: 0.0,
            cost_usd_exact: true,
            estimated_cost_usd: None,
        };
        let result = store.record_auto_triage(stale_id, &outcome);
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
    fn record_auto_triage_after_finding_insert_succeeds_with_dedup_safe_id() {
        // Companion to the FK error test — confirms the happy path: when
        // a triage write follows its findings insert in the same scan,
        // the FK is satisfied. This is the contract callers must keep.
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-fk-ok", Path::new("/repo"), "running")
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
            .record_auto_triage(
                id,
                &TriageOutcome {
                    first_link: None,
                    refute_reason: None,
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.7,
                    rationale: "ok".to_string(),
                    cost_usd: 0.0,
                    cost_usd_exact: true,
                    estimated_cost_usd: None,
                },
            )
            .expect("triage insert must succeed when finding exists");
    }

    #[test]
    fn get_latest_verification_returns_none_when_no_rows() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-v3", Path::new("/repo"), "running")
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
    fn fingerprint_is_v3_stable_line_and_message_independent() {
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
        assert!(one.fingerprint.starts_with("fp3_"));
        let other_line = Finding::new_tool(
            "semgrep",
            "demo.sqli",
            "src/db.rs",
            43,
            None,
            Severity::High,
            "first wording",
        );
        assert_eq!(one.fingerprint, other_line.fingerprint);
    }

    // ---- Findings dismissal + re-scan reconciler (state machine) ----

    fn semgrep_finding(rule: &str, line: u32, msg: &str) -> Finding {
        Finding::new_semgrep(rule, "src/app.ts", line, Some(line), Severity::High, msg)
    }

    fn state_filter_count(store: &FindingStore, expr: &str) -> usize {
        let filter = FindingListFilter::from_filter_expression(expr).unwrap();
        store
            .list_findings_filtered(&filter)
            .unwrap()
            .findings
            .len()
    }

    #[test]
    fn rescan_marks_vanished_finding_not_observed_when_tool_reran() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        let vanished = semgrep_finding("demo.gone", 10, "will vanish");
        store.insert_finding("run-a", &vanished).unwrap();
        store.record_run_finished("run-a", "completed", 1).unwrap();

        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        // A different semgrep finding keeps the tool "exercised" in run-b.
        store
            .insert_finding("run-b", &semgrep_finding("demo.other", 20, "still here"))
            .unwrap();
        store.record_run_finished("run-b", "completed", 1).unwrap();

        assert_eq!(state_filter_count(&store, "state:not_observed"), 1);
        assert_eq!(state_filter_count(&store, "state:fixed"), 0);
        let stored = store.get_finding_by_fingerprint(&vanished.fingerprint).unwrap().unwrap();
        let gap = stored.observation_gap.unwrap();
        assert_eq!(gap.last_seen_run_id.as_deref(), Some("run-a"));
        assert_eq!(gap.compared_run_id.as_deref(), Some("run-b"));
        assert!(gap.event_seq > 0);
        assert!(!gap.event_hash.is_empty());
    }

    #[test]
    fn rescan_preserves_confirmed_finding_without_inventing_a_fix() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        let real = semgrep_finding("demo.real", 10, "confirmed bug");
        let id = store.insert_finding("run-a", &real).unwrap();
        store
            .append_user_review_decision(
                id,
                &ReviewDecision {
                    verdict: ReviewDecisionVerdict::Confirmed,
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "verified reachable".to_string(),
                    dismiss_reason: None,
                    actor: None,
                },
            )
            .unwrap();
        store.record_run_finished("run-a", "completed", 1).unwrap();

        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-b", &semgrep_finding("demo.other", 20, "still here"))
            .unwrap();
        store.record_run_finished("run-b", "completed", 1).unwrap();

        assert_eq!(state_filter_count(&store, "state:fixed"), 0);
        assert_eq!(state_filter_count(&store, "state:confirmed"), 1);
        assert_eq!(state_filter_count(&store, "state:not_observed"), 1);
        assert_eq!(state_filter_count(&store, "state:removed"), 0);
        assert!(store.finding_is_relevant(&real).unwrap());
        let filter = FindingListFilter::from_filter_expression("state:not_observed").unwrap();
        let report = store.list_findings_filtered(&filter).unwrap();
        let data = report.aliased_rows_json();
        assert_eq!(data["findings"][0]["review_decision"], "confirmed");
        assert_eq!(data["findings"][0]["review_decision_author"], "human");
        assert_eq!(data["findings"][0]["observation_gap"]["comparedRunId"], "run-b");
        assert!(report.output().contains(" tp "));
        for policy in [IdentityFoldPolicy::Safe, IdentityFoldPolicy::Legacy, IdentityFoldPolicy::Aggressive] {
            let operator_report = store.list_findings_filtered_with_identity_policy(&filter, policy).unwrap();
            assert_eq!(operator_report.count, 1, "{policy:?}");
            assert!(operator_report.findings[0].observation_gap.is_some());
        }
    }

    #[test]
    fn observation_gap_survives_restart_and_suppression_changes() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let bug = semgrep_finding("demo.gap", 10, "not seen in the later scan");
        let store = workspace_store(&root);
        completed_run(&store, "run-a", std::slice::from_ref(&bug));
        write_scan_scope_receipt(&root, "run-b", &[]);
        completed_run(&store, "run-b", &[semgrep_finding("demo.other", 20, "present")]);
        let before = store.get_finding_by_fingerprint(&bug.fingerprint).unwrap().unwrap().observation_gap;
        assert!(before.is_some());
        for event_kind in [crate::event_log::EventKind::SuppressionAdded, crate::event_log::EventKind::SuppressionRemoved] {
            store.append_finding_suppression_event(&bug.fingerprint, SuppressionLifecycleEvent {
                event_kind, reason: None, rule_id: Some("fixture".to_string()),
                statement: None, origin: None, expires_at_unix: None, actor: "test".to_string(),
            }).unwrap();
            assert_eq!(store.get_finding_by_fingerprint(&bug.fingerprint).unwrap().unwrap().observation_gap, before);
        }
        drop(store);
        let resumed = workspace_store(&root);
        assert_eq!(resumed.get_finding_by_fingerprint(&bug.fingerprint).unwrap().unwrap().observation_gap, before);
    }

    #[test]
    fn observation_gap_from_a_producer_cannot_override_the_ledger() {
        let store = FindingStore::open_in_memory().unwrap();
        let mut bug = semgrep_finding("demo.forged-gap", 10, "present");
        bug.observation_gap = Some(FindingObservationGap {
            event_seq: 999, event_hash: "producer-claim".to_string(),
            last_seen_run_id: Some("old".to_string()), compared_run_id: Some("new".to_string()),
        });
        completed_run(&store, "run-a", std::slice::from_ref(&bug));
        assert!(store.get_finding_by_fingerprint(&bug.fingerprint).unwrap().unwrap().observation_gap.is_none());
    }

    #[test]
    fn rescan_does_not_stale_findings_from_untouched_tools() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding(
                "run-a",
                &semgrep_finding("demo.gone", 10, "semgrep finding"),
            )
            .unwrap();
        store.record_run_finished("run-a", "completed", 1).unwrap();

        // run-b only exercises codeql; the semgrep finding must NOT be staled.
        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        let codeql = Finding::new_tool(
            "codeql",
            "cql.rule",
            "src/other.rs",
            5,
            Some(5),
            Severity::Medium,
            "codeql finding",
        );
        store.insert_finding("run-b", &codeql).unwrap();
        store.record_run_finished("run-b", "completed", 1).unwrap();

        assert_eq!(state_filter_count(&store, "state:not_observed"), 0);
        assert_eq!(state_filter_count(&store, "state:open"), 2);
    }

    #[test]
    fn failed_rescan_never_reconciles() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-a", &semgrep_finding("demo.gone", 10, "finding"))
            .unwrap();
        store.record_run_finished("run-a", "completed", 1).unwrap();

        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-b", &semgrep_finding("demo.other", 20, "finding"))
            .unwrap();
        store.record_run_finished("run-b", "failed", 1).unwrap();

        assert_eq!(state_filter_count(&store, "state:not_observed"), 0);
    }

    #[test]
    fn reconcile_is_idempotent() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-a", &semgrep_finding("demo.gone", 10, "finding"))
            .unwrap();
        store.record_run_finished("run-a", "completed", 1).unwrap();
        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-b", &semgrep_finding("demo.other", 20, "finding"))
            .unwrap();
        // First reconcile already ran inside record_run_finished below.
        store.record_run_finished("run-b", "completed", 1).unwrap();

        let second = store.reconcile_disappeared_findings("run-b").unwrap();
        assert!(
            second.disappeared.is_empty(),
            "already-stale findings must not be re-emitted"
        );
    }

    #[test]
    fn dismissed_finding_round_trips_and_stays_dismissed_after_disappearing() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        let fp_finding = semgrep_finding("demo.fp", 10, "false positive");
        let id = store.insert_finding("run-a", &fp_finding).unwrap();
        store
            .append_dismissal(
                id,
                DismissReason::UsedInTests,
                "only used in tests",
                "alice",
            )
            .unwrap();
        store.record_run_finished("run-a", "completed", 1).unwrap();

        let latest = store
            .latest_review_decision(id)
            .unwrap()
            .expect("dismissal decision");
        assert_eq!(
            latest.decision.dismiss_reason,
            Some(DismissReason::UsedInTests)
        );
        assert_eq!(latest.decision.actor.as_deref(), Some("alice"));
        assert_eq!(state_filter_count(&store, "state:dismissed"), 1);

        // The finding vanishes in a later semgrep run: it stays Dismissed,
        // never flips to Fixed/Removed.
        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-b", &semgrep_finding("demo.other", 20, "still here"))
            .unwrap();
        store.record_run_finished("run-b", "completed", 1).unwrap();

        assert_eq!(state_filter_count(&store, "state:dismissed"), 1);
        assert_eq!(state_filter_count(&store, "state:fixed"), 0);
        assert_eq!(state_filter_count(&store, "state:not_observed"), 0);
    }

    #[test]
    fn append_dismissal_rejects_empty_note() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = semgrep_finding("demo.x", 10, "finding");
        let id = store.insert_finding("run-a", &finding).unwrap();
        let result = store.append_dismissal(id, DismissReason::WontFix, "   ", "alice");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("note cannot be empty"));
    }

    fn confirmed_human_decision() -> ReviewDecision {
        ReviewDecision {
            verdict: ReviewDecisionVerdict::Confirmed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "verified reachable".to_string(),
            dismiss_reason: None,
            actor: None,
        }
    }

    #[test]
    fn scoped_same_tool_rerun_does_not_fabricate_removed() {
        // A confirmed/open finding in src/db must NOT show Fixed/Removed after a
        // semgrep re-run scoped to a *different* subdir (src/api).
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-a", &semgrep_finding("demo.db", 10, "sqli in src/db"))
            .unwrap();
        store.record_run_finished("run-a", "completed", 1).unwrap();

        // Same tool, but the run scanned only a subdir — different scope.
        store
            .record_run_started("run-b", Path::new("/tmp/repo/src/api"), "running")
            .unwrap();
        store
            .insert_finding(
                "run-b",
                &semgrep_finding("demo.api", 20, "issue in src/api"),
            )
            .unwrap();
        store.record_run_finished("run-b", "completed", 1).unwrap();

        assert_eq!(
            state_filter_count(&store, "state:not_observed"),
            0,
            "a subdir-scoped re-run must not stale out-of-scope findings"
        );
        assert_eq!(state_filter_count(&store, "state:fixed"), 0);
        assert_eq!(state_filter_count(&store, "state:open"), 2);
    }

    #[test]
    fn agentic_rehunt_never_marks_confirmed_finding_fixed() {
        // A non-deterministic engine (taint-iris-next) must NEVER retire a
        // finding: a re-hunt that happens not to re-surface a real bug is not
        // evidence the bug is fixed.
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("hunt-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        let real = Finding::new_tool(
            "taint-iris-next",
            "tin.sqli",
            "src/db.rs",
            10,
            Some(10),
            Severity::High,
            "confirmed sqli",
        );
        let id = store.insert_finding("hunt-a", &real).unwrap();
        store
            .append_user_review_decision(id, &confirmed_human_decision())
            .unwrap();
        store.record_run_finished("hunt-a", "completed", 1).unwrap();

        // Same target, same tool, but a flaky re-hunt returns a different flow.
        store
            .record_run_started("hunt-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding(
                "hunt-b",
                &Finding::new_tool(
                    "taint-iris-next",
                    "tin.xss",
                    "src/api.rs",
                    5,
                    Some(5),
                    Severity::Medium,
                    "different flow",
                ),
            )
            .unwrap();
        store.record_run_finished("hunt-b", "completed", 1).unwrap();

        assert_eq!(
            state_filter_count(&store, "state:fixed"),
            0,
            "agentic re-hunt must not fabricate Fixed"
        );
        assert_eq!(state_filter_count(&store, "state:confirmed"), 1);
    }

    #[test]
    fn auto_retriage_and_absence_preserve_human_confirmation() {
        // A human Confirmed followed by a later automated re-triage must not be
        // masked: disappearance does not erase the confirmation or establish a fix.
        let store = FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("run-a", Path::new("/tmp/repo"), "running")
            .unwrap();
        let id = store
            .insert_finding("run-a", &semgrep_finding("demo.real", 10, "confirmed bug"))
            .unwrap();
        store
            .append_user_review_decision(id, &confirmed_human_decision())
            .unwrap();
        store
            .record_triage_with_author(
                id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.5,
                    rationale: "automated re-triage".to_string(),
                    ..Default::default()
                },
                TriageAuthor::Auto,
            )
            .unwrap();
        store.record_run_finished("run-a", "completed", 1).unwrap();

        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-b", &semgrep_finding("demo.other", 20, "still here"))
            .unwrap();
        store.record_run_finished("run-b", "completed", 1).unwrap();

        assert_eq!(
            state_filter_count(&store, "state:fixed"),
            0,
            "human Confirm must survive a later automated re-triage"
        );
        assert_eq!(state_filter_count(&store, "state:not_observed"), 1);
        assert_eq!(state_filter_count(&store, "state:removed"), 0);
    }

    // ---- Reopen emitter + scan-to-scan comparison ----

    fn completed_run(store: &FindingStore, run_id: &str, findings: &[Finding]) {
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        for finding in findings {
            store.insert_finding(run_id, finding).unwrap();
        }
        store
            .record_run_finished(run_id, "completed", findings.len())
            .unwrap();
    }

    fn comparison_class_of(
        comparison: &ScanRunComparison,
        rule_fragment: &str,
    ) -> (ScanComparisonClass, Option<String>) {
        let row = comparison
            .findings
            .iter()
            .find(|row| row.title.contains(rule_fragment) || row.stable_key.contains(rule_fragment))
            .unwrap_or_else(|| panic!("no compared finding matching {rule_fragment}"));
        (row.class, row.reason.clone())
    }

    #[test]
    fn reobserving_a_stale_finding_records_a_durable_reopen() {
        let store = FindingStore::open_in_memory().unwrap();
        let bug = semgrep_finding("demo.reopen", 10, "vanishes then returns");
        completed_run(&store, "run-a", std::slice::from_ref(&bug));
        // run-b re-runs semgrep without the bug → reconciler marks it stale.
        completed_run(
            &store,
            "run-b",
            &[semgrep_finding("demo.other", 20, "still here")],
        );
        assert_eq!(state_filter_count(&store, "state:not_observed"), 1);

        // run-c observes the bug again → the reopen must be durable, not a
        // silent status flip.
        completed_run(
            &store,
            "run-c",
            &[bug, semgrep_finding("demo.other", 20, "still here")],
        );

        let reopened = store.reopened_stable_fps_for_run("run-c").unwrap();
        assert_eq!(reopened.len(), 1, "one durable FindingReopened event");
        assert_eq!(state_filter_count(&store, "state:not_observed"), 0);
        assert_eq!(state_filter_count(&store, "state:open"), 2);
    }

    #[test]
    fn comparison_classifies_new_persisting_resolved_and_reopened() {
        let store = FindingStore::open_in_memory().unwrap();
        let returning = semgrep_finding("demo.reopen", 10, "vanishes then returns");
        let persisting = semgrep_finding("demo.persist", 30, "still present");
        completed_run(
            &store,
            "run-a",
            &[
                returning.clone(),
                persisting.clone(),
                semgrep_finding("demo.gone", 40, "fixed later"),
            ],
        );
        completed_run(&store, "run-b", std::slice::from_ref(&persisting));
        completed_run(
            &store,
            "run-c",
            &[
                returning,
                persisting,
                semgrep_finding("demo.fresh", 50, "brand new"),
            ],
        );

        let comparison = compare_scan_runs(&store, "run-a", "run-c").unwrap();

        assert_eq!(comparison.base_status, "completed");
        assert_eq!(comparison.compare_status, "completed");
        assert_eq!(
            comparison_class_of(&comparison, "brand new").0,
            ScanComparisonClass::New
        );
        assert_eq!(
            comparison_class_of(&comparison, "still present").0,
            ScanComparisonClass::Persisting
        );
        assert_eq!(
            comparison_class_of(&comparison, "vanishes then returns").0,
            ScanComparisonClass::Reopened,
            "a finding the reconciler staled and run-c re-observed is reopened"
        );
        let (class, reason) = comparison_class_of(&comparison, "fixed later");
        assert_eq!(
            class,
            ScanComparisonClass::Resolved,
            "same-target completed deterministic re-scan proves absence ({reason:?})"
        );
    }

    /// The reopen key set belongs to the compare run, not to the pair. A
    /// finding the base run never observed must read as `New` there, otherwise
    /// the diff implies the base run had already seen (and lost) it.
    #[test]
    fn comparison_reports_new_not_reopened_when_the_base_run_never_observed_the_finding() {
        let store = FindingStore::open_in_memory().unwrap();
        let exercised = semgrep_finding("demo.other", 20, "keeps semgrep exercised");
        let late = semgrep_finding("demo.late", 10, "first seen after the base run");
        completed_run(&store, "run-a", std::slice::from_ref(&exercised));
        completed_run(&store, "run-b1", &[late.clone(), exercised.clone()]);
        // run-b2 re-runs semgrep without `late` → the reconciler stales it.
        completed_run(&store, "run-b2", std::slice::from_ref(&exercised));
        completed_run(&store, "run-c", &[late, exercised]);
        assert_eq!(
            store.reopened_stable_fps_for_run("run-c").unwrap().len(),
            1,
            "run-c must emit the durable FindingReopened this test hinges on"
        );

        let from_blind_base = compare_scan_runs(&store, "run-a", "run-c").unwrap();
        assert_eq!(
            comparison_class_of(&from_blind_base, "first seen after the base run").0,
            ScanComparisonClass::New,
            "run-a never observed this finding, so it cannot have reopened"
        );

        let from_observing_base = compare_scan_runs(&store, "run-b1", "run-c").unwrap();
        assert_eq!(
            comparison_class_of(&from_observing_base, "first seen after the base run").0,
            ScanComparisonClass::Reopened,
            "run-b1 observed it before the stale, so the pair is a real reopen"
        );
    }

    #[test]
    fn comparison_refuses_run_ids_with_no_recorded_history() {
        let store = FindingStore::open_in_memory().unwrap();
        completed_run(
            &store,
            "run-a",
            &[semgrep_finding("demo.only", 10, "the one recorded run")],
        );

        let error = compare_scan_runs(&store, "run-a", "run-ghost").unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("run-ghost"), "{message}");
        assert!(message.contains("kuzushi runs list"), "{message}");
        assert!(
            compare_scan_runs(&store, "run-ghost", "run-a").is_err(),
            "an unrecorded base id must fail just as loudly"
        );
    }

    #[test]
    fn comparison_never_resolves_findings_from_agentic_engines() {
        let store = FindingStore::open_in_memory().unwrap();
        let agentic = Finding::new_tool(
            "taint-iris",
            "flow.sqli",
            "src/app.ts",
            10,
            Some(10),
            Severity::High,
            "agent-hunted flow",
        );
        completed_run(&store, "run-a", &[agentic]);
        completed_run(
            &store,
            "run-b",
            &[semgrep_finding("demo.other", 20, "unrelated")],
        );

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();

        let (class, reason) = comparison_class_of(&comparison, "agent-hunted flow");
        assert_eq!(class, ScanComparisonClass::NotRescanned);
        let absent = comparison.findings.iter().find(|row| row.after.is_none()).unwrap();
        assert!(absent.reassessment_block.as_ref().unwrap().contains("unavailable"));
        assert!(
            reason.unwrap().contains("not a deterministic engine"),
            "reason must name the missing proof"
        );
    }

    #[test]
    fn comparison_never_resolves_against_an_uncompleted_compare_run() {
        let store = FindingStore::open_in_memory().unwrap();
        completed_run(
            &store,
            "run-a",
            &[semgrep_finding("demo.gone", 10, "was here")],
        );
        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding("run-b", &semgrep_finding("demo.other", 20, "unrelated"))
            .unwrap();
        store.record_run_finished("run-b", "failed", 1).unwrap();

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();

        let (class, reason) = comparison_class_of(&comparison, "was here");
        assert_eq!(class, ScanComparisonClass::NotRescanned);
        assert_eq!(reason.as_deref(), Some("compare run status is failed"));
    }

    #[test]
    fn comparison_never_resolves_when_the_engine_did_not_rerun() {
        let store = FindingStore::open_in_memory().unwrap();
        completed_run(
            &store,
            "run-a",
            &[semgrep_finding("demo.gone", 10, "semgrep saw this")],
        );
        let codeql = Finding::new_tool(
            "codeql",
            "cql.rule",
            "src/other.rs",
            5,
            Some(5),
            Severity::Medium,
            "codeql-only rescan",
        );
        completed_run(&store, "run-b", &[codeql]);

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();

        let (class, reason) = comparison_class_of(&comparison, "semgrep saw this");
        assert_eq!(class, ScanComparisonClass::NotRescanned);
        assert_eq!(
            reason.as_deref(),
            Some("no run evidence for engine semgrep in the compare scan")
        );
    }

    fn write_scan_scope_receipt(root: &Path, run_id: &str, paths: &[&str]) {
        write_scan_receipt(root, run_id, paths, &[]);
    }

    /// The durable Scan stage receipt a real scan leaves behind: the paths it
    /// examined plus each engine's outcome, which is the only evidence a clean
    /// engine re-run produces.
    fn write_scan_receipt(
        root: &Path,
        run_id: &str,
        paths: &[&str],
        engines: &[(&str, ScanEngineStageOutcome)],
    ) {
        use crate::run_artifacts::{
            PhaseStageOutcome, PhaseStageReceipt, ScanFindingDelta, ScanStageData, ScanStageEngine,
            ScanStagePlan, ScanStageScope,
        };
        let engine_stages = engines
            .iter()
            .map(|(engine, outcome)| ScanStageEngine {
                engine: (*engine).to_string(),
                outcome: *outcome,
                run_ref: None,
                detail: None,
            })
            .collect();
        let receipt = PhaseStageReceipt {
            phase: crate::WorkflowPhase::Scan,
            outcome: PhaseStageOutcome::Completed,
            run_refs: vec![run_id.to_string()],
            scan: Some(ScanStageData {
                scope: ScanStageScope {
                    target: "/tmp/repo".to_string(),
                    paths: paths.iter().map(|path| path.to_string()).collect(),
                },
                plan: ScanStagePlan {
                    selection: "explicit".to_string(),
                    engines: vec!["semgrep".to_string()],
                },
                engines: engine_stages,
                finding_delta: ScanFindingDelta::default(),
                severity_counts: Vec::new(),
                artifact_delta: Vec::new(),
                duration_ms: 0,
                cost: None,
                target_snapshot: crate::workflow_attempts::PhaseTargetSnapshot {
                    target: "/tmp/repo".to_string(),
                    revision: None,
                    dirty: false,
                },
            }),
        };
        let run_dir = root.join(".kuzushi/v3/runs").join(run_id);
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(
            run_dir.join("phase-stages.jsonl"),
            format!("{}\n", serde_json::to_string(&receipt).unwrap()),
        )
        .unwrap();
    }

    /// A real on-disk workspace store: the reconciler and the comparison reach
    /// run artifacts (run directories, Scan stage receipts) only through this
    /// root, so scope proof can be exercised end to end.
    fn workspace_store(root: &Path) -> FindingStore {
        let v3 = root.join(".kuzushi/v3");
        std::fs::create_dir_all(&v3).unwrap();
        FindingStore::open(v3.join("index.sqlite3")).unwrap()
    }

    fn canonical_root(workspace: &tempfile::TempDir) -> std::path::PathBuf {
        std::fs::canonicalize(workspace.path()).unwrap()
    }

    fn semgrep_finding_at(rule: &str, path: &str, title: &str) -> Finding {
        Finding::new_tool("semgrep", rule, path, 10, Some(10), Severity::High, title)
    }

    /// The honesty fix for path-restricted re-scans: a re-run recording
    /// `paths=["lib"]` in its Scan stage receipt re-examined only `lib/`, so
    /// it may retire a vanished finding in `lib/` but never one in `src/`.
    #[test]
    fn path_restricted_rescan_cannot_retire_findings_outside_its_paths() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let store = workspace_store(&root);

        let in_src = semgrep_finding_at("demo.src", "src/app.ts", "outside the rescan paths");
        let in_lib = semgrep_finding_at("demo.lib", "lib/util.ts", "inside the rescan paths");
        completed_run(&store, "run-a", &[in_src, in_lib]);

        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding(
                "run-b",
                &semgrep_finding_at("demo.other", "lib/other.ts", "keeps semgrep exercised"),
            )
            .unwrap();
        write_scan_scope_receipt(&root, "run-b", &["lib"]);
        store.record_run_finished("run-b", "completed", 1).unwrap();

        assert_eq!(
            state_filter_count(&store, "state:not_observed"),
            1,
            "only the lib/ finding has an observation gap"
        );
        assert_eq!(
            state_filter_count(&store, "state:open"),
            3,
            "absence never closes an unreviewed finding; src/ was not re-examined"
        );

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();
        let (class, reason) = comparison_class_of(&comparison, "outside the rescan paths");
        assert_eq!(class, ScanComparisonClass::NotRescanned);
        assert_eq!(
            reason.as_deref(),
            Some("finding path is outside the compare scan's paths")
        );
        let (class, _) = comparison_class_of(&comparison, "inside the rescan paths");
        assert_eq!(class, ScanComparisonClass::Resolved);
    }

    const SCOPE_UNKNOWN_REASON: &str =
        "compare run scope is unknown (run artifacts missing or unreadable)";

    /// A scoped re-run stays scoped even after `kz runs prune` deletes its
    /// artifacts: the observations survive the prune, so reading a missing run
    /// directory as "whole target" would fabricate a Resolved.
    #[test]
    fn pruning_the_compare_runs_artifacts_never_upgrades_a_scoped_rescan_to_whole_target() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let store = workspace_store(&root);
        let in_src = semgrep_finding_at("demo.src", "src/app.ts", "outside the rescan paths");
        completed_run(&store, "run-a", &[in_src]);

        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding(
                "run-b",
                &semgrep_finding_at("demo.other", "lib/other.ts", "keeps semgrep exercised"),
            )
            .unwrap();
        write_scan_scope_receipt(&root, "run-b", &["lib"]);
        store.record_run_finished("run-b", "completed", 1).unwrap();
        std::fs::remove_dir_all(crate::run_artifacts::run_dir(&root, "run-b")).unwrap();

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();

        let (class, reason) = comparison_class_of(&comparison, "outside the rescan paths");
        assert_eq!(class, ScanComparisonClass::NotRescanned);
        assert_eq!(reason.as_deref(), Some(SCOPE_UNKNOWN_REASON));
    }

    #[test]
    fn a_completed_run_directory_without_a_scan_receipt_still_means_whole_target() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let store = workspace_store(&root);
        completed_run(
            &store,
            "run-a",
            &[semgrep_finding_at("demo.gone", "src/app.ts", "vanished")],
        );

        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding(
                "run-b",
                &semgrep_finding_at("demo.other", "lib/other.ts", "keeps semgrep exercised"),
            )
            .unwrap();
        // A single-tool run materializes its directory but writes no Scan receipt.
        std::fs::create_dir_all(crate::run_artifacts::run_dir(&root, "run-b")).unwrap();
        store.record_run_finished("run-b", "completed", 1).unwrap();

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();

        let (class, reason) = comparison_class_of(&comparison, "vanished");
        assert_eq!(
            class,
            ScanComparisonClass::Resolved,
            "a receipt-less run directory means the whole target ({reason:?})"
        );
    }

    #[test]
    fn a_rescan_whose_run_artifacts_are_missing_retires_nothing() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let store = workspace_store(&root);
        completed_run(
            &store,
            "run-a",
            &[semgrep_finding_at("demo.gone", "src/app.ts", "vanished")],
        );

        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_finding(
                "run-b",
                &semgrep_finding_at("demo.other", "lib/other.ts", "keeps semgrep exercised"),
            )
            .unwrap();
        write_scan_scope_receipt(&root, "run-b", &[]);
        std::fs::remove_dir_all(crate::run_artifacts::run_dir(&root, "run-b")).unwrap();
        store.record_run_finished("run-b", "completed", 1).unwrap();

        assert_eq!(
            state_filter_count(&store, "state:not_observed"),
            0,
            "a re-run with no surviving artifacts proves no absence"
        );
        assert_eq!(state_filter_count(&store, "state:open"), 2);
    }

    /// A re-run that finds nothing leaves no observation, so the Scan receipt's
    /// engine outcomes are the only evidence the engine ran at all. Without them
    /// the flagship clean re-scan would read as "the engine never ran".
    fn clean_semgrep_rerun(root: &Path, store: &FindingStore, outcome: ScanEngineStageOutcome) {
        completed_run(
            store,
            "run-a",
            &[semgrep_finding_at(
                "demo.gone",
                "src/app.ts",
                "vanished in a clean rerun",
            )],
        );
        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        write_scan_receipt(root, "run-b", &[], &[("semgrep", outcome)]);
        store.record_run_finished("run-b", "completed", 0).unwrap();
    }

    #[test]
    fn a_clean_engine_rerun_recorded_in_the_scan_receipt_resolves_its_vanished_findings() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let store = workspace_store(&root);
        clean_semgrep_rerun(&root, &store, ScanEngineStageOutcome::Complete);

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();

        let (class, reason) = comparison_class_of(&comparison, "vanished in a clean rerun");
        assert_eq!(
            class,
            ScanComparisonClass::Resolved,
            "a completed engine stage is evidence it ran ({reason:?})"
        );
    }

    #[test]
    fn a_clean_engine_rerun_records_absence_without_closing_the_finding() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let store = workspace_store(&root);
        clean_semgrep_rerun(&root, &store, ScanEngineStageOutcome::Complete);

        assert_eq!(state_filter_count(&store, "state:not_observed"), 1);
        assert_eq!(state_filter_count(&store, "state:open"), 1);
    }

    #[test]
    fn a_failed_engine_outcome_in_the_receipt_is_not_proof_the_engine_ran() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let store = workspace_store(&root);
        clean_semgrep_rerun(&root, &store, ScanEngineStageOutcome::Failed);

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();

        let (class, reason) = comparison_class_of(&comparison, "vanished in a clean rerun");
        assert_eq!(class, ScanComparisonClass::NotRescanned);
        assert_eq!(
            reason.as_deref(),
            Some("no run evidence for engine semgrep in the compare scan")
        );
        assert_eq!(
            state_filter_count(&store, "state:open"),
            1,
            "a failed engine stage retires nothing"
        );
    }

    /// Deduplication merges the tools of coalesced observations into one
    /// comma-joined string, so absence is only proven when every component
    /// engine is deterministic AND re-ran.
    fn merged_tool_rescan(
        root: &Path,
        store: &FindingStore,
        tool: &str,
        engines: &[(&str, ScanEngineStageOutcome)],
    ) {
        let mut finding = semgrep_finding_at("demo.merged", "src/app.ts", "merged tool finding");
        finding.tool = tool.to_string();
        completed_run(store, "run-a", &[finding]);
        store
            .record_run_started("run-b", Path::new("/tmp/repo"), "running")
            .unwrap();
        write_scan_receipt(root, "run-b", &[], engines);
        store.record_run_finished("run-b", "completed", 0).unwrap();
    }

    #[test]
    fn merged_tool_findings_resolve_only_when_every_component_engine_reran() {
        let complete = tempfile::tempdir().unwrap();
        let root = canonical_root(&complete);
        let store = workspace_store(&root);
        merged_tool_rescan(
            &root,
            &store,
            "codeql,semgrep",
            &[
                ("codeql", ScanEngineStageOutcome::Complete),
                ("semgrep", ScanEngineStageOutcome::Complete),
            ],
        );

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();
        let (class, reason) = comparison_class_of(&comparison, "merged tool finding");
        assert_eq!(class, ScanComparisonClass::Resolved, "{reason:?}");
        assert_eq!(state_filter_count(&store, "state:not_observed"), 1);

        let partial = tempfile::tempdir().unwrap();
        let root = canonical_root(&partial);
        let store = workspace_store(&root);
        merged_tool_rescan(
            &root,
            &store,
            "codeql,semgrep",
            &[("semgrep", ScanEngineStageOutcome::Complete)],
        );

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();
        let (class, reason) = comparison_class_of(&comparison, "merged tool finding");
        assert_eq!(class, ScanComparisonClass::NotRescanned);
        assert_eq!(
            reason.as_deref(),
            Some("no run evidence for engine codeql in the compare scan")
        );
        assert_eq!(state_filter_count(&store, "state:open"), 1);
    }

    #[test]
    fn a_merged_tool_with_an_agentic_component_never_retires_a_finding() {
        let workspace = tempfile::tempdir().unwrap();
        let root = canonical_root(&workspace);
        let store = workspace_store(&root);
        merged_tool_rescan(
            &root,
            &store,
            "semgrep,taint-iris",
            &[
                ("semgrep", ScanEngineStageOutcome::Complete),
                ("taint-iris", ScanEngineStageOutcome::Complete),
            ],
        );

        let comparison = compare_scan_runs(&store, "run-a", "run-b").unwrap();

        let (class, reason) = comparison_class_of(&comparison, "merged tool finding");
        assert_eq!(class, ScanComparisonClass::NotRescanned);
        assert_eq!(
            reason.as_deref(),
            Some("taint-iris is not a deterministic engine; absence is not proof")
        );
        assert_eq!(
            state_filter_count(&store, "state:open"),
            1,
            "one agentic component keeps the merged finding open"
        );
    }
}
