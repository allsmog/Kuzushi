#[cfg(test)]
mod tests {
    use super::super::domain::{
        compute_finding_identity_id, finding_identity_key_for_finding, FindingEvidence,
    };
    use super::super::persistence::merge_tool_list;
    use super::super::*;
    use crate::run_artifacts::{RunSummary, RunTargetGitMetadata};
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
        assert_eq!(listed.len(), 2);
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
            events[3].payload["identityMatchBasis"].as_str(),
            Some("stable_fp")
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

    #[cfg(unix)]
    #[test]
    fn file_backed_insert_omits_provenance_for_outside_symlink() {
        const OUTSIDE_TOKEN: &str = "OUTSIDE-REQUIREMENTS-TOKEN-MUST-NOT-PERSIST";
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let workspace_root = workspace.path().canonicalize().unwrap();
        let outside_file = outside.path().join("requirements.txt");
        std::fs::write(&outside_file, OUTSIDE_TOKEN).unwrap();
        std::os::unix::fs::symlink(
            &outside_file,
            workspace_root.join("requirements.txt"),
        )
        .unwrap();
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
        assert!(!serde_json::to_string(&events).unwrap().contains(OUTSIDE_TOKEN));
        assert!(!serde_json::to_string(&store.list_findings_for_scan_id(run_id).unwrap())
            .unwrap()
            .contains(OUTSIDE_TOKEN));
        assert!(!crate::workspace::workspace_objects_dir(&workspace_root).exists());
        assert_eq!(std::fs::read_to_string(outside_file).unwrap(), OUTSIDE_TOKEN);
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
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.95,
                    rationale: "operator confirmed source-to-sink evidence".to_string(),
                    ..Default::default()
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
                cost_usd: Some(0.25),
                validator_log: Some("tests passed".to_string()),
                history: vec![PatchAttempt {
                    attempt: 1,
                    diff: "diff".to_string(),
                    status: PatchStatus::Sound,
                    output: "ok".to_string(),
                }],
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

        let conn = rusqlite::Connection::open(db_path).unwrap();
        let projected: (String, String, String, i64) = conn
            .query_row(
                "select stable_fp, patch_run_id, diff_object, diff_size_bytes from patch_attempt_events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(projected.0, stable_fp);
        assert_eq!(projected.1, "patch-run-v3");
        assert!(projected.2.len() >= 4);
        assert_eq!(projected.3, "diff --git a/src/app.rs b/src/app.rs\n".len() as i64);
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
            assert!(error.contains("symlink") || error.contains("non-symlink"), "{error}");
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
            verdict: TriageVerdict::FalsePositive,
            confidence: 0.8,
            rationale: "model signal did not match reachable code".to_string(),
            cost_usd: 0.12,
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
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-evidence";
        store
            .record_run_started(run_id, Path::new("/tmp/repo"), "running")
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
            crash_evidence: Some("runtime fixture recorded marker".to_string()),
            duration_ms: 321,
            cost_usd: 0.0,
            notes: vec!["browser fixture recorded runtime evidence".to_string()],
            verification_run_id: None,
            verified_scan_id: None,
            created_at: "now".to_string(),
        });

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

        let verification = PersistedVerification {
            proof_level: 4,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Bwrap,
            language: Some("javascript".to_string()),
            harness_path: None,
            crash_evidence: None,
            duration_ms: 321,
            cost_usd: 0.0,
            notes: Vec::new(),
            verification_run_id: None,
            verified_scan_id: None,
            created_at: "now".to_string(),
        };
        let verified = runtime_validation_summary(Some(&verification));
        assert_eq!(verified.label, "verified L4");
        assert!(verified.explanation.contains("empirical evidence"));
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

        finding.verification = Some(PersistedVerification {
            proof_level: 4,
            proof_verdict: PersistedProofVerdict::Exploited,
            backend: PersistedSandboxBackend::Bwrap,
            language: Some("javascript".to_string()),
            harness_path: None,
            crash_evidence: None,
            duration_ms: 321,
            cost_usd: 0.0,
            notes: Vec::new(),
            verification_run_id: None,
            verified_scan_id: None,
            created_at: "now".to_string(),
        });
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
            verdict: TriageVerdict::TruePositive,
            confidence: 0.72,
            rationale: "source reaches sink".to_string(),
            cost_usd: 0.0,
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
        finding.set_static_proof_state(StaticProofState::SourceSinkLinked);
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "reviewed source-linked evidence".to_string(),
            cost_usd: 0.0,
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
            count: 1,
            findings: vec![finding],
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
        assert_eq!(
            fetched.verification_run_id.as_deref(),
            Some("verify-run-roundtrip")
        );
        assert_eq!(fetched.verified_scan_id.as_deref(), Some("run-v1"));
        assert!(!fetched.created_at.is_empty());
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
            verdict: TriageVerdict::TruePositive,
            confidence: 0.5,
            rationale: "synthetic".to_string(),
            cost_usd: 0.0,
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
    fn rescan_marks_vanished_finding_removed_when_tool_reran() {
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

        assert_eq!(state_filter_count(&store, "state:removed"), 1);
        assert_eq!(state_filter_count(&store, "state:fixed"), 0);
    }

    #[test]
    fn rescan_marks_confirmed_finding_fixed() {
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

        assert_eq!(state_filter_count(&store, "state:fixed"), 1);
        assert_eq!(state_filter_count(&store, "state:removed"), 0);
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

        assert_eq!(state_filter_count(&store, "state:removed"), 0);
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

        assert_eq!(state_filter_count(&store, "state:removed"), 0);
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
        assert_eq!(state_filter_count(&store, "state:removed"), 0);
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
            state_filter_count(&store, "state:removed"),
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
    fn auto_retriage_after_human_confirm_still_yields_fixed() {
        // A human Confirmed followed by a later automated re-triage must not be
        // masked: on same-scope disappearance the finding is Fixed, not Removed.
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
            1,
            "human Confirm must survive a later automated re-triage"
        );
        assert_eq!(state_filter_count(&store, "state:removed"), 0);
    }
}
