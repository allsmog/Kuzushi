#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::{Finding, FindingStore, Severity};

    #[test]
    fn indexes_known_artifacts_findings_and_searches_offline() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::run_artifacts::run_dir(tmp.path(), "run-1")).unwrap();
        fs::create_dir_all(tmp.path().join("x-ray")).unwrap();
        fs::write(
            crate::context::context_snapshot_path(tmp.path()),
            r#"{"repoContext":{"language":"rust"},"notes":"payment routing"}"#,
        )
        .unwrap();
        fs::write(
            crate::capabilities::persistent_threat_model_path(tmp.path()),
            r#"{"dfd":{"nodes":[{"name":"payments api"}]},"threats":["trust boundary"]}"#,
        )
        .unwrap();
        fs::write(
            tmp.path().join("x-ray/x-ray.md"),
            "# X-Ray\n\nPayment entry point reaches ledger writer.\n",
        )
        .unwrap();
        fs::write(
            crate::run_artifacts::run_dir(tmp.path(), "run-1").join("run.json"),
            r#"{"ok":true,"data":{"carliniThreatHunt":{"count":1}}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let findings = FindingStore::open(workspace.findings_db_path()).unwrap();
        findings
            .record_run_started("scan-1", workspace.root(), "completed")
            .unwrap();
        findings
            .insert_finding(
                "scan-1",
                &Finding::new_tool(
                    "carlini-threat-hunt",
                    "carlini/payment-xss",
                    "src/app.ts",
                    42,
                    None,
                    Severity::High,
                    "Actor-controlled payment name reaches HTML response",
                ),
            )
            .unwrap();
        findings
            .record_run_finished("scan-1", "completed", 1)
            .unwrap();

        let report = index_workspace_artifacts(&workspace).unwrap();

        assert_eq!(
            report.db_path,
            crate::workspace::workspace_artifact_kb_db_path(workspace.root())
                .display()
                .to_string()
        );
        assert!(report.indexed >= 5);
        let search = search_artifact_knowledge(&workspace, "payment actor", 10).unwrap();
        assert!(!search.missing_db);
        assert!(search.results.iter().any(|result| {
            result.record.module_id == "carlini-threat-hunt"
                && result.record.source_path.contains("index.sqlite3#finding")
                && result.record.refs == ["src/app.ts:42"]
        }));
        assert!(search
            .results
            .iter()
            .any(|result| result.record.module_id == "x-ray"));
    }

    #[test]
    fn reindex_updates_existing_source_record() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        fs::create_dir_all(crate::workspace::workspace_state_root(workspace.root())).unwrap();
        let source = crate::context::context_snapshot_path(workspace.root());
        fs::write(&source, r#"{"notes":"alpha service"}"#).unwrap();

        index_workspace_artifacts(&workspace).unwrap();
        fs::write(&source, r#"{"notes":"beta service"}"#).unwrap();
        index_workspace_artifacts(&workspace).unwrap();

        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        let source_path = relative_workspace_path(workspace.root(), &source);
        let records = store.records_for_source(&source_path).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].body.contains("beta service"));
        assert_eq!(store.search("alpha", 10).unwrap().len(), 0);
        assert_eq!(store.search("beta", 10).unwrap().len(), 1);
    }

    #[test]
    fn bounded_refresh_skips_unchanged_sources_without_timestamp_churn() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        fs::create_dir_all(crate::workspace::workspace_state_root(workspace.root())).unwrap();
        let source = crate::context::context_snapshot_path(workspace.root());
        fs::write(&source, r#"{"notes":"alpha"}"#).unwrap();

        let first = refresh_workspace_artifacts(&workspace).unwrap();
        assert_eq!(first.indexed, 1);
        assert!(!first.partial);
        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        store
            .conn
            .execute("update artifact_kb_records set indexed_at_unix = 7", [])
            .unwrap();

        let unchanged = refresh_workspace_artifacts(&workspace).unwrap();
        let source_path = relative_workspace_path(workspace.root(), &source);
        let records = store.records_for_source(&source_path).unwrap();
        assert_eq!(unchanged.indexed, 0);
        assert_eq!(unchanged.unchanged, 1);
        assert_eq!(records[0].indexed_at_unix, 7);

        fs::write(&source, r#"{"notes":"beta service"}"#).unwrap();
        let changed = refresh_workspace_artifacts(&workspace).unwrap();
        let records = store.records_for_source(&source_path).unwrap();
        assert_eq!(changed.indexed, 1);
        assert!(records[0].body.contains("beta service"));
    }

    #[test]
    fn changed_source_identity_removes_orphan_record_and_fts_row() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let run_dir = crate::run_artifacts::run_dir(workspace.root(), "run-1");
        fs::create_dir_all(&run_dir).unwrap();
        let source = run_dir.join("run.json");
        fs::write(&source, r#"{"xRay":"old unique marker"}"#).unwrap();

        index_workspace_artifacts(&workspace).unwrap();
        fs::write(&source, r#"{"carliniThreatHunt":"new marker"}"#).unwrap();
        index_workspace_artifacts(&workspace).unwrap();

        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        let records = store
            .records_for_source(&relative_workspace_path(workspace.root(), &source))
            .unwrap();
        let paths = store
            .conn
            .prepare("select source_path from artifact_kb_records order by source_path")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 1, "indexed paths: {paths:?}");
        assert_eq!(records[0].module_id, "carlini-threat-hunt");
        assert!(store.search("old unique", 10).unwrap().is_empty());
    }

    #[test]
    fn stale_records_report_changed_source_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        fs::create_dir_all(crate::workspace::workspace_state_root(workspace.root())).unwrap();
        let source = crate::capabilities::persistent_threat_model_path(workspace.root());
        fs::write(&source, r#"{"threats":["old"]}"#).unwrap();
        index_workspace_artifacts(&workspace).unwrap();
        fs::write(&source, r#"{"threats":["new"]}"#).unwrap();

        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        let stale = store.stale_records(&workspace).unwrap();

        assert_eq!(stale.len(), 1);
        assert_eq!(
            stale[0].record.source_path,
            relative_workspace_path(workspace.root(), &source)
        );
        assert_ne!(
            stale[0].current_hash.as_deref(),
            Some(stale[0].record.content_hash.as_str())
        );
    }

    #[test]
    fn stale_records_never_read_absolute_or_oversized_sources() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let oversized = workspace.root().join("oversized.txt");
        fs::File::create(&oversized)
            .unwrap()
            .set_len(65 * 1024 * 1024)
            .unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        for source in [
            outside.path().display().to_string(),
            "oversized.txt".to_string(),
        ] {
            store
                .upsert_record(&ArtifactKnowledgeRecord::from_body(
                    source.as_str(),
                    "context",
                    None,
                    "adversarial source",
                    "body",
                    Vec::new(),
                    json!({}),
                ))
                .unwrap();
        }

        let stale = store.stale_records(&workspace).unwrap();

        assert_eq!(stale.len(), 2);
        assert!(stale.iter().all(|record| record.current_hash.is_none()));
    }

    #[test]
    fn current_staleness_and_prompt_queries_do_not_select_record_body() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        fs::create_dir_all(crate::workspace::workspace_state_root(workspace.root())).unwrap();
        let source = crate::context::context_snapshot_path(workspace.root());
        fs::write(&source, r#"{"notes":"payment ledger"}"#).unwrap();
        refresh_workspace_artifacts(&workspace).unwrap();
        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        store
            .conn
            .execute("update artifact_kb_records set body = zeroblob(1024)", [])
            .unwrap();

        assert!(store.stale_records(&workspace).unwrap().is_empty());
        let context = artifact_knowledge_prompt_context(&workspace, "payment ledger", 3);
        assert_eq!(context.snippets.len(), 1);
    }

    #[test]
    fn opening_a_legacy_kb_adds_incremental_refresh_tables() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("legacy.sqlite3");
        let conn = Connection::open(&path).unwrap();
        conn.execute("create table legacy_marker(value text)", [])
            .unwrap();
        drop(conn);

        let store = ArtifactKnowledgeStore::open_path(&path).unwrap();

        for table in [
            "artifact_kb_source_state",
            "artifact_kb_checkpoints",
            "artifact_kb_state",
            "artifact_kb_finding_quarantine",
        ] {
            assert!(sqlite_table_exists(&store.conn, table).unwrap());
        }
    }

    #[test]
    fn bounded_refresh_does_not_rebuild_a_missing_run_history_index() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = crate::run_artifacts::RunSummary::running(
            "run-current",
            "tool",
            Some("x-ray:run".to_string()),
            tmp.path().display().to_string(),
        )
        .complete();
        crate::run_artifacts::write_run_summary(tmp.path(), &summary).unwrap();
        let index = crate::run_artifacts::checked_run_history_index_path(tmp.path()).unwrap();
        fs::remove_file(&index).unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let report = refresh_workspace_artifacts(&workspace).unwrap();

        assert!(report.partial);
        assert!(!index.exists());
    }

    #[test]
    fn search_missing_db_returns_empty_report_without_creating_it() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let path = artifact_kb_path(&workspace);

        let report = search_artifact_knowledge(&workspace, "anything", 10).unwrap();

        assert!(report.missing_db);
        assert!(report.results.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn prompt_context_renders_missing_and_matching_snippets() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let missing = artifact_knowledge_prompt_context(&workspace, "payment route", 3);
        assert!(missing.missing_db);
        assert!(missing.status.contains("missing local artifact KB"));
        assert!(missing.render_prompt_block().contains("Snippets: none"));

        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        store
            .upsert_record(&ArtifactKnowledgeRecord::from_body(
                "manual://operator-note",
                "x-ray",
                Some("run-7".to_string()),
                "operator note",
                "Payment route reaches ledger writer through the public deposit entry point.",
                vec!["src/routes.ts:12".to_string()],
                json!({"sourceKind": "manual-test"}),
            ))
            .unwrap();

        let context = artifact_knowledge_prompt_context(&workspace, "payment ledger", 3);
        assert!(!context.missing_db);
        assert_eq!(context.snippets.len(), 1);
        let block = context.render_prompt_block();
        assert!(block.contains("available, 1 matching snippet"));
        assert!(block.contains("[x-ray] operator note"));
        assert!(block.contains("src/routes.ts:12"));
    }

    #[test]
    fn in_memory_store_indexes_and_searches_record() {
        let store = ArtifactKnowledgeStore::open_in_memory().unwrap();
        let record = ArtifactKnowledgeRecord::from_body(
            "manual://operator-note",
            "context",
            None,
            "operator note",
            "GraphQL resolver uses payment scope",
            vec!["src/schema.ts:12".to_string()],
            json!({"sourceKind": "manual-test"}),
        );

        store.upsert_record(&record).unwrap();

        let results = store.search("graphql payment", 5).unwrap();
        assert_eq!(store.count_records().unwrap(), 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].record.id, record.id);
    }
}
