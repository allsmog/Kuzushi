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
                && result
                    .record
                    .source_path
                    .contains("index.sqlite3#finding")
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
