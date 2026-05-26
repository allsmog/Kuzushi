#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::*;

    #[test]
    fn static_evidence_kind_names_match_whitebox_spec() {
        let node_names = STATIC_EVIDENCE_NODE_KINDS
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            node_names,
            vec![
                "code_span",
                "scanner_signal",
                "source",
                "sink",
                "dataflow_step",
                "sanitizer",
                "guard",
                "attack_surface",
                "triage_claim",
                "report_claim",
            ]
        );
        for name in node_names {
            assert_eq!(
                StaticEvidenceNodeKind::try_from(name).unwrap().as_str(),
                name
            );
        }

        let edge_names = STATIC_EVIDENCE_EDGE_KINDS
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            edge_names,
            vec![
                "supports",
                "derived_from",
                "flows_to",
                "guarded_by",
                "sanitized_by",
                "contradicts",
                "reported_as",
            ]
        );
        for name in edge_names {
            assert_eq!(
                StaticEvidenceEdgeKind::try_from(name).unwrap().as_str(),
                name
            );
        }
    }

    #[test]
    fn static_evidence_store_inserts_fetches_and_links_nodes() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let code_span = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::CodeSpan,
            "route handler span",
            "const name = req.query.name;",
        )
        .with_finding_fingerprint("finding-1")
        .with_source_span("src/routes.ts", 12, Some(12))
        .with_metadata(json!({"language": "typescript"}));
        let scanner_signal = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::ScannerSignal,
            "semgrep express xss",
            "express-xss flagged src/routes.ts:12",
        )
        .with_finding_fingerprint("finding-1")
        .with_metadata(json!({"tool": "semgrep", "ruleId": "express-xss"}));

        store.upsert_node(&code_span).unwrap();
        store.upsert_node(&scanner_signal).unwrap();

        let fetched_span = store.get_node(&code_span.id).unwrap().unwrap();
        assert_eq!(fetched_span, code_span);
        assert_eq!(
            fetched_span.content_hash,
            static_content_hash(&fetched_span.body)
        );
        assert_eq!(store.list_nodes_for_finding("finding-1").unwrap().len(), 2);

        let edge = StaticEvidenceEdge::new(
            StaticEvidenceEdgeKind::DerivedFrom,
            scanner_signal.id.clone(),
            code_span.id.clone(),
        )
        .with_finding_fingerprint("finding-1")
        .with_metadata(json!({"normalizer": "semgrep"}));
        store.upsert_edge(&edge).unwrap();

        assert_eq!(store.get_edge(&edge.id).unwrap().unwrap(), edge);
        assert_eq!(store.edges_for_node(&code_span.id).unwrap(), vec![edge]);
    }

    #[test]
    fn static_evidence_hashes_are_stable_and_body_sensitive() {
        let first = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Source,
            "request source",
            "req.query.name",
        )
        .with_finding_fingerprint("finding-2")
        .with_source_span("src/routes.ts", 8, Some(8))
        .with_metadata(json!({"framework": "express"}));
        let same = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Source,
            "request source",
            "req.query.name",
        )
        .with_finding_fingerprint("finding-2")
        .with_source_span("src/routes.ts", 8, Some(8))
        .with_metadata(json!({"framework": "express"}));
        let changed_body = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Source,
            "request source",
            "req.body.name",
        )
        .with_finding_fingerprint("finding-2")
        .with_source_span("src/routes.ts", 8, Some(8))
        .with_metadata(json!({"framework": "express"}));

        assert_eq!(first.id, same.id);
        assert_eq!(first.content_hash, same.content_hash);
        assert_ne!(first.id, changed_body.id);
        assert_ne!(first.content_hash, changed_body.content_hash);

        let first_edge =
            StaticEvidenceEdge::new(StaticEvidenceEdgeKind::FlowsTo, first.id.clone(), "sink-1")
                .with_finding_fingerprint("finding-2");
        let same_edge =
            StaticEvidenceEdge::new(StaticEvidenceEdgeKind::FlowsTo, first.id.clone(), "sink-1")
                .with_finding_fingerprint("finding-2");
        let changed_edge = StaticEvidenceEdge::new(
            StaticEvidenceEdgeKind::GuardedBy,
            first.id.clone(),
            "sink-1",
        )
        .with_finding_fingerprint("finding-2");

        assert_eq!(first_edge.id, same_edge.id);
        assert_ne!(first_edge.id, changed_edge.id);
    }

    #[test]
    fn static_evidence_store_uses_workspace_v2_path() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = StaticEvidenceStore::open(&workspace).unwrap();

        assert_eq!(
            store.db_path(),
            crate::workspace::workspace_static_evidence_db_path(workspace.root())
                .to_string_lossy()
        );
        assert!(static_evidence_path(&workspace).exists());
    }

    #[test]
    fn static_evidence_store_rejects_unhashed_or_mutated_source_evidence() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let mut node = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::CodeSpan,
            "route handler span",
            "const name = req.query.name;",
        );
        node.body = "const name = req.body.name;".to_string();

        let error = store.upsert_node(&node).unwrap_err().to_string();

        assert!(error.contains("content hash does not match body hash"));
    }

    #[test]
    fn semgrep_static_evidence_indexes_signal_and_code_span_without_true_positive_default() {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("routes.ts"),
            "import express from 'express';\nres.send(req.query.name);\n",
        )
        .unwrap();
        let finding = Finding::new_semgrep(
            "javascript.express.security.audit.xss",
            "src/routes.ts",
            2,
            Some(2),
            crate::findings::Severity::High,
            "Detected unescaped user input",
        );
        let fingerprint = finding.fingerprint.clone();
        let store = StaticEvidenceStore::open_in_memory().unwrap();

        let report =
            index_semgrep_findings_as_static_evidence(&store, temp.path(), &[finding]).unwrap();

        assert_eq!(report.findings_indexed, 1);
        assert_eq!(report.nodes_indexed, 2);
        assert_eq!(report.edges_indexed, 1);

        let nodes = store.list_nodes_for_finding(&fingerprint).unwrap();
        assert_eq!(nodes.len(), 2);
        let code_span = nodes
            .iter()
            .find(|node| node.kind == StaticEvidenceNodeKind::CodeSpan)
            .unwrap();
        let signal = nodes
            .iter()
            .find(|node| node.kind == StaticEvidenceNodeKind::ScannerSignal)
            .unwrap();

        assert_eq!(code_span.source_path.as_deref(), Some("src/routes.ts"));
        assert_eq!(code_span.body, "res.send(req.query.name);");
        assert_eq!(
            signal
                .metadata
                .pointer("/staticProofState")
                .and_then(Value::as_str),
            Some("signal_only")
        );
        assert_eq!(
            signal
                .metadata
                .pointer("/truePositiveByDefault")
                .and_then(Value::as_bool),
            Some(false)
        );

        let edges = store.edges_for_node(&code_span.id).unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, StaticEvidenceEdgeKind::DerivedFrom);
        assert_eq!(edges[0].from_node_id, signal.id);
        assert_eq!(edges[0].to_node_id, code_span.id);
        assert_eq!(
            edges[0]
                .metadata
                .pointer("/truePositiveByDefault")
                .and_then(Value::as_bool),
            Some(false)
        );
    }
}
