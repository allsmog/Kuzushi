#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::*;
    use crate::attack_surface::{AttackSurfaceMap, AttackSurfaceRisk, AttackSurfaceSummary};
    use crate::findings::{TriageOutcome, TriageVerdict};
    use crate::static_evidence::{StaticEvidenceEdge, StaticEvidenceEdgeKind};

    #[test]
    fn static_ranking_high_impact_static_flow_outranks_generic_scanner_noise() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let mut static_flow = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/routes.ts",
            12,
            Some(30),
            Severity::Medium,
            "Source: req.query.userId\nSink: db.query(sql)\nSanitizer assessment: absent\nGuard assessment: absent\nConfidence: high\nCode flow: src/routes.ts:12 -> src/db.ts:30",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        static_flow.triage = Some(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.78,
            rationale: "static source-to-sink evidence".to_string(),
            ..Default::default()
        });
        let generic_noise = Finding::new_semgrep(
            "generic.best-practice.no-console",
            "src/util.ts",
            4,
            Some(4),
            Severity::Critical,
            "Generic lint noise: console statement.",
        )
        .with_static_proof_state(StaticProofState::SignalOnly);

        insert_flow_evidence(&store, &static_flow);
        let attack_surface = route_and_sink_surface();

        let ranked = rank_static_findings(
            &[generic_noise.clone(), static_flow.clone()],
            Some(&attack_surface),
            Some(&store),
        )
        .unwrap();

        assert_eq!(ranked[0].fingerprint, static_flow.fingerprint);
        assert_eq!(ranked[1].fingerprint, generic_noise.fingerprint);
        assert!(ranked[0].impact.total > ranked[1].impact.total);
        assert!(ranked[0].impact.factors.attack_surface_reachability > 0);
        assert!(ranked[0].impact.factors.source_sink_class > 0);
        assert!(ranked[0].impact.factors.data_sensitivity > 0);
        assert!(ranked[0].impact.factors.privilege_boundary > 0);
        assert!(ranked[0].impact.factors.sanitizer_absence > 0);
        assert!(ranked[0].impact.factors.framework_context > 0);
        assert!(ranked[0].impact.factors.codeql_flow_quality > 0);
        assert!(ranked[0].impact.factors.confidence > 0);
        assert!(ranked[1].impact.factors.noise_adjustment < 0);
    }

    #[test]
    fn static_ranking_is_deterministic_for_equal_scores() {
        let first = Finding::new_tool(
            "semgrep",
            "generic.rule",
            "src/a.ts",
            3,
            Some(3),
            Severity::Low,
            "generic signal",
        );
        let second = Finding::new_tool(
            "semgrep",
            "generic.rule",
            "src/b.ts",
            3,
            Some(3),
            Severity::Low,
            "generic signal",
        );

        let one = rank_static_findings(&[second.clone(), first.clone()], None, None).unwrap();
        let two = rank_static_findings(&[first.clone(), second.clone()], None, None).unwrap();

        let one_order = one
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<Vec<_>>();
        let two_order = two
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<Vec<_>>();
        assert_eq!(one_order, two_order);
        assert_eq!(one_order[0], first.fingerprint);
    }

    #[test]
    fn static_ranking_downranks_sanitized_or_rejected_findings() {
        let sanitized = Finding::new_tool(
            "agentic",
            "validated-input",
            "src/routes.ts",
            10,
            Some(10),
            Severity::High,
            "Sanitizer assessment: present\nInput is sanitized before the sink.",
        )
        .with_static_proof_state(StaticProofState::StaticallyRejected);
        let unsanitized = Finding::new_tool(
            "agentic",
            "missing-validation",
            "src/routes.ts",
            11,
            Some(11),
            Severity::Medium,
            "Sanitizer assessment: absent\nreq.body.password reaches db.query.",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);

        let ranked = rank_static_findings(&[sanitized, unsanitized.clone()], None, None).unwrap();

        assert_eq!(ranked[0].fingerprint, unsanitized.fingerprint);
        assert!(ranked[1].impact.total < 0);
    }

    #[test]
    fn static_ranking_uses_threat_model_priority() {
        let threat_linked = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/routes.ts",
            12,
            Some(12),
            Severity::Medium,
            "CWE-89 sql injection reaches tenant database query",
        )
        .with_static_proof_state(StaticProofState::CodeCited);
        let generic = Finding::new_tool(
            "semgrep",
            "generic.warning",
            "src/other.ts",
            4,
            Some(4),
            Severity::High,
            "generic best practice warning",
        );
        let threat_model = json!({
            "version": "2.0",
            "dfd": {"nodes": [], "flows": [], "trustBoundaries": []},
            "summary": {},
            "threats": [{
                "id": "TM-001",
                "category": "injection",
                "title": "Tenant SQL injection",
                "description": "attacker controls tenant database query",
                "impact": "high",
                "relatedCwe": ["CWE-89"],
                "affectedFiles": [{"filePath": "src/routes.ts"}]
            }]
        });

        let ranked = rank_static_findings_with_threats(
            &[generic.clone(), threat_linked.clone()],
            None,
            None,
            Some(&threat_model),
        )
        .unwrap();

        assert_eq!(ranked[0].fingerprint, threat_linked.fingerprint);
        assert!(ranked[0].impact.factors.threat_model_priority > 0);
        assert!(ranked[0]
            .impact
            .reasons
            .iter()
            .any(|reason| reason == "threat_model_priority=TM-001"));
    }

    #[test]
    fn degraded_static_ranking_records_malformed_evidence_without_aborting() {
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "generic.rule",
            "src/app.rs",
            7,
            Some(7),
            Severity::Medium,
            "scanner finding remains available",
        );
        store
            .conn
            .execute(
                "insert into static_evidence_nodes(id, kind, finding_fingerprint, content_hash, title, body, metadata_json, indexed_at_unix) values (?1, 'source', ?2, 'hash', 'bad', 'bad', '{', 0)",
                rusqlite::params!["bad-node", &finding.fingerprint],
            )
            .unwrap();

        let (ranked, warnings) = rank_static_findings_with_threats_degraded(
            &[finding.clone()],
            None,
            Some(&store),
            None,
        )
        .unwrap();

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].fingerprint, finding.fingerprint);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("static evidence unavailable"));
    }

    fn insert_flow_evidence(store: &StaticEvidenceStore, finding: &Finding) {
        let source = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Source,
            "Express request source",
            "const userId = req.query.userId;",
        )
        .with_finding_fingerprint(&finding.fingerprint)
        .with_source_span("src/routes.ts", 12, Some(12))
        .with_metadata(json!({"framework": "Express", "data": "user token"}));
        let sink = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::Sink,
            "Database query sink",
            "return db.query(sql);",
        )
        .with_finding_fingerprint(&finding.fingerprint)
        .with_source_span("src/db.ts", 30, Some(30))
        .with_metadata(json!({"sinkClass": "sql_query", "data": "tenant data"}));
        let step = StaticEvidenceNode::new(
            StaticEvidenceNodeKind::DataflowStep,
            "CodeQL dataflow step",
            "CodeQL links req.query.userId to db.query(sql)",
        )
        .with_finding_fingerprint(&finding.fingerprint)
        .with_source_span("src/routes.ts", 18, Some(18))
        .with_metadata(json!({"normalizer": "codeql", "sequence": 1, "codeFlowStepCount": 3}));

        store.upsert_node(&source).unwrap();
        store.upsert_node(&sink).unwrap();
        store.upsert_node(&step).unwrap();
        store
            .upsert_edge(
                &StaticEvidenceEdge::new(StaticEvidenceEdgeKind::FlowsTo, source.id, step.id)
                    .with_finding_fingerprint(&finding.fingerprint),
            )
            .unwrap();
    }

    fn route_and_sink_surface() -> AttackSurfaceMap {
        let surfaces = vec![
            AttackSurface {
                id: "route".to_string(),
                kind: AttackSurfaceKind::HttpRoute,
                path: "src/routes.ts".to_string(),
                line: Some(10),
                language: "TypeScript".to_string(),
                framework: Some("Express".to_string()),
                title: "GET /users/:id".to_string(),
                evidence: "app.get('/users/:id', handler)".to_string(),
                method: Some("GET".to_string()),
                route: Some("/users/:id".to_string()),
                boundary: Some("public_http".to_string()),
                risk: AttackSurfaceRisk::default(),
                metadata: json!({}),
            },
            AttackSurface {
                id: "db".to_string(),
                kind: AttackSurfaceKind::DbQueryBoundary,
                path: "src/db.ts".to_string(),
                line: Some(30),
                language: "TypeScript".to_string(),
                framework: None,
                title: "database query".to_string(),
                evidence: "db.query(sql)".to_string(),
                method: None,
                route: None,
                boundary: Some("data_store".to_string()),
                risk: AttackSurfaceRisk::default(),
                metadata: json!({}),
            },
        ];
        AttackSurfaceMap {
            root_name: "fixture".to_string(),
            summary: AttackSurfaceSummary {
                total: surfaces.len(),
                by_kind: Default::default(),
                by_file: Default::default(),
                high_risk: 0,
                max_risk_score: 0,
                by_risk_tier: Default::default(),
            },
            surfaces,
        }
    }
}
