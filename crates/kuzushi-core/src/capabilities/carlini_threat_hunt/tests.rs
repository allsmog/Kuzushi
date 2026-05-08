#[cfg(test)]
mod tests {
    use super::super::build_actor_fingerprint::looks_like_prompt_path;
    use super::super::*;
    use crate::config::V2Config;
    use crate::modules::ToolExecutionContext;
    use crate::workspace::artifact_kb::{ArtifactKnowledgeRecord, ArtifactKnowledgeStore};
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn prompt_path_detection_matches_inline_and_file_prompt_shapes() {
        assert!(looks_like_prompt_path("./prompt.md"));
        assert!(looks_like_prompt_path("../prompt.txt"));
        assert!(looks_like_prompt_path("/tmp/custom.prompt"));
        assert!(looks_like_prompt_path("checked-in.md"));
        assert!(!looks_like_prompt_path("Analyze auth flows only"));
    }

    #[test]
    fn prioritizes_high_impact_external_actors_and_flows() {
        let document = json!({
            "dfd": {
                "nodes": [
                    {"id":"actor-user","type":"external-entity","name":"User","description":"External user","trustZone":"external"},
                    {"id":"actor-admin","type":"external-entity","name":"Admin","description":"External admin","trustZone":"external"},
                    {"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}
                ],
                "flows": [
                    {"id":"flow-user","sourceId":"actor-user","targetId":"web","description":"user request","trustBoundaryIds":["tb"]},
                    {"id":"flow-admin","sourceId":"actor-admin","targetId":"web","description":"admin request","trustBoundaryIds":["tb"]}
                ]
            },
            "threats": [
                {"id":"T-1","impact":"high","category":"spoofing","title":"User spoofing","actorIds":["actor-user"],"flowIds":["flow-user"]},
                {"id":"T-2","impact":"critical","category":"tampering","title":"Admin tampering","actorIds":["actor-admin"],"flowIds":["flow-admin"]},
                {"id":"T-3","impact":"medium","category":"repudiation","title":"Ignored","actorIds":["actor-user"]}
            ]
        });

        let actors = actors_from_document(&document);

        assert_eq!(actors.all_actors.len(), 2);
        assert_eq!(actors.prioritized[0].actor.id, "actor-admin");
        assert_eq!(actors.prioritized[0].flows[0].id, "flow-admin");
        assert_eq!(actors.prioritized[1].actor.id, "actor-user");
    }

    #[test]
    fn threat_search_text_feeds_semantic_actor_matching() {
        let threat = json!({
            "title": "Pull request fork can poison build",
            "requiredCapabilities": ["contributor account"],
            "sources": [{
                "name": "fork branch",
                "description": "attacker controlled pull request",
                "filePath": ".github/workflows/ci.yml"
            }]
        });
        let actor = DfdNode {
            id: "actor-pr-author".to_string(),
            node_type: "external-entity".to_string(),
            name: "PR Author".to_string(),
            description: "Fork contributor".to_string(),
            trust_zone: "external".to_string(),
        };

        let haystack = threat_search_text(&threat);
        assert!(haystack.contains("pull request fork"));
        assert!(actor_semantic_score(&actor, &haystack) >= 2);
    }

    #[test]
    fn normalizes_findings_with_actor_fingerprint_and_scope_filter() {
        let target = Path::new("/repo");
        let raw = json!({
            "findings": [
                {"ruleId":"carlini-threat-hunt/xss","filePath":"/repo/src/app.ts","startLine":9,"severity":"ERROR","message":"XSS","confidence":"HIGH","evidence":"source to sink"},
                {"ruleId":"outside","filePath":"/tmp/outside.ts","startLine":1,"severity":"ERROR","message":"drop"}
            ]
        });

        let findings = normalize_findings(raw, target, 10, "carlini-threat-hunt:User:0").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "src/app.ts");
        assert_eq!(
            findings[0].actor_fingerprint.as_deref(),
            Some("carlini-threat-hunt:User:0")
        );
        assert!(findings[0].message.contains("Evidence: source to sink"));
    }

    #[test]
    fn actor_prompt_includes_matching_artifact_kb_snippets() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        store
            .upsert_record(&ArtifactKnowledgeRecord::from_body(
                "x-ray/entry-points.md",
                "x-ray",
                None,
                "entry points",
                "Authenticated user actor flow reaches the HTML response entry point.",
                vec!["x-ray/entry-points.md:4".to_string()],
                json!({"sourceKind": "manual-test"}),
            ))
            .unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
        };
        let options = CarliniInput::from_tool_input(&json!({}), &ctx, workspace.root()).unwrap();
        let prompt = build_actor_prompt(
            workspace.root(),
            &ActorHunt {
                actor: DfdNode {
                    id: "actor-user".to_string(),
                    node_type: "external-entity".to_string(),
                    name: "Authenticated User".to_string(),
                    description: "Logged-in user".to_string(),
                    trust_zone: "external".to_string(),
                },
                threats: Vec::new(),
                flows: Vec::new(),
            },
            &options,
            &[],
            "carlini-threat-hunt:Authenticated_User:0",
        );

        assert!(prompt.contains("Local artifact KB context"));
        assert!(prompt.contains("Authenticated user actor flow"));
        assert_eq!(options.kb_context.snippets[0].module_id, "x-ray");
    }
}
