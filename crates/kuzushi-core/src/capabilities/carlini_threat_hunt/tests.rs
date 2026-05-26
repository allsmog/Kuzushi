#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::modules::ToolExecutionContext;
    use crate::workspace::artifact_kb::{ArtifactKnowledgeRecord, ArtifactKnowledgeStore};
    use crate::workspace::WorkspaceTarget;
    use std::fs;

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
    fn routes_unassigned_url_file_threats_to_network_actor() {
        let document = json!({
            "dfd": {
                "nodes": [
                    {"id":"network","type":"external-entity","name":"Network peers","description":"Remote HTTP and FTP endpoints","trustZone":"internet"},
                    {"id":"deps","type":"external-entity","name":"Third-party build dependencies","description":"Optional libraries","trustZone":"supply-chain"},
                    {"id":"maintainers","type":"external-entity","name":"Maintainers and contributors","description":"Humans with commit access","trustZone":"human"}
                ],
                "flows": []
            },
            "threats": [{
                "id":"T-url-file",
                "impact":"Local file overwrite or privilege escalation through writable locations",
                "category":"ElevationOfPrivilege",
                "title":"Unsafe URL-to-file handling in helper paths",
                "attackVector":"Path traversal or unsafe filename resolution",
                "affectedFiles":["src/*", "lib/*"]
            }]
        });

        let actors = actors_from_document(&document);

        assert_eq!(actors.prioritized.len(), 1);
        assert_eq!(actors.prioritized[0].actor.id, "network");
        assert_eq!(actors.prioritized[0].threats[0]["id"], "T-url-file");
    }

    #[test]
    fn routes_business_impact_threats_to_matching_web_and_ci_actors() {
        let document = json!({
            "dfd": {
                "nodes": [
                    {"id":"browser-user","type":"external-entity","name":"Authenticated Browser User","description":"Web user and admin browser client","trustZone":"external"},
                    {"id":"github-actions","type":"external-entity","name":"GitHub Actions CI/CD","description":"Workflow automation and release pipeline","trustZone":"supply-chain"}
                ],
                "flows": []
            },
            "threats": [
                {
                    "id":"T-web",
                    "impact":"Credential theft, admin takeover, and data exfiltration",
                    "title":"CORS or session handling exposes dashboard data",
                    "affectedFiles":["core/API/Request.php"]
                },
                {
                    "id":"T-ci",
                    "impact":"Supply chain compromise affecting downstream users",
                    "title":"Release workflow can publish attacker-controlled artifact",
                    "affectedFiles":[".github/workflows/release.yml"]
                }
            ]
        });

        let actors = actors_from_document(&document);
        let actor_ids = actors
            .prioritized
            .iter()
            .map(|hunt| hunt.actor.id.as_str())
            .collect::<Vec<_>>();

        assert!(actor_ids.contains(&"browser-user"), "{actor_ids:?}");
        assert!(actor_ids.contains(&"github-actions"), "{actor_ids:?}");
    }

    #[test]
    fn carlini_inventory_prioritizes_threat_affected_files_before_generic_files() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("aaa.txt"), "generic alpha").unwrap();
        fs::write(
            temp.path().join("src/critical.php"),
            "<?php echo $_GET['x']; ?>",
        )
        .unwrap();
        let hunt = ActorHunt {
            actor: DfdNode {
                id: "actor-user".to_string(),
                node_type: "external-entity".to_string(),
                name: "User".to_string(),
                description: "External user".to_string(),
                trust_zone: "external".to_string(),
            },
            threats: vec![json!({
                "id": "T-focused",
                "impact": "high",
                "affectedFiles": ["src/critical.php", "../outside.php", "src/*.php"]
            })],
            flows: Vec::new(),
        };

        let inventory = collect_carlini_inventory(temp.path(), &[hunt]).unwrap();

        assert_eq!(inventory[0].0, "src/critical.php");
        assert!(inventory[0].1.contains("$_GET"));
        assert!(!inventory.iter().any(|(path, _)| path.contains("outside")));
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
            trace: None,
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

    #[test]
    fn actor_prompt_attachments_use_shared_workspace_attachment_store() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("operator-note.md"), "review reset flow\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        crate::attachments::attach_source(&workspace, "offense-review", "operator-note.md")
            .unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
        };

        let options = CarliniInput::from_tool_input(&json!({}), &ctx, workspace.root()).unwrap();

        let block = options.attachments_block.as_deref().unwrap();
        assert!(block.contains("operator-note.md"));
        assert!(block.contains("review reset flow"));
        assert!(block.contains("moduleId=\"carlini-threat-hunt\""));
        assert!(crate::workspace::workspace_attachments_path(workspace.root()).exists());
    }

    #[test]
    fn input_options_index_x_ray_artifacts_before_loading_kb_context() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("x-ray")).unwrap();
        fs::write(
            temp.path().join("x-ray/entry-points.md"),
            "# Entry Points\n\nCarlini threat hunt actor flows should use x-ray context: authenticated user actor flow reaches the HTML response entry point.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
        };

        let options = CarliniInput::from_tool_input(&json!({}), &ctx, workspace.root()).unwrap();

        assert!(!options.kb_context.missing_db);
        assert_eq!(
            options.kb_context.snippets[0].source_path,
            "x-ray/entry-points.md"
        );
        assert!(options
            .kb_context
            .snippets
            .iter()
            .any(|snippet| snippet.module_id == "x-ray"
                && snippet.source_path == "x-ray/entry-points.md"));
    }
}
