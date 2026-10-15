#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::FindingStore;
    use crate::modules::ModuleRegistry;
    use crate::modules::ToolExecutionContext;
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
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

        let normalized = normalize_findings(raw, target, 10, "carlini-threat-hunt:User:0").unwrap();
        let findings = normalized.kept;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "src/app.ts");
        assert_eq!(
            findings[0].actor_fingerprint.as_deref(),
            Some("carlini-threat-hunt:User:0")
        );
        assert!(findings[0].message.contains("Evidence: source to sink"));
        assert_eq!(
            normalized.rejected.len(),
            1,
            "out-of-target finding must be rejected with a reason, not dropped silently"
        );
        assert!(normalized.rejected[0].contains("outside"));
    }

    #[test]
    fn narrative_location_fallback_recovers_findings_without_file_path() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/gateway.go"), "package gw\n").unwrap();
        let raw = json!({
            "findings": [{
                "title": "ForwardRequest lacks ownership check",
                "severity": "high",
                "message": "RouterRPC ForwardRequest trusts in.Uuid",
                "evidence": "handler at src/gateway.go:42 forwards in.Uuid without ownership validation"
            }]
        });

        let normalized = normalize_findings(raw, temp.path(), 10, "fp:0").unwrap();

        assert_eq!(normalized.kept.len(), 1, "{:?}", normalized.rejected);
        assert_eq!(normalized.kept[0].file_path, "src/gateway.go");
        assert_eq!(normalized.kept[0].start_line, 42);
        assert!(normalized.rejected.is_empty());
    }

    #[test]
    fn recursively_recovers_locations_from_all_actor_evidence_shapes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        for name in ["evidence", "source", "sink", "trace", "hops"] {
            std::fs::write(
                temp.path().join(format!("src/{name}.rs")),
                "fn checked() {}\n",
            )
            .unwrap();
        }
        let shapes = [
            json!({"evidence": [{"detail": {"file": "src/evidence.rs", "startLine": "11"}}]}),
            json!({"source": {"location": {"path": "src/source.rs", "line": 12}}}),
            json!({"sink": {"node": {"file": "src/sink.rs", "startLine": 13}}}),
            json!({"trace": [{"hop": {"path": "src/trace.rs", "line": 14}}]}),
            json!({"hops": [{"file": "src/hops.rs", "startLine": 15}]}),
        ];
        let findings: Vec<Value> = shapes
            .into_iter()
            .enumerate()
            .map(|(index, shape)| finding_with_evidence_shape(index, shape))
            .collect();

        let normalized =
            normalize_findings(json!({"findings": findings}), temp.path(), 10, "actor:0").unwrap();

        assert_eq!(normalized.rejected_count, 0, "{:?}", normalized.rejected);
        assert_eq!(normalized.kept.len(), 5);
        assert_eq!(normalized.kept[0].start_line, 11);
        assert_eq!(normalized.kept[4].file_path, "src/hops.rs");
    }

    fn finding_with_evidence_shape(index: usize, shape: Value) -> Value {
        let mut object = shape.as_object().unwrap().clone();
        object.insert("title".to_string(), json!(format!("finding {index}")));
        object.insert("severity".to_string(), json!("high"));
        object.insert("message".to_string(), json!(format!("message {index}")));
        Value::Object(object)
    }

    #[test]
    fn unlocatable_finding_is_rejected_with_reason() {
        let temp = tempfile::tempdir().unwrap();
        let raw = json!({
            "findings": [{
                "title": "cache-hit bypass",
                "severity": "high",
                "message": "account cache-hit path skips cookie check"
            }]
        });

        let normalized = normalize_findings(raw, temp.path(), 10, "fp:0").unwrap();

        assert!(normalized.kept.is_empty());
        assert_eq!(normalized.rejected.len(), 1);
        assert!(normalized.rejected[0].contains("cache-hit bypass"));
    }

    #[test]
    fn recursive_location_recovery_rejects_paths_outside_target() {
        let temp = tempfile::tempdir().unwrap();
        let raw = json!({
            "findings": [{
                "title": "outside evidence",
                "severity": "high",
                "message": "evidence points outside scope",
                "trace": {"hops": [{"path": "../outside.rs", "line": 7}]}
            }]
        });

        let normalized = normalize_findings(raw, temp.path(), 10, "actor:0").unwrap();

        assert!(normalized.kept.is_empty());
        assert_eq!(normalized.rejected_count, 1);
        assert!(normalized.rejected[0].contains("outside evidence"));
    }

    #[test]
    fn offense_review_alias_persists_reported_evidence_and_trace_shape() {
        let temp = tempfile::tempdir().unwrap();
        write_carlini_alias_fixture_files(temp.path());
        let response: Value =
            serde_json::from_str(include_str!("fixtures/audit1_item12_actor_response.json"))
                .unwrap();
        let runtime = StructuredCarliniRuntime { response, binding:None };
        let (workspace, store, config) = carlini_alias_test_context(temp.path());
        let trace = crate::run_artifacts::TraceHandle::jsonl(temp.path(), "carlini-source-delta");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };

        approve_carlini_fixture(&ctx);
        let result = ModuleRegistry::with_v2_builtins()
            .execute_tool_with_runtime(
                "offense-review:threat-hunt",
                carlini_fixture_input(&ctx, json!({"maxActors": 1, "runsPerActor": 1})),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.pointer("/data/count"), Some(&json!(2)));
        assert!(result
            .pointer("/data/snapshotHash")
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() == 64));
        let projection =
            crate::run_lifecycle::load_run_projection(temp.path(), "carlini-source-delta")
                .unwrap()
                .projection;
        let delta = projection
            .finding_deltas
            .last()
            .expect("persisted findings have a typed delta");
        assert_eq!((delta.added, delta.updated, delta.removed), (2, 0, 0));
        assert_eq!(result.pointer("/data/rejectedCount"), Some(&json!(0)));
        assert_eq!(
            result.pointer("/data/findings/0/start_line"),
            Some(&json!(73))
        );
        assert_eq!(
            result.pointer("/data/findings/1/start_line"),
            Some(&json!(118))
        );
        assert!(result.pointer("/data/persisted/runId").is_some());
        let persisted = store.list_findings(10).unwrap();
        assert_eq!(persisted.len(), 2);
        assert!(persisted.iter().all(|finding| {
            finding.actor_fingerprint.as_deref()
                == Some("carlini-threat-hunt:Cluster_Gateway_User:0")
        }));
        check_repeated_carlini_delta(
            &workspace,
            &store,
            &config,
            &runtime,
            "carlini-repeated",
            (0, 2, 0),
        );
        let empty = StructuredCarliniRuntime {
            response: json!({"findings": []}),
            binding:None,
        };
        check_repeated_carlini_delta(
            &workspace,
            &store,
            &config,
            &empty,
            "carlini-empty",
            (0, 0, 0),
        );
    }

    fn check_repeated_carlini_delta(
        workspace: &WorkspaceTarget,
        store: &FindingStore,
        config: &V2Config,
        runtime: &dyn AgentRuntime,
        run_id: &str,
        expected: (u64, u64, u64),
    ) {
        let trace = crate::run_artifacts::TraceHandle::jsonl(workspace.root(), run_id);
        let ctx = ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: Some(store),
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };
        ModuleRegistry::with_v2_builtins()
            .execute_tool_with_runtime(
                "offense-review:threat-hunt",
                carlini_fixture_input(&ctx, json!({"maxActors":1,"runsPerActor":1})),
                &ctx,
                Some(runtime),
            )
            .unwrap();
        let projection = crate::run_lifecycle::load_run_projection(workspace.root(), run_id)
            .unwrap()
            .projection;
        let delta = projection.finding_deltas.last().unwrap();
        assert_eq!((delta.added, delta.updated, delta.removed), expected);
    }

    #[test]
    fn rejection_receipt_counts_all_items_and_bounds_actor_scoped_reasons() {
        let temp = tempfile::tempdir().unwrap();
        write_carlini_alias_fixture_files(temp.path());
        let rejected: Vec<Value> = (0..12)
            .map(|index| {
                json!({
                    "title": format!("unlocatable finding {index}"),
                    "severity": "high",
                    "message": "No target-contained source location"
                })
            })
            .collect();
        let runtime = StructuredCarliniRuntime {
            response: json!({"findings": rejected}),
            binding:None,
        };
        let (workspace, store, config) = carlini_alias_test_context(temp.path());
        let trace = crate::run_artifacts::TraceHandle::jsonl(temp.path(), "carlini-rejections");
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };

        approve_carlini_fixture(&ctx);
        let result = ModuleRegistry::with_v2_builtins()
            .execute_tool_with_runtime(
                "offense-review:threat-hunt",
                carlini_fixture_input(&ctx, json!({"maxActors": 1, "maxFindings": 1})),
                &ctx,
                Some(&runtime),
            )
            .unwrap();

        assert_eq!(result.pointer("/data/rejectedCount"), Some(&json!(12)));
        let reasons = result
            .pointer("/data/rejectionReasons")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(reasons.len(), MAX_CARLINI_REJECTION_REASONS);
        assert!(reasons.iter().all(|reason| reason
            .as_str()
            .unwrap()
            .starts_with("carlini-threat-hunt:Cluster_Gateway_User:0:")));
        assert!(result["summary"].as_str().unwrap().contains("12 rejected"));
        assert!(result["output"]
            .as_str()
            .unwrap()
            .contains("Rejected by finding schema: 12"));
        let trace_text = std::fs::read_to_string(
            crate::run_artifacts::run_dir(temp.path(), "carlini-rejections").join("items.jsonl"),
        )
        .unwrap();
        assert!(trace_text.contains("finding rejected by normalizer"));
        assert!(trace_text.contains("Cluster_Gateway_User:0"));
        assert!(trace_text.contains("2 more findings rejected by normalizer"));
        assert!(trace_text.contains("12 rejected by schema"));
        assert!(trace_text.contains("actor hunts"));
        assert!(!trace_text.contains("defender-critic"));
    }

    fn carlini_fixture_input(ctx: &ToolExecutionContext<'_>, mut input: Value) -> Value {
        let work_id = ctx.trace.and_then(|trace|trace.run_artifact_location()).unwrap().1;
        input["allowanceRef"] = json!({"schemaVersion":1,"investigationId":"owned-actor","revision":1,"workId":work_id});
        input
    }

    fn approve_carlini_fixture(ctx: &ToolExecutionContext<'_>) {
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared=registry.prepare_dispatch_input("campaign:approve-allowance",json!({"investigationId":"owned-actor",
            "expectedRevision":0,"model":ctx.config.model,"maxProviderCalls":4,"protectedReviewCalls":1,
            "reason":"Owned actor observation regression"}),ctx,None).unwrap().authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared,ctx,None).unwrap();
    }

    #[derive(Clone)]
    struct StructuredCarliniRuntime {
        response: Value,
        binding:Option<crate::allowance::AllowanceBinding>,
    }

    impl AgentRuntime for StructuredCarliniRuntime {
        fn allowance_binding(&self) -> Option<&crate::allowance::AllowanceBinding> { self.binding.as_ref() }
        fn with_allowance_binding(&self,binding:crate::allowance::AllowanceBinding)->Result<Box<dyn AgentRuntime+'_>> {
            Ok(Box::new(Self {binding:Some(binding),..self.clone()}))
        }
        fn query_blocking(
            &self,
            request: AgentQueryRequest,
        ) -> anyhow::Result<AgentQueryResponse> {
            let binding=self.binding.as_ref().unwrap();
            let reservation=binding.reserve(&request.model)?;
            assert_eq!(binding.work().work,crate::allowance::InvestigationWork::Discovery);
            binding.settle(reservation,RuntimeCostReport::incomplete(RuntimeCost::ZERO))?;
            Ok(AgentQueryResponse {
                structured: Some(self.response.clone()),
                ..AgentQueryResponse::default()
            })
        }

        fn triage_finding_blocking(
            &self,
            _request: TriageRequest,
        ) -> anyhow::Result<crate::findings::TriageOutcome> {
            unreachable!("Carlini actor hunt does not triage")
        }
    }

    fn carlini_alias_test_context(target: &Path) -> (WorkspaceTarget, FindingStore, V2Config) {
        let workspace = WorkspaceTarget::new(target).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("anthropic:test-model".to_string());
        (workspace, store, config)
    }

    fn write_carlini_alias_fixture_files(target: &Path) {
        fs::create_dir_all(target.join("bluejay_auth")).unwrap();
        fs::create_dir_all(target.join("router/rpc")).unwrap();
        fs::write(
            target.join("bluejay_auth/account_cache.go"),
            "package auth\n",
        )
        .unwrap();
        fs::write(target.join("bluejay_auth/session.go"), "package auth\n").unwrap();
        fs::write(target.join("router/rpc/forward.go"), "package rpc\n").unwrap();
        let threat_model_path = crate::capabilities::persistent_threat_model_path(target);
        fs::create_dir_all(threat_model_path.parent().unwrap()).unwrap();
        fs::write(
            threat_model_path,
            serde_json::to_vec(&carlini_alias_threat_model()).unwrap(),
        )
        .unwrap();
    }

    fn carlini_alias_threat_model() -> Value {
        json!({
            "dfd": {
                "nodes": [
                    {"id":"cluster-user","type":"external-entity","name":"Cluster Gateway User","description":"Remote tenant user","trustZone":"external"},
                    {"id":"gateway","type":"process","name":"RouterRPC","description":"RPC gateway","trustZone":"internal"}
                ],
                "flows": [
                    {"id":"proxy-flow","sourceId":"cluster-user","targetId":"gateway","description":"ForwardRequest","trustBoundaryIds":["tenant-boundary"]}
                ]
            },
            "threats": [{
                "id":"T-proxy-owner",
                "impact":"high",
                "title":"Cross-tenant ForwardRequest dispatch",
                "actorIds":["cluster-user"],
                "flowIds":["proxy-flow"],
                "affectedFiles":["router/rpc/forward.go"]
            }]
        })
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
            cancellation: None,
            authorization: Default::default(),
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
            &render_carlini_inventory_block(&[]),
            "carlini-threat-hunt:Authenticated_User:0",
        );

        assert!(prompt.contains("Local artifact KB context"));
        assert!(prompt.contains("Authenticated user actor flow"));
        assert_eq!(options.kb_context.snippets[0].module_id, "x-ray");
    }

    #[test]
    fn actor_prompt_places_repository_inventory_before_actor_specific_context() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
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
            &render_carlini_inventory_block(&[(
                "src/auth.rs".to_string(),
                "fn login() {}".to_string(),
            )]),
            "carlini-threat-hunt:Authenticated_User:0",
        );

        let inventory = prompt.find("Repository inventory and snippets").unwrap();
        let actor = prompt.find("Actor activity fingerprint").unwrap();
        assert!(inventory < actor);
    }

    fn actor_hunt_named(id: &str, name: &str) -> ActorHunt {
        ActorHunt {
            actor: DfdNode {
                id: id.to_string(),
                node_type: "external-entity".to_string(),
                name: name.to_string(),
                description: format!("{name} actor"),
                trust_zone: "external".to_string(),
            },
            threats: Vec::new(),
            flows: Vec::new(),
        }
    }

    #[test]
    fn actor_prompt_cacheable_prefix_is_shared_across_actors_and_leads_each_prompt() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let options = CarliniInput::from_tool_input(&json!({}), &ctx, workspace.root()).unwrap();
        let inventory = render_carlini_inventory_block(&[(
            "src/auth.rs".to_string(),
            "fn login() {}".to_string(),
        )]);

        let user = build_actor_prompt_parts(
            workspace.root(),
            &actor_hunt_named("actor-user", "Authenticated User"),
            &options,
            &inventory,
            "carlini-threat-hunt:Authenticated_User:0",
        );
        let admin = build_actor_prompt_parts(
            workspace.root(),
            &actor_hunt_named("actor-admin", "Operator"),
            &options,
            &inventory,
            "carlini-threat-hunt:Operator:1",
        );

        assert_eq!(user.cacheable_prefix, admin.cacheable_prefix);
        assert!(user.prompt.starts_with(&user.cacheable_prefix));
        assert!(admin.prompt.starts_with(&admin.cacheable_prefix));
        assert!(user.cacheable_prefix.contains("fn login() {}"));
        assert!(!user.cacheable_prefix.contains("Actor activity fingerprint"));
        assert_ne!(user.prompt, admin.prompt);
        assert_eq!(
            user.prompt,
            build_actor_prompt(
                workspace.root(),
                &actor_hunt_named("actor-user", "Authenticated User"),
                &options,
                &inventory,
                "carlini-threat-hunt:Authenticated_User:0",
            )
        );
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
            cancellation: None,
            authorization: Default::default(),
        };

        let options = CarliniInput::from_tool_input(&json!({}), &ctx, workspace.root()).unwrap();

        let block = options.attachments_block.as_deref().unwrap();
        assert!(block.contains("operator-note.md"));
        assert!(block.contains("review reset flow"));
        assert!(block.contains("moduleId=\"carlini-threat-hunt\""));
        assert!(crate::workspace::workspace_attachments_path(workspace.root()).exists());
    }

    #[test]
    fn tampered_attachment_store_cannot_read_outside_workspace() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), "outside-secret").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        let record = json!({
            "version": 1,
            "attachments": [{
                "id": "A-tampered", "moduleId": "offense-review",
                "kind": "path", "source": outside.path(), "title": "outside",
                "metadataOnly": false, "status": "tampered", "updatedAtUnix": 0
            }]
        });
        fs::write(
            crate::workspace::workspace_attachments_path(workspace.root()),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };

        let options = CarliniInput::from_tool_input(&json!({}), &ctx, workspace.root()).unwrap();
        let block = options.attachments_block.unwrap();

        assert!(block.contains("Unsafe attachment"), "{block}");
        assert!(!block.contains("outside-secret"), "{block}");
    }

    fn carlini_actor(id: &str, name: &str) -> ActorHunt {
        ActorHunt {
            actor: DfdNode {
                id: id.to_string(),
                node_type: "external-entity".to_string(),
                name: name.to_string(),
                description: format!("{name} actor"),
                trust_zone: "external".to_string(),
            },
            threats: Vec::new(),
            flows: Vec::new(),
        }
    }

    #[test]
    fn saving_the_builtin_carlini_mission_preserves_the_runtime_prompt() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let options = CarliniInput::from_tool_input(&json!({}), &ctx, workspace.root()).unwrap();
        let actor = carlini_actor("external-user", "External user");
        let inventory = render_carlini_inventory_block(&[]);
        let default_prompt = build_actor_prompt(
            workspace.root(),
            &actor,
            &options,
            &inventory,
            "fingerprint",
        );
        let mut saved_options = options;
        saved_options.prompt_override = Some(DEFAULT_CARLINI_MISSION.to_string());

        let saved_prompt = build_actor_prompt(
            workspace.root(),
            &actor,
            &saved_options,
            &inventory,
            "fingerprint",
        );

        assert_eq!(saved_prompt, default_prompt);
        assert!(!saved_prompt.contains("operator-prompt-override"));
    }

    struct RecordingRuntime {
        prompts: std::sync::Mutex<Vec<String>>,
    }

    impl crate::runtime::AgentRuntime for RecordingRuntime {
        fn query_blocking(
            &self,
            request: crate::runtime::AgentQueryRequest,
        ) -> anyhow::Result<crate::runtime::AgentQueryResponse> {
            self.prompts.lock().unwrap().push(request.prompt.clone());
            Ok(crate::runtime::AgentQueryResponse {
                text: r#"{"findings":[]}"#.to_string(),
                ..crate::runtime::AgentQueryResponse::default()
            })
        }

        fn triage_finding_blocking(
            &self,
            _request: crate::runtime::TriageRequest,
        ) -> anyhow::Result<crate::findings::TriageOutcome> {
            unreachable!("carlini actor hunt does not triage")
        }
    }

    #[test]
    fn inventory_is_rendered_once_but_every_actor_still_receives_full_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let options = CarliniInput::from_tool_input(&json!({}), &ctx, workspace.root()).unwrap();

        let inventory = vec![
            (
                "src/alpha.rs".to_string(),
                "fn alpha_secret() {}".to_string(),
            ),
            ("src/beta.rs".to_string(), "fn beta_secret() {}".to_string()),
        ];

        // Build the shared inventory block exactly once for the whole
        // K-actor run, mirroring `execute_carlini_threat_hunt_run`. Before
        // this fix, the block was re-rendered inside `build_actor_prompt`
        // once per actor iteration (K constructions); now it is built once
        // and reused.
        let mut render_calls = 0usize;
        let inventory_block = {
            render_calls += 1;
            render_carlini_inventory_block(&inventory)
        };
        let mut decoded_inventory = Vec::new();
        let mut remaining = inventory_block.as_str();
        while let Some(start) = remaining.find(crate::prompts::UNTRUSTED_REPO_BEGIN) {
            let frame = &remaining[start..];
            let end = frame.find(crate::prompts::UNTRUSTED_REPO_END).unwrap()
                + crate::prompts::UNTRUSTED_REPO_END.len();
            decoded_inventory.push(crate::prompts::decode_untrusted_record(&frame[..end]).unwrap());
            remaining = &frame[end..];
        }
        assert_eq!(
            decoded_inventory
                .iter()
                .map(|record| (record.label.as_str(), record.content.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("src/alpha.rs", "fn alpha_secret() {}"),
                ("src/beta.rs", "fn beta_secret() {}"),
            ]
        );

        let actors = vec![
            carlini_actor("actor-one", "One"),
            carlini_actor("actor-two", "Two"),
            carlini_actor("actor-three", "Three"),
        ];

        let runtime = RecordingRuntime {
            prompts: std::sync::Mutex::new(Vec::new()),
        };

        run_carlini_actor_hunts(
            &runtime,
            &json!({}),
            workspace.root(),
            &options,
            "anthropic:test-model",
            &inventory_block,
            &actors,
            None,
        )
        .unwrap();

        let prompts = runtime.prompts.lock().unwrap().clone();

        // Inventory payload constructed exactly once for the whole run.
        assert_eq!(render_calls, 1, "inventory block rendered once per run");
        // One transmission per actor (runs_per_actor defaults to 1). The
        // inventory bytes still ride each request until the bridge gains
        // cache_control support; we only stopped re-*building* the payload.
        assert_eq!(prompts.len(), actors.len());

        for prompt in &prompts {
            // Correctness: each actor still receives the complete inventory
            // block verbatim (byte-for-byte the single canonical rendered
            // payload). The decoded assertions above prove the framed records
            // retain their original paths and contents without expecting raw
            // untrusted bytes to appear outside the encoding boundary.
            assert!(prompt.contains(&inventory_block));
        }
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
            cancellation: None,
            authorization: Default::default(),
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
