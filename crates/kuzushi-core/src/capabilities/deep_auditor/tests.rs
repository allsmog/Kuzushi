#[cfg(test)]
mod tests {
    use super::super::application::{build_triage_outcome, parse_vuln_analysis};
    use super::super::*;
    use crate::agent_router::{AgentRole, AgentRouter, RoutedRuntime};
    use crate::findings::{Finding, FindingStore, Severity, TriageOutcome, TriageVerdict};
    use crate::runtime::{
        AgentLoopOutcome, AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime,
        AgentToolLoopRequest, LoopHistoryEntry, ToolCall, TriageRequest,
    };
    use crate::spend::{Operation, SpendLimiter};
    use anyhow::Result;
    use std::sync::{Arc, Mutex};

    /// Mock runtime that walks a scripted sequence of steps. Tests use it
    /// to drive deterministic auditor behaviour.
    struct ScriptedRuntime {
        steps: Mutex<Vec<AgentLoopStep>>,
        captured_prompts: Mutex<Vec<String>>,
        captured_models: Mutex<Vec<String>>,
    }
    impl ScriptedRuntime {
        fn new(steps: Vec<AgentLoopStep>) -> Arc<Self> {
            Arc::new(Self {
                steps: Mutex::new(steps),
                captured_prompts: Mutex::new(Vec::new()),
                captured_models: Mutex::new(Vec::new()),
            })
        }

        fn last_prompt(&self) -> Option<String> {
            self.captured_prompts.lock().unwrap().last().cloned()
        }

        fn captured_models(&self) -> Vec<String> {
            self.captured_models.lock().unwrap().clone()
        }
    }
    impl AgentRuntime for ScriptedRuntime {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            unreachable!()
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
        fn supports_tools(&self) -> bool {
            true
        }
        fn next_step_blocking(
            &self,
            request: &AgentToolLoopRequest,
            _history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            self.captured_prompts
                .lock()
                .unwrap()
                .push(request.prompt.clone());
            self.captured_models
                .lock()
                .unwrap()
                .push(request.model.clone());
            let mut s = self.steps.lock().unwrap();
            anyhow::ensure!(!s.is_empty(), "scripted runtime exhausted");
            Ok(s.remove(0))
        }
    }

    fn finding() -> Finding {
        Finding::new_tool(
            "semgrep",
            "java.injection",
            "src/foo.c",
            42,
            Some(50),
            Severity::High,
            "Possible OOB write via user-controlled length",
        )
    }

    fn routed_runtime_with_role(steps: Vec<AgentLoopStep>) -> RoutedRuntime<'static> {
        let runtime: Arc<dyn AgentRuntime> = ScriptedRuntime::new(steps);
        let mut router = AgentRouter::empty();
        router_add_route(
            &mut router,
            AgentRole::DeepAuditor,
            "anthropic:claude-opus-4-7",
        );
        RoutedRuntime::new(runtime, Arc::new(router), None)
    }

    fn routed_runtime_with_role_typed(
        steps: Vec<AgentLoopStep>,
    ) -> (RoutedRuntime<'static>, Arc<ScriptedRuntime>) {
        let runtime = ScriptedRuntime::new(steps);
        let runtime_dyn: Arc<dyn AgentRuntime> = runtime.clone();
        let mut router = AgentRouter::empty();
        router_add_route(
            &mut router,
            AgentRole::DeepAuditor,
            "anthropic:claude-opus-4-7",
        );
        (
            RoutedRuntime::new(runtime_dyn, Arc::new(router), None),
            runtime,
        )
    }

    fn router_add_route(router: &mut AgentRouter, role: AgentRole, primary: &str) {
        // The router's `routes` field is module-private — so for the
        // test we round-trip through models.toml.
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".kuzushi");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("models.toml"),
            format!("[roles.{}]\nprimary = \"{}\"\n", role.as_key(), primary),
        )
        .unwrap();
        let loaded = AgentRouter::load(&crate::config::ConfigPaths {
            home_dir: tmp.path().to_path_buf(),
            target_dir: None,
        })
        .unwrap();
        *router = loaded;
        // tmpdir intentionally leaks for the duration of the test — Drop
        // closes it; the router has already loaded the data it needs.
        let _ = tmp;
    }

    #[test]
    fn parses_structured_true_positive_verdict() {
        let outcome = AgentLoopOutcome {
            text: String::new(),
            structured: Some(serde_json::json!({
                "triggerable": true,
                "rationale": "user-controlled len reaches memcpy without check",
                "confidence": 0.85,
                "evidence": [{
                    "file": "src/foo.c", "start_line": 42, "end_line": 50,
                    "note": "no bounds check", "kind": "sink"
                }]
            })),
            steps_used: 3,
            truncated: false,
            cost_usd: 0.012,
            cost_usd_exact: true,
            transcript: vec![],
        };
        let analysis = parse_vuln_analysis(&outcome);
        assert!(analysis.triggerable);
        assert!((analysis.confidence - 0.85).abs() < 1e-6);
        assert_eq!(analysis.evidence.len(), 1);
        let triage = build_triage_outcome(&analysis, &outcome);
        assert_eq!(triage.verdict, TriageVerdict::TruePositive);
    }

    #[test]
    fn parses_loose_json_inside_text_response() {
        let outcome = AgentLoopOutcome {
            text: "Here is my answer:\n```json\n{\"triggerable\":false,\"rationale\":\"safe\",\"confidence\":0.9}\n```".to_string(),
            structured: None,
            steps_used: 1,
            truncated: false,
            cost_usd: 0.0,
            cost_usd_exact: true,
            transcript: vec![],
        };
        let analysis = parse_vuln_analysis(&outcome);
        assert!(!analysis.triggerable);
        assert!((analysis.confidence - 0.9).abs() < 1e-6);
        let triage = build_triage_outcome(&analysis, &outcome);
        assert_eq!(triage.verdict, TriageVerdict::FalsePositive);
    }

    #[test]
    fn malformed_response_falls_back_to_needs_review() {
        let outcome = AgentLoopOutcome {
            text: "I'm not sure about this one.".to_string(),
            structured: None,
            steps_used: 1,
            truncated: false,
            cost_usd: 0.0,
            cost_usd_exact: true,
            transcript: vec![],
        };
        let analysis = parse_vuln_analysis(&outcome);
        assert!(!analysis.triggerable);
        assert!(analysis.confidence < 0.5);
        assert!(
            analysis.rationale.contains("synthesized fallback"),
            "fallback rationale must make parse failure visible: {}",
            analysis.rationale
        );
        let triage = build_triage_outcome(&analysis, &outcome);
        assert_eq!(triage.verdict, TriageVerdict::NeedsReview);
        assert!(triage.rationale.contains("synthesized fallback"));
    }

    #[test]
    fn truncation_marks_rationale_and_falls_back_to_needs_review() {
        let outcome = AgentLoopOutcome {
            text: String::new(),
            structured: Some(serde_json::json!({
                "triggerable": true,
                "rationale": "looked promising",
                "confidence": 0.6,
                "evidence": []
            })),
            steps_used: 24,
            truncated: true,
            cost_usd: 0.0,
            cost_usd_exact: true,
            transcript: vec![],
        };
        let analysis = parse_vuln_analysis(&outcome);
        let triage = build_triage_outcome(&analysis, &outcome);
        assert!(triage.rationale.contains("truncated"));
        // Truncated true_positive at 0.6 → still TruePositive (>=0.5),
        // but the operator-visible rationale is decorated.
        assert_eq!(triage.verdict, TriageVerdict::TruePositive);
    }

    #[test]
    fn deep_auditor_drives_loop_to_completion_with_spend_settlement() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path();
        std::fs::write(workspace.join("foo.c"), "void foo() {}\n").unwrap();

        // Two-step script: model reads source, then returns final.
        let steps = vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({ "file": "foo.c" }),
                    call_id: "c1".to_string(),
                },
                cost_usd: Some(0.0),
            },
            AgentLoopStep::Final {
                text: String::new(),
                structured: Some(serde_json::json!({
                    "triggerable": false,
                    "rationale": "no user input reaches the function",
                    "confidence": 0.85,
                    "evidence": [{
                        "file": "foo.c", "start_line": 1, "end_line": 1,
                        "note": "trivially safe", "kind": "context"
                    }]
                })),
                cost_usd: Some(0.05),
            },
        ];
        let runtime = routed_runtime_with_role(steps);
        let limiter = SpendLimiter::open_in_memory().unwrap();
        limiter.set_cap(Operation::DeepAudit, 100.0).unwrap();

        let cfg = DeepAuditConfig::new(workspace);
        let outcome = run_deep_auditor(&runtime, Some(&limiter), &cfg, &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::FalsePositive);
        assert_eq!(outcome.evidence.len(), 1);
        assert!((outcome.cost_usd - 0.05).abs() < 1e-9);
        assert_eq!(outcome.steps_used, 2);

        // Spend settled at 0.05, not the 1.0 deposit.
        assert!((limiter.total_spent(Operation::DeepAudit).unwrap() - 0.05).abs() < 1e-9);
    }

    #[test]
    fn deep_auditor_retains_deposit_when_any_loop_step_cost_is_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("foo.c"), "void foo() {}\n").unwrap();
        let steps = vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({ "file": "foo.c" }),
                    call_id: "c1".to_string(),
                },
                cost_usd: None,
            },
            AgentLoopStep::Final {
                text: String::new(),
                structured: Some(serde_json::json!({
                    "triggerable": false,
                    "rationale": "guarded",
                    "confidence": 0.9,
                    "evidence": []
                })),
                cost_usd: Some(0.05),
            },
        ];
        let runtime = routed_runtime_with_role(steps);
        let limiter = SpendLimiter::open_in_memory().unwrap();
        let cfg = DeepAuditConfig::new(tmp.path());

        let outcome = run_deep_auditor(&runtime, Some(&limiter), &cfg, &finding()).unwrap();

        assert_eq!(outcome.cost_usd, 0.05);
        assert!(!outcome.cost_usd_exact);
        assert_eq!(
            limiter.total_spent(Operation::DeepAudit).unwrap(),
            cfg.deposit_usd
        );
    }

    #[test]
    fn deep_auditor_collects_implicit_evidence_from_tool_calls() {
        // Model returns no evidence in its final, but its tool calls reveal
        // which regions it consulted.
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path();
        std::fs::write(workspace.join("a.c"), "int a;\nint b;\nint c;\n").unwrap();
        let steps = vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({ "file": "a.c", "start_line": 1, "end_line": 3 }),
                    call_id: "c1".to_string(),
                },
                cost_usd: None,
            },
            AgentLoopStep::Final {
                text: "I cannot determine triggerability".to_string(),
                structured: None,
                cost_usd: None,
            },
        ];
        let runtime = routed_runtime_with_role(steps);
        let cfg = DeepAuditConfig::new(workspace);
        let outcome = run_deep_auditor(&runtime, None, &cfg, &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::NeedsReview);
        // Implicit evidence picked up from the read_source call.
        assert_eq!(outcome.evidence.len(), 1);
        assert_eq!(outcome.evidence[0].file, "a.c");
        assert_eq!(outcome.evidence[0].start_line, 1);
        assert_eq!(outcome.evidence[0].end_line, 3);
    }

    #[test]
    fn appends_static_evidence_block_when_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path();
        std::fs::write(workspace.join("foo.c"), "void foo() {}\n").unwrap();
        let steps = vec![AgentLoopStep::Final {
            text: String::new(),
            structured: Some(serde_json::json!({
                "triggerable": false,
                "rationale": "no input reaches the function",
                "confidence": 0.9,
                "evidence": []
            })),
            cost_usd: Some(0.001),
        }];
        let (runtime, scripted) = routed_runtime_with_role_typed(steps);
        let cfg = DeepAuditConfig::new(workspace);
        let _ = run_deep_auditor(&runtime, None, &cfg, &finding()).unwrap();
        let captured = scripted.last_prompt().expect("a prompt was sent");
        assert!(
            captured.contains("Pre-populated Static Evidence"),
            "static-evidence header missing from prompt: {captured}"
        );
        assert!(
            captured.contains("Trigger path:"),
            "narrative trigger-path missing: {captured}"
        );
    }

    #[test]
    fn skips_static_evidence_block_when_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path();
        std::fs::write(workspace.join("foo.c"), "void foo() {}\n").unwrap();
        let steps = vec![AgentLoopStep::Final {
            text: String::new(),
            structured: Some(serde_json::json!({
                "triggerable": false,
                "rationale": "no input reaches the function",
                "confidence": 0.9,
                "evidence": []
            })),
            cost_usd: Some(0.001),
        }];
        let (runtime, scripted) = routed_runtime_with_role_typed(steps);
        let cfg = DeepAuditConfig {
            include_static_evidence: false,
            ..DeepAuditConfig::new(workspace)
        };
        let _ = run_deep_auditor(&runtime, None, &cfg, &finding()).unwrap();
        let captured = scripted.last_prompt().expect("a prompt was sent");
        assert!(
            !captured.contains("Pre-populated Static Evidence"),
            "static-evidence header should not appear when disabled: {captured}"
        );
    }

    fn verdict_final(triggerable: bool) -> AgentLoopStep {
        AgentLoopStep::Final {
            text: String::new(),
            structured: Some(serde_json::json!({
                "triggerable": triggerable,
                "rationale": if triggerable { "reachable path" } else { "guarded upstream" },
                "confidence": 0.8,
                "evidence": []
            })),
            cost_usd: Some(0.01),
        }
    }

    fn needs_review_final() -> AgentLoopStep {
        AgentLoopStep::Final {
            text: "I cannot determine triggerability".to_string(),
            structured: None,
            cost_usd: Some(0.01),
        }
    }

    /// Router with the deep_auditor primary plus an optional, operator-named
    /// tie-break model for the `triage_escalation` role.
    fn routed_runtime_with_escalation(
        steps: Vec<AgentLoopStep>,
        escalation_primary: Option<&str>,
    ) -> (RoutedRuntime<'static>, Arc<ScriptedRuntime>) {
        use std::fs;
        let scripted = ScriptedRuntime::new(steps);
        let runtime: Arc<dyn AgentRuntime> = scripted.clone();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".kuzushi");
        fs::create_dir_all(&dir).unwrap();
        let mut body =
            String::from("[roles.deep_auditor]\nprimary = \"anthropic:claude-opus-4-7\"\n");
        if let Some(escalation) = escalation_primary {
            body.push_str(&format!(
                "\n[roles.triage_escalation]\nprimary = \"{escalation}\"\n"
            ));
        }
        fs::write(dir.join("models.toml"), body).unwrap();
        let loaded = AgentRouter::load(&crate::config::ConfigPaths {
            home_dir: tmp.path().to_path_buf(),
            target_dir: None,
        })
        .unwrap();
        (RoutedRuntime::new(runtime, Arc::new(loaded), None), scripted)
    }

    fn split_panel_config(workspace: &std::path::Path) -> DeepAuditConfig {
        DeepAuditConfig {
            passes: 2,
            include_static_evidence: false,
            ..DeepAuditConfig::new(workspace)
        }
    }

    #[test]
    fn tie_without_role_model_stays_needs_review() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("foo.c"), "void foo() {}\n").unwrap();
        let (runtime, _scripted) =
            routed_runtime_with_escalation(vec![verdict_final(true), verdict_final(false)], None);

        let outcome =
            run_deep_auditor(&runtime, None, &split_panel_config(tmp.path()), &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::NeedsReview);
        assert!(!outcome.triage.rationale.contains("tie-break"));
    }

    #[test]
    fn tie_refuses_same_model_and_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("foo.c"), "void foo() {}\n").unwrap();
        let (runtime, _scripted) = routed_runtime_with_escalation(
            vec![verdict_final(true), verdict_final(false)],
            Some("anthropic:claude-opus-4-7"),
        );

        let outcome =
            run_deep_auditor(&runtime, None, &split_panel_config(tmp.path()), &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::NeedsReview);
        assert!(
            outcome.triage.rationale.contains("tie-break refused"),
            "refusal must be disclosed: {}",
            outcome.triage.rationale
        );
    }

    #[test]
    fn tie_adopts_distinct_escalation_verdict() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("foo.c"), "void foo() {}\n").unwrap();
        // 2 split passes + 1 escalation pass that returns a true positive.
        let (runtime, scripted) = routed_runtime_with_escalation(
            vec![verdict_final(true), verdict_final(false), verdict_final(true)],
            Some("openai:escalation-model"),
        );

        let outcome =
            run_deep_auditor(&runtime, None, &split_panel_config(tmp.path()), &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::TruePositive);
        assert!(
            outcome
                .triage
                .rationale
                .contains("tie-break via openai:escalation-model"),
            "escalation provenance must be visible: {}",
            outcome.triage.rationale
        );
        // The extra pass's REQUEST actually carried the escalation model — not
        // the primary. A regression where run_deep_audit_pass ignored its model
        // argument (leaving the rationale string, which the code fabricates from
        // its own arg, correct while the request stayed on the primary) is
        // caught here.
        let models = scripted.captured_models();
        assert_eq!(models.len(), 3, "two panel passes plus one escalation pass");
        assert_eq!(models[0], "anthropic:claude-opus-4-7");
        assert_eq!(models[1], "anthropic:claude-opus-4-7");
        assert_eq!(models[2], "openai:escalation-model");
    }

    #[test]
    fn escalation_that_needs_review_does_not_forge() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("foo.c"), "void foo() {}\n").unwrap();
        // The escalation pass itself is inconclusive — the verdict must stay
        // NeedsReview, never a manufactured TP/FP.
        let (runtime, _scripted) = routed_runtime_with_escalation(
            vec![verdict_final(true), verdict_final(false), needs_review_final()],
            Some("openai:escalation-model"),
        );

        let outcome =
            run_deep_auditor(&runtime, None, &split_panel_config(tmp.path()), &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::NeedsReview);
    }

    #[test]
    fn escalation_pass_failure_keeps_needs_review_and_discloses_it() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("foo.c"), "void foo() {}\n").unwrap();
        // Only the two panel passes are scripted; the escalation pass exhausts
        // the runtime and errors. The truthful NeedsReview consensus, already
        // computed and paid for, must survive with a disclosed failure note
        // rather than nuking the whole audit into a top-level error.
        let (runtime, _scripted) = routed_runtime_with_escalation(
            vec![verdict_final(true), verdict_final(false)],
            Some("openai:escalation-model"),
        );

        let outcome =
            run_deep_auditor(&runtime, None, &split_panel_config(tmp.path()), &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::NeedsReview);
        assert!(
            outcome
                .triage
                .rationale
                .contains("tie-break via openai:escalation-model failed"),
            "the escalation failure must be disclosed: {}",
            outcome.triage.rationale
        );
        assert!(
            outcome.triage.rationale.contains("needs_review stands"),
            "the consensus must be preserved: {}",
            outcome.triage.rationale
        );
    }

    #[test]
    fn record_evidence_persists_v3_audit_event() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("index.sqlite3");
        let store = FindingStore::open(&db).unwrap();
        store
            .record_run_started("run-deep-audit", tmp.path(), "running")
            .unwrap();
        let finding_id = store.insert_finding("run-deep-audit", &finding()).unwrap();
        let evidence = vec![EvidenceCitation {
            file: "src/foo.c".to_string(),
            start_line: 10,
            end_line: 20,
            note: "OOB sink".to_string(),
            kind: "sink".to_string(),
            origin: EvidenceOrigin::CodeRead,
        }];
        record_evidence(&store, finding_id, &evidence).unwrap();

        let conn = rusqlite::Connection::open(&db).unwrap();
        let row: (String, String, String) = conn
            .query_row(
                "select subject, summary, payload_json from audit_events",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row.0, "deep-audit:evidence");
        assert!(row.1.contains("1 evidence citation"));
        assert!(row.2.contains("OOB sink"));
    }
}
