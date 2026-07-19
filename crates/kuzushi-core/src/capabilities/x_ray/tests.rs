#[cfg(test)]
mod tests {
    use super::super::domain::{
        is_likely_entry_label, REQUIRED_ARCHITECTURE_SVG, REQUIRED_ENTRY_POINTS_MD,
        REQUIRED_INVARIANTS_MD, REQUIRED_X_RAY_MD,
    };
    use super::super::*;
    use crate::artifact_kb::{ArtifactKnowledgeRecord, ArtifactKnowledgeStore};
    use crate::config::V2Config;
    use crate::modules::ToolExecutionContext;
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
    use crate::{TriageOutcome, TriageVerdict, WorkspaceTarget};
    use anyhow::Result;
    use serde_json::{json, Value};
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct MockRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
        response: AgentQueryResponse,
    }

    impl MockRuntime {
        fn new(response: AgentQueryResponse) -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
                response,
            }
        }

        fn queries(&self) -> Vec<AgentQueryRequest> {
            self.queries.lock().unwrap().clone()
        }
    }

    impl AgentRuntime for MockRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.queries.lock().unwrap().push(request);
            Ok(self.response.clone())
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome {
                verdict: TriageVerdict::NeedsReview,
                confidence: 0.0,
                rationale: "unused".to_string(),
                ..Default::default()
            })
        }
    }

    #[test]
    fn likely_entry_label_accepts_code_shapes_and_rejects_noise() {
        assert!(is_likely_entry_label(" deposit(uint256 amount) "));
        assert!(is_likely_entry_label("Vault::withdraw"));
        assert!(is_likely_entry_label("api.transfer"));
        assert!(is_likely_entry_label("rebalance"));
        assert!(!is_likely_entry_label(" 12345 "));
    }

    fn write_fixture(root: &Path) {
        let dir = root.join("x-ray");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(REQUIRED_X_RAY_MD),
            "# X-Ray\n\n## X-Ray Verdict\nREADY\nThe protocol has clear core flows.\n",
        )
        .unwrap();
        fs::write(
            dir.join(REQUIRED_ENTRY_POINTS_MD),
            "# Entry Points\n\n> TinyVault | 4 entry points | 2 permissionless | 1 role-gated | 1 admin-only\n\n## Permissionless Entry Points\n### deposit(uint256 amount)\n### withdraw(uint256 shares)\n",
        )
        .unwrap();
        fs::write(
            dir.join(REQUIRED_INVARIANTS_MD),
            "# Invariants\n\n### G-1 Total assets cover shares\n### G2 No stale accounting\n### I-1 Oracle bounds\n### X-1 Bridge replay\n### E-1 Fee conservation\n",
        )
        .unwrap();
        fs::write(
            dir.join(REQUIRED_ARCHITECTURE_SVG),
            r#"<svg xmlns="http://www.w3.org/2000/svg" />"#,
        )
        .unwrap();
    }

    fn context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
cancellation: None,
authorization: Default::default(),
        }
    }

    #[test]
    fn reads_existing_x_ray_artifacts() {
        let tmp = tempdir().unwrap();
        write_fixture(tmp.path());
        let data = read_x_ray_report_artifacts(tmp.path(), None, "rust", 0.0).unwrap();

        assert_eq!(data.verdict.tier.as_deref(), Some("READY"));
        assert_eq!(data.verdict.summary, "The protocol has clear core flows.");
        assert_eq!(data.entry_point_counts.total, 4);
        assert_eq!(data.entry_point_counts.permissionless, 2);
        assert_eq!(data.invariant_counts.global, 2);
        assert_eq!(data.invariant_counts.total, 5);
    }

    #[test]
    fn parses_label_colon_entry_point_summary_counts() {
        let tmp = tempdir().unwrap();
        write_fixture(tmp.path());
        fs::write(
            tmp.path().join("x-ray").join(REQUIRED_ENTRY_POINTS_MD),
            "# Entry Points\n\n**Summary:** total: 6, permissionless: 6, role-gated: 0, admin-only: 0\n",
        )
        .unwrap();

        let data = read_x_ray_report_artifacts(tmp.path(), None, "rust", 0.0).unwrap();

        assert_eq!(data.entry_point_counts.total, 6);
        assert_eq!(data.entry_point_counts.permissionless, 6);
        assert_eq!(data.entry_point_counts.role_gated, 0);
        assert_eq!(data.entry_point_counts.admin_only, 0);
    }

    #[test]
    fn run_writes_structured_langgraph_runtime_artifacts() {
        let tmp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let runtime = MockRuntime::new(AgentQueryResponse {
            text: String::new(),
            structured: Some(json!({
                "xRayMarkdown": "# X-Ray\n\n## X-Ray Verdict\nWATCH\nReview invariants before launch.\n",
                "entryPointsMarkdown": "# Entry Points\n\n> App | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n",
                "invariantsMarkdown": "# Invariants\n\n### G-1 Balance conservation\n",
                "architectureSvg": "<svg xmlns=\"http://www.w3.org/2000/svg\" />\n",
            })),
            ..Default::default()
        });

        let output = execute_x_ray_tool(
            "x-ray:run",
            json!({"X_RAY_PROMPT": "custom x-ray system", "maxBudgetUsd": 0.25}),
            &context(&config, &workspace),
            Some(&runtime),
        )
        .unwrap();

        assert_eq!(output.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_x_ray_envelope(&output, "x-ray:run complete");
        assert!(workspace.root().join("x-ray/x-ray.md").exists());
        assert!(output
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("x-ray:run complete"));
        assert_eq!(runtime.queries().len(), 1);
        assert_eq!(runtime.queries()[0].model, "openai:gpt-4.1");
        assert_eq!(runtime.queries()[0].system_prompt, "custom x-ray system");
        assert!(runtime.queries()[0]
            .prompt
            .contains("missing local artifact KB"));
        assert!(runtime.queries()[0]
            .prompt
            .contains("Observed-spend stop requested by operator"));
        assert_eq!(
            runtime.queries()[0]
                .runtime_options
                .as_ref()
                .and_then(|options| options.observed_spend_stop_usd),
            Some(0.25)
        );
    }

    #[test]
    fn run_includes_matching_artifact_kb_snippets() {
        let tmp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = ArtifactKnowledgeStore::open(&workspace).unwrap();
        store
            .upsert_record(&ArtifactKnowledgeRecord::from_body(
                "manual://x-ray-note",
                "context",
                None,
                "context snapshot",
                "The repository has a permissionless payment entry point and a ledger invariant.",
                vec!["src/routes.ts:7".to_string()],
                json!({"sourceKind": "manual-test"}),
            ))
            .unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let runtime = MockRuntime::new(AgentQueryResponse {
            text: String::new(),
            structured: Some(json!({
                "xRayMarkdown": "# X-Ray\n\n## X-Ray Verdict\nWATCH\nReview invariants before launch.\n",
                "entryPointsMarkdown": "# Entry Points\n\n> App | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n",
                "invariantsMarkdown": "# Invariants\n\n### G-1 Ledger conservation\n",
                "architectureSvg": "<svg xmlns=\"http://www.w3.org/2000/svg\" />\n",
            })),
            ..Default::default()
        });

        let output = execute_x_ray_tool(
            "x-ray:run",
            json!({}),
            &context(&config, &workspace),
            Some(&runtime),
        )
        .unwrap();

        let query = runtime.queries().pop().unwrap();
        assert!(query.prompt.contains("Local artifact KB context"));
        assert!(query.prompt.contains("permissionless payment entry point"));
        assert_eq!(
            output
                .pointer("/data/kbContext/snippets/0/moduleId")
                .and_then(Value::as_str),
            Some("context")
        );
    }

    #[test]
    fn run_requires_explicit_model_without_fallback() {
        let tmp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let config = V2Config::default();
        let runtime = MockRuntime::new(AgentQueryResponse {
            text: String::new(),
            structured: None,
            ..Default::default()
        });

        let err = execute_x_ray_tool(
            "x-ray:run",
            json!({}),
            &context(&config, &workspace),
            Some(&runtime),
        )
        .unwrap_err();

        assert!(err.to_string().contains("explicit model"));
        assert!(runtime.queries().is_empty());
    }

    #[test]
    fn read_reports_missing_required_artifacts() {
        let tmp = tempdir().unwrap();
        fs::create_dir(tmp.path().join("x-ray")).unwrap();
        fs::write(tmp.path().join("x-ray/x-ray.md"), "# X-Ray\n").unwrap();

        let err = read_x_ray_report_artifacts(tmp.path(), None, "rust", 0.0).unwrap_err();
        assert!(format!("{err:#}").contains("missing or has unsafe required artifact"));
    }

    #[test]
    fn read_accepts_explicit_target_path() {
        let tmp = tempdir().unwrap();
        write_fixture(tmp.path());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let config = V2Config::default();

        let output = execute_x_ray_tool(
            "x-ray:read",
            json!({"target": tmp.path().display().to_string()}),
            &context(&config, &workspace),
            None,
        )
        .unwrap();

        assert_eq!(output.get("ok").and_then(Value::as_bool), Some(true));
        assert_completed_x_ray_envelope(&output, "x-ray:read loaded artifacts");
    }

    #[test]
    fn read_rejects_explicit_file_target() {
        let tmp = tempdir().unwrap();
        let target_file = tmp.path().join("not-a-dir.txt");
        fs::write(&target_file, "not a directory").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let config = V2Config::default();

        let err = execute_x_ray_tool(
            "x-ray:read",
            json!({"target": target_file.display().to_string()}),
            &context(&config, &workspace),
            None,
        )
        .unwrap_err();

        assert!(err.to_string().contains("Target must be a directory"));
    }

    #[test]
    fn read_rejects_missing_explicit_target() {
        let tmp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let config = V2Config::default();

        let err = execute_x_ray_tool(
            "x-ray:read",
            json!({"target": tmp.path().join("missing").display().to_string()}),
            &context(&config, &workspace),
            None,
        )
        .unwrap_err();

        assert!(err.to_string().contains("Could not resolve target"));
    }

    fn assert_completed_x_ray_envelope(output: &Value, summary_prefix: &str) {
        assert_eq!(output.get("status").and_then(Value::as_str), Some("completed"));
        assert!(output
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|summary| summary.starts_with(summary_prefix)));
        assert!(output
            .get("artifacts")
            .and_then(Value::as_array)
            .is_some_and(|artifacts| artifacts.len() == 4));
        assert!(output
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty));
    }
}
