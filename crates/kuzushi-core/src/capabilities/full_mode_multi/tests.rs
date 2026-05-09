#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::config::ConfigPaths;
    use crate::findings::{Severity, TriageOutcome};
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
    use crate::spend::{Operation, SpendLimiter};
    use anyhow::Result;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    fn make_workspace(files: &[(&str, &str)]) -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        for (name, body) in files {
            let p = tmp.path().join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, body).unwrap();
        }
        tmp
    }

    #[test]
    fn plan_groups_files_into_token_bounded_chunks() {
        let big = "x".repeat(10 * 1024); // ~2.7k tokens
        let tmp = make_workspace(&[
            ("src/a.c", &big),
            ("src/b.c", &big),
            ("src/c.c", &big),
            ("ignored.txt", "not c"),
        ]);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 5_000, // forces multiple chunks
            ..Default::default()
        };
        let plan = plan(&cfg).unwrap();
        assert!(plan.chunks.len() >= 2, "expected multiple chunks");
        assert_eq!(plan.total_files, 3);
        // Files sorted by path → chunks are directory-affine.
        let chunk0_paths: Vec<&str> = plan.chunks[0]
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert!(chunk0_paths.iter().any(|p| p.starts_with("src/")));
    }

    #[test]
    fn scope_files_filter_narrows_the_plan_to_diff_set() {
        let big = "// padding\n".repeat(1_500);
        let tmp = make_workspace(&[("src/a.c", &big), ("src/b.c", &big), ("src/c.c", &big)]);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            scope_files: Some(vec![PathBuf::from("src/b.c")]),
            ..Default::default()
        };
        let plan = plan(&cfg).unwrap();
        let paths: Vec<&str> = plan
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(|f| f.path.as_str()))
            .collect();
        assert_eq!(paths, vec!["src/b.c"]);
    }

    #[test]
    fn plan_skips_skip_dirs() {
        let tmp = make_workspace(&[
            ("src/keep.c", "void k(){}"),
            (".git/HEAD", "ref: refs/heads/main"),
            ("node_modules/pkg/src/skip.c", "void s(){}"),
            ("target/build/skip.c", "void s(){}"),
        ]);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let plan = plan(&cfg).unwrap();
        let paths: Vec<&str> = plan
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(|f| f.path.as_str()))
            .collect();
        assert_eq!(paths, vec!["src/keep.c"]);
    }

    #[test]
    fn cost_summary_scales_with_tokens() {
        let plan = FullModePlan {
            chunks: vec![],
            total_files: 100,
            total_bytes: 1_000_000,
            total_tokens: 280_000, // ~1MB at 3.6 B/T
        };
        let summary = cost_summary(&plan, Some("anthropic:claude-haiku-4-5"));
        assert_eq!(summary.total_tokens, 280_000);
        assert!(summary.usd_low > 0.0);
        assert!(summary.usd_high > summary.usd_low);
        let opus_summary = cost_summary(&plan, Some("anthropic:claude-opus-4-7"));
        // Opus is ~10× more expensive than haiku at the high band.
        assert!(opus_summary.usd_high > summary.usd_high * 5.0);
    }

    #[test]
    fn dry_run_produces_plan_without_calling_model() {
        let tmp = make_workspace(&[("src/a.c", "void a(){}")]);
        let inner: Arc<dyn AgentRuntime> = Arc::new(PanickingRuntime);
        let runtime = RoutedRuntime::new(
            inner,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            dry_run: true,
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.plan.total_files, 1);
        assert_eq!(report.findings.len(), 0);
    }

    #[test]
    fn dispatches_each_chunk_and_aggregates_findings() {
        let big = "// padding\n".repeat(2_000); // each ~3k tokens
        let tmp = make_workspace(&[("src/a.c", &big), ("src/b.c", &big), ("src/c.c", &big)]);
        let runtime_inner = ScriptedRuntime::new(vec![
            r#"[{"file":"src/a.c","line":42,"function":"foo","severity":"high","cwe":["CWE-787"],"title":"OOB write","rationale":"unbounded copy"}]"#.to_string(),
            r#"[]"#.to_string(),
            r#"[{"file":"src/c.c","line":99,"function":"bar","severity":"medium","cwe":["CWE-125"],"title":"OOB read","rationale":"missing length check"}]"#.to_string(),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner.clone() as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 4_000,
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert!(report.plan.chunks.len() >= 3);
        assert_eq!(report.chunks_dispatched, report.plan.chunks.len() as u32);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].file_path, "src/a.c");
        assert_eq!(report.findings[0].start_line, 42);
        assert_eq!(report.findings[0].severity, Severity::High);
        assert_eq!(report.findings[1].file_path, "src/c.c");
    }

    #[test]
    fn one_failing_chunk_does_not_abort_pass() {
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body), ("src/b.c", &body)]);
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Ok(
                r#"[{"file":"src/a.c","line":1,"function":"f","severity":"low","cwe":[],"title":"t","rationale":"r"}]"#.to_string(),
            ),
            ScriptedItem::Err("simulated transport error".to_string()),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 4_000,
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert_eq!(report.chunks_failed, 1);
        assert_eq!(report.chunks_dispatched, 1);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn spend_ledger_settles_each_chunk_even_on_failure() {
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body), ("src/b.c", &body)]);
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Ok("[]".to_string()),
            ScriptedItem::Err("fail".to_string()),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let limiter = SpendLimiter::open_in_memory().unwrap();
        limiter.set_cap(Operation::FullModeMulti, 100.0).unwrap();
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 4_000,
            deposit_usd_per_chunk: 1.5,
            ..Default::default()
        };
        let report = run(&runtime, Some(&limiter), &cfg).unwrap();
        assert_eq!(report.chunks_dispatched, 1);
        assert_eq!(report.chunks_failed, 1);
        // Successful chunk costs 1.5; failed chunk refunds to 0.
        let spent = limiter.total_spent(Operation::FullModeMulti).unwrap();
        assert!((spent - 1.5).abs() < 1e-9, "got {spent}");
    }

    #[test]
    fn malformed_responses_mark_chunk_failed_not_panic() {
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body)]);
        let runtime_inner = ScriptedRuntime::new(vec![
            "I don't know what to say".to_string(),
            "Still no JSON".to_string(),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.chunks_failed, 1);
        assert_eq!(report.chunks_dispatched, 0);
    }

    // -- Test runtime helpers ------------------------------------------------

    struct PanickingRuntime;
    impl AgentRuntime for PanickingRuntime {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            panic!("dry-run must not call the runtime")
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
    }

    #[derive(Clone)]
    struct ScriptedRuntime {
        responses: Arc<Mutex<Vec<String>>>,
    }
    impl ScriptedRuntime {
        fn new(responses: Vec<String>) -> Arc<Self> {
            Arc::new(Self {
                responses: Arc::new(Mutex::new(responses)),
            })
        }
    }
    impl AgentRuntime for ScriptedRuntime {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let mut q = self.responses.lock().unwrap();
            anyhow::ensure!(!q.is_empty(), "scripted runtime exhausted");
            Ok(AgentQueryResponse {
                text: q.remove(0),
                structured: None,
                ..Default::default()
            })
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
    }

    enum ScriptedItem {
        Ok(String),
        Err(String),
    }

    #[derive(Clone)]
    struct ScriptedRuntimeMixed {
        items: Arc<Mutex<Vec<ScriptedItem>>>,
    }
    impl ScriptedRuntimeMixed {
        fn new(items: Vec<ScriptedItem>) -> Arc<Self> {
            Arc::new(Self {
                items: Arc::new(Mutex::new(items)),
            })
        }
    }
    impl AgentRuntime for ScriptedRuntimeMixed {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let mut q = self.items.lock().unwrap();
            anyhow::ensure!(!q.is_empty(), "scripted runtime exhausted");
            match q.remove(0) {
                ScriptedItem::Ok(text) => Ok(AgentQueryResponse {
                    text,
                    structured: None,
                    ..Default::default()
                }),
                ScriptedItem::Err(message) => anyhow::bail!(message),
            }
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
    }

    fn router_with_full_mode_role(model: &str) -> AgentRouter {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join(".kuzushi");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("models.toml"),
            format!("[roles.full_mode_multi]\nprimary = \"{model}\"\n"),
        )
        .unwrap();
        let r = AgentRouter::load(&ConfigPaths {
            home_dir: tmp.path().to_path_buf(),
            target_dir: None,
        })
        .unwrap();
        let _ = tmp;
        r
    }
}
