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

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

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
    fn scoped_plan_includes_non_c_sources_verbatim() {
        let body = "// padding\n".repeat(1_500);
        let tmp = make_workspace(&[
            ("src/Throttle.scala", &body),
            ("src/conf.py", &body),
            ("src/tmpl.j2", &body),
            ("src/unscoped.scala", &body),
        ]);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            scope_files: Some(vec![
                PathBuf::from("src/Throttle.scala"),
                PathBuf::from("src/conf.py"),
                PathBuf::from("src/tmpl.j2"),
                PathBuf::from("src/tmpl.j2"), // duplicate scope line plans once
            ]),
            ..Default::default()
        };
        let plan = plan(&cfg).unwrap();
        let mut paths: Vec<&str> = plan
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(|f| f.path.as_str()))
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["src/Throttle.scala", "src/conf.py", "src/tmpl.j2"]
        );
    }

    /// The PowerShellExecutor.cpp regression: a scoped file larger than
    /// MAX_FILE_BYTES was silently dropped from the plan (zero coverage of
    /// the shard's primary seed file, no diagnostic). Oversized files must
    /// now plan as contiguous line-aligned window buckets.
    #[test]
    fn oversized_scoped_file_windows_instead_of_dropping() {
        let line = format!("{}\n", "y".repeat(99)); // 100 bytes/line
        let lines = MAX_FILE_BYTES / 100 + 500; // ~1.17 windows worth
        let big = line.repeat(lines);
        assert!(big.len() > MAX_FILE_BYTES);
        let tmp = make_workspace(&[("src/huge.cpp", &big), ("src/small.c", "void s(){}\n")]);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            scope_files: Some(vec![
                PathBuf::from("src/huge.cpp"),
                PathBuf::from("src/small.c"),
            ]),
            ..Default::default()
        };
        let plan = plan(&cfg).unwrap();
        let windows: Vec<_> = plan
            .chunks
            .iter()
            .flat_map(|c| c.files.iter())
            .filter(|f| f.path == "src/huge.cpp")
            .collect();
        assert_eq!(windows.len(), 2, "334KB-class file must yield 2 windows");
        // Contiguous byte coverage of the whole file, line-aligned.
        assert_eq!(windows[0].start_byte, 0);
        assert_eq!(windows[0].start_line, 1);
        assert!(windows[0].bytes <= MAX_FILE_BYTES);
        assert_eq!(windows[1].start_byte, windows[0].bytes);
        assert_eq!(windows[1].start_line, windows[0].bytes / 100 + 1);
        assert_eq!(windows[0].bytes + windows[1].bytes, big.len());
        assert!(windows[1].is_window());
        // The small scoped sibling still plans as a whole file.
        assert!(plan
            .chunks
            .iter()
            .flat_map(|c| c.files.iter())
            .any(|f| f.path == "src/small.c" && !f.is_window()));
    }

    /// Window buckets render the correct slice with a window header, and
    /// the chunk executor restores absolute lines from `start_line`.
    #[test]
    fn window_bucket_renders_slice_and_lines_restore() {
        use super::super::application::{render_chunk_prompt, restore_absolute_lines};
        use crate::findings::Finding;

        let body = "line one\nline two\nline three\nline four\n";
        let tmp = make_workspace(&[("src/win.cpp", body)]);
        // Window covering "line three\nline four\n" (starts at byte 18, line 3).
        let window = FileBucket {
            path: "src/win.cpp".to_string(),
            bytes: body.len() - 18,
            est_tokens: 10,
            start_byte: 18,
            start_line: 3,
        };
        let chunk = ChunkPlan {
            id: 0,
            files: vec![window],
            est_tokens: 10,
        };
        let prompt = render_chunk_prompt(tmp.path(), &chunk).unwrap();
        assert!(prompt.contains("line three"));
        assert!(
            !prompt.contains("line one"),
            "window must not leak the prefix"
        );
        assert!(prompt.contains("first line is line 3"));

        let mut findings = vec![Finding::new_tool(
            "full-mode-multi",
            "full-mode-multi/scan",
            "src/win.cpp",
            1, // window-relative: first visible line = real line 3
            Some(2),
            Severity::Low,
            "window finding",
        )];
        restore_absolute_lines(&chunk, &mut findings);
        assert_eq!(findings[0].start_line, 3);
        assert_eq!(findings[0].end_line, Some(4));
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
            coverage: None,
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
    fn full_mode_model_ignores_env_model_channel() {
        let _guard = EnvVarGuard::set("MODEL_FULL_MODE_MULTI", "anthropic:claude-haiku-4-5");
        let tmp = make_workspace(&[("src/a.c", "void a(){}")]);
        let inner: Arc<dyn AgentRuntime> = Arc::new(PanickingRuntime);
        let runtime = RoutedRuntime::new(inner, Arc::new(AgentRouter::empty()), None);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let error = run(&runtime, None, &cfg).unwrap_err().to_string();

        assert!(error.contains("no model configured"), "{error}");
        assert!(!error.contains("export MODEL_FULL_MODE_MULTI"), "{error}");
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
    fn successful_unpriced_chunk_keeps_exact_total_unavailable() {
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body), ("src/b.c", &body)]);
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Costed("[]".to_string(), 0.4),
            ScriptedItem::Unpriced("[]".to_string()),
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

        assert_eq!(report.cost_usd, None);
        assert!((report.observed_cost_usd - 0.4).abs() < 1e-9);
        assert!(report.unresolved_provider_spend);
        assert_eq!(report.chunks_dispatched, 2);
        assert_eq!(report.chunks_failed, 0);
        let spent = limiter.total_spent(Operation::FullModeMulti).unwrap();
        assert!((spent - 1.9).abs() < 1e-9, "got {spent}");
        let output = report_to_tool_json(&report);
        assert!(output.get("costUsd").is_none());
        assert_eq!(output["data"]["costUsd"], serde_json::Value::Null);
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

    #[test]
    fn disabling_cache_after_a_cached_pass_uses_fresh_discovery() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let tmp = make_workspace(&[("src/owned.c", "// Owned inert metadata. Never executed.\n")]);
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Costed("[]".into(), 0.1),
            ScriptedItem::Costed(r#"[{"file":"src/owned.c","line":1,"severity":"low","title":"Owned policy signal","rationale":"Scripted changed opinion; no vulnerability is claimed."}]"#.into(), 0.1),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("openai-codex:gpt-5.5")),
            None,
        );
        let mut cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let first = run(&runtime, None, &cfg).unwrap();
        assert_eq!(first.chunks_from_cache, 0);
        assert!(first.findings.is_empty());
        cfg.reuse_cached_chunks = false;
        let second = run(&runtime, None, &cfg).unwrap();
        assert_eq!(second.chunks_from_cache, 0);
        assert_eq!(second.chunks_dispatched, 1);
        assert_eq!(second.findings.len(), 1);
        assert_eq!(second.findings[0].file_path, "src/owned.c");
    }

    #[test]
    fn rerunning_an_unchanged_scan_replays_every_chunk_from_cache() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body), ("src/b.c", &body)]);
        // Enough scripted responses for the FIRST run only: a second live
        // call on any chunk would exhaust the script and fail the chunk.
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Costed("[]".to_string(), 0.4),
            ScriptedItem::Costed(
                r#"[{"file":"src/b.c","line":7,"function":"g","severity":"high","cwe":[],"title":"t","rationale":"r"}]"#.to_string(),
                0.4,
            ),
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

        let first = run(&runtime, None, &cfg).unwrap();
        assert_eq!(first.chunks_from_cache, 0);
        assert!((first.observed_cost_usd - 0.8).abs() < 1e-9);

        let second = run(&runtime, None, &cfg).unwrap();

        assert_eq!(second.chunks_dispatched, first.chunks_dispatched);
        assert_eq!(second.chunks_from_cache, second.chunks_dispatched);
        assert_eq!(second.chunks_failed, 0);
        assert_eq!(second.findings.len(), first.findings.len());
        assert_eq!(second.cost_usd, Some(0.0));
        let summary = report_to_tool_json(&second)["summary"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(summary.contains("replayed from cache"), "{summary}");
    }

    #[test]
    fn editing_one_file_only_pays_for_the_chunks_the_edit_touched() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body), ("src/b.c", &body)]);
        // First run: two chunks. Second run: only the edited chunk goes live.
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Ok("[]".to_string()),
            ScriptedItem::Ok("[]".to_string()),
            ScriptedItem::Ok(
                r#"[{"file":"src/b.c","line":1,"function":"f","severity":"low","cwe":[],"title":"new","rationale":"r"}]"#.to_string(),
            ),
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
        let first = run(&runtime, None, &cfg).unwrap();
        assert_eq!(first.chunks_dispatched, 2);

        fs::write(tmp.path().join("src/b.c"), format!("{body}// edited\n")).unwrap();
        let second = run(&runtime, None, &cfg).unwrap();

        assert_eq!(second.chunks_dispatched, 2);
        assert_eq!(second.chunks_from_cache, 1);
        assert_eq!(second.findings.len(), 1);
        assert_eq!(second.findings[0].file_path, "src/b.c");
    }

    #[test]
    fn prefilter_routes_low_risk_chunks_away_from_the_deep_scan() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body), ("src/b.c", &body)]);
        // Call order: chunk 0 prefilter (low -> skip), chunk 1 prefilter
        // (high), chunk 1 deep scan.
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Costed(r#"{"score": 1, "reason": "pure padding"}"#.to_string(), 0.01),
            ScriptedItem::Costed(r#"{"score": 9, "reason": "parses input"}"#.to_string(), 0.01),
            ScriptedItem::Costed(
                r#"[{"file":"src/b.c","line":2,"function":"f","severity":"high","cwe":[],"title":"t","rationale":"r"}]"#.to_string(),
                0.5,
            ),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 4_000,
            prefilter_model: Some("anthropic:claude-haiku-4-5".to_string()),
            ..Default::default()
        };

        let report = run(&runtime, None, &cfg).unwrap();

        assert_eq!(report.chunks_dispatched, 1);
        assert_eq!(report.prefiltered_chunks.len(), 1);
        assert_eq!(report.prefiltered_chunks[0].score, 1);
        assert_eq!(report.prefiltered_chunks[0].reason, "pure padding");
        assert_eq!(report.chunks_failed, 0);
        assert_eq!(report.findings.len(), 1);
        // Prefilter spend still lands in the run total.
        assert!((report.observed_cost_usd - 0.52).abs() < 1e-9);
        let summary = report_to_tool_json(&report)["summary"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(summary.contains("1 chunk prefiltered out"), "{summary}");
    }

    #[test]
    fn legacy_report_json_without_cache_fields_still_deserializes() {
        let legacy = serde_json::json!({
            "findings": [],
            "plan": {"chunks": [], "total_files": 0, "total_bytes": 0, "total_tokens": 0},
            "chunks_dispatched": 3,
            "chunks_failed": 0,
            "dry_run": false
        });
        let report: FullModeReport = serde_json::from_value(legacy).unwrap();
        assert_eq!(report.chunks_from_cache, 0);
        assert!(report.prefiltered_chunks.is_empty());
    }

    #[test]
    fn legacy_config_json_defaults_to_reusing_cached_chunks() {
        let legacy = serde_json::json!({
            "workspace_root": ".",
            "max_tokens_per_chunk": 12000,
            "deposit_usd_per_chunk": 2.0,
            "language": "c",
            "dry_run": false
        });
        let cfg: FullModeConfig = serde_json::from_value(legacy).unwrap();
        assert!(cfg.reuse_cached_chunks);
        assert_eq!(cfg.prefilter_model, None);
    }

    // -- Test runtime helpers ------------------------------------------------

    #[test]
    fn a_partial_source_plan_is_readable_but_never_reaches_the_runtime() {
        let root = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(root.path().join("large.c")).unwrap();
        file.set_len(crate::workspace::MAX_REPOSITORY_INSPECTED_BYTES as u64 + 1)
            .unwrap();
        let runtime = RoutedRuntime::new(
            Arc::new(PanickingRuntime),
            Arc::new(AgentRouter::empty()),
            None,
        );
        let mut cfg = FullModeConfig {
            workspace_root: root.path().into(),
            scope_files: Some(vec!["large.c".into()]),
            dry_run: true,
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert_eq!(report.chunks_dispatched, 0);
        assert_eq!(report_to_tool_json(&report)["status"], "partial");
        assert_eq!(
            report_to_tool_json(&report)["summary"],
            "Partial source plan: 1 omitted, including large.c. No scan ran."
        );
        cfg.dry_run = false;
        assert!(format!("{:#}", run(&runtime, None, &cfg).unwrap_err())
            .contains("No model request started."));
    }

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
        Costed(String, f64),
        Unpriced(String),
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
        fn semantic_cache_identity(
            &self,
            _request: &AgentQueryRequest,
        ) -> Option<crate::identity::Blake3Hash> {
            Some(crate::identity::hash_parts("scripted-full-mode:v1", &[]))
        }

        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let mut q = self.items.lock().unwrap();
            anyhow::ensure!(!q.is_empty(), "scripted runtime exhausted");
            match q.remove(0) {
                ScriptedItem::Ok(text) => Ok(AgentQueryResponse {
                    text,
                    structured: None,
                    cost_usd_reported: true,
                    ..Default::default()
                }),
                ScriptedItem::Costed(text, cost_usd) => Ok(AgentQueryResponse {
                    text,
                    structured: None,
                    cost_usd,
                    cost_usd_reported: true,
                    ..Default::default()
                }),
                ScriptedItem::Unpriced(text) => Ok(AgentQueryResponse {
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
