use super::*;

pub(crate) fn tool_context_config_paths(
    ctx: &ToolExecutionContext<'_>,
    target_root: Option<&std::path::Path>,
) -> Result<crate::config::ConfigPaths> {
    let target = target_root.or_else(|| ctx.workspace.map(|workspace| workspace.root()));
    crate::config::ConfigPaths::from_target(target)
}

pub(crate) fn routed_runtime_for_tool_context<'a>(
    runtime: &'a dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    target_root: Option<&std::path::Path>,
) -> Result<crate::agent_router::RoutedRuntime<'a>> {
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use std::sync::Arc;

    let paths = tool_context_config_paths(ctx, target_root)?;
    let router = Arc::new(AgentRouter::load(&paths)?);
    let routed = RoutedRuntime::borrowed(runtime, router, ctx.config.model.clone());
    routed_runtime_with_persistent_options(routed, &paths)
}

pub(crate) fn persistent_tool_options_for_paths(
    paths: &crate::config::ConfigPaths,
) -> Result<crate::options::ToolOptionStore> {
    crate::options::ToolOptionStore::load_persistent(
        &paths.global_options_path(),
        paths.project_options_path().as_deref(),
    )
}

fn routed_runtime_with_persistent_options<'a>(
    routed: crate::agent_router::RoutedRuntime<'a>,
    paths: &crate::config::ConfigPaths,
) -> Result<crate::agent_router::RoutedRuntime<'a>> {
    let store = persistent_tool_options_for_paths(paths)?;
    Ok(routed.with_option_store(&store))
}

#[cfg(test)]
mod routed_runtime_option_tests {
    use super::*;

    struct NoopRuntime;

    impl AgentRuntime for NoopRuntime {
        fn triage_finding_blocking(
            &self,
            _request: crate::runtime::TriageRequest,
        ) -> Result<crate::findings::TriageOutcome> {
            anyhow::bail!("unused test runtime")
        }
    }

    #[test]
    fn routed_runtime_snapshots_persistent_role_options() {
        let temp = tempfile::tempdir().unwrap();
        let paths = test_config_paths(temp.path());
        write_deep_auditor_override(&paths);
        let routed = routed_runtime_with_persistent_options(test_routed_runtime(), &paths).unwrap();

        assert_eq!(
            routed
                .resolve_model_for_role(
                    crate::agent_router::AgentRole::DeepAuditor,
                    0,
                    Some("openai:operator-default"),
                )
                .unwrap(),
            "openai:setg-model"
        );
    }

    fn test_config_paths(root: &std::path::Path) -> crate::config::ConfigPaths {
        let home = root.join("home");
        let target = root.join("repo");
        std::fs::create_dir_all(home.join(".kuzushi/v3")).unwrap();
        std::fs::create_dir_all(target.join(".kuzushi/v3")).unwrap();
        crate::config::ConfigPaths {
            home_dir: home,
            target_dir: Some(target),
        }
    }

    fn write_deep_auditor_override(paths: &crate::config::ConfigPaths) {
        let mut store = crate::options::ToolOptionStore::new();
        store.set_value(
            crate::options::OptionScope::Global,
            crate::options::OptionTarget::All,
            "MODEL_DEEP_AUDITOR",
            json!("openai:setg-model"),
        );
        store
            .save_persistent(
                &paths.global_options_path(),
                paths.project_options_path().as_deref(),
            )
            .unwrap();
    }

    fn test_routed_runtime() -> crate::agent_router::RoutedRuntime<'static> {
        let runtime = NoopRuntime;
        crate::agent_router::RoutedRuntime::owned(
            std::sync::Arc::new(runtime),
            std::sync::Arc::new(crate::agent_router::AgentRouter::empty()),
            Some("openai:operator-default".to_string()),
        )
    }
}

pub(crate) fn full_mode_spend_limiter(
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<crate::spend::SpendLimiter>> {
    ctx.workspace
        .map(|w| {
            crate::spend::SpendLimiter::open_with_hard_ceiling(
                w.findings_db_path(),
                ctx.config.operator.spend_hard_ceiling_usd,
            )
        })
        .transpose()
}

pub(crate) fn persist_full_mode_report(
    ctx: &ToolExecutionContext<'_>,
    report: &mut crate::capabilities::full_mode_multi::FullModeReport,
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let store = FindingStore::open(workspace.findings_db_path())?;
    let scan_id = ctx.finding_run_id();
    let delta = store.with_run_lifecycle(&scan_id, workspace.root(), || {
        let delta = store.insert_findings_measuring_delta(&scan_id, &report.findings)?;
        Ok((delta, report.findings.len()))
    })?;
    for (finding, id) in report.findings.iter_mut().zip(&delta.row_ids) {
        finding.id = Some(*id);
    }
    crate::findings::emit_finding_delta(
        ctx.run_observation().as_ref(),
        &store,
        &report.findings,
        (delta.added, delta.updated),
    )
}

#[cfg(test)]
mod persist_full_mode_report_tests {
    use super::*;

    #[test]
    fn persist_emits_a_real_finding_delta() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = crate::WorkspaceTarget::new(temp.path()).unwrap();
        let mut report = test_report(vec![test_finding("rule-a"), test_finding("rule-b")]);

        let delta = persisted_delta(temp.path(), &workspace, "full-mode-delta", &mut report);

        assert_eq!((delta.added, delta.updated, delta.removed), (2, 0, 0));
        assert!(!delta.store_watermark.as_str().contains("unavailable"));
        assert_eq!(delta.finding_id_samples.len(), 2);
    }

    #[test]
    fn zero_findings_still_emit_a_delta_observation() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = crate::WorkspaceTarget::new(temp.path()).unwrap();
        let mut report = test_report(Vec::new());

        let delta = persisted_delta(temp.path(), &workspace, "full-mode-clean", &mut report);

        assert_eq!((delta.added, delta.updated), (0, 0));
        assert!(!delta.store_watermark.as_str().contains("unavailable"));
    }

    fn persisted_delta(
        target: &std::path::Path,
        workspace: &crate::WorkspaceTarget,
        run_id: &str,
        report: &mut crate::capabilities::full_mode_multi::FullModeReport,
    ) -> crate::run_lifecycle::FindingDeltaSummary {
        let config = crate::V2Config::default();
        {
            let trace =
                crate::run_artifacts::TraceHandle::observed_jsonl_with_delivery_subscribers(
                    target, run_id, None, None, None,
                )
                .unwrap();
            let ctx = ToolExecutionContext {
                config: &config,
                workspace: Some(workspace),
                findings_store: None,
                trace: Some(&trace),
                cancellation: None,
                authorization: Default::default(),
            };

            persist_full_mode_report(&ctx, report).unwrap();
            // The run-item writer commits asynchronously; dropping the trace
            // joins the writer thread so the projection read sees the delta.
        }

        let projection = crate::run_lifecycle::load_run_projection(target, run_id)
            .unwrap()
            .projection;
        assert_eq!(projection.finding_deltas.len(), 1);
        projection.finding_deltas.into_iter().next().unwrap()
    }

    fn test_report(
        findings: Vec<crate::findings::Finding>,
    ) -> crate::capabilities::full_mode_multi::FullModeReport {
        use crate::capabilities::full_mode_multi::{FullModePlan, FullModeReport};
        FullModeReport {
            findings,
            plan: FullModePlan {
                coverage: None,
                chunks: Vec::new(),
                total_files: 1,
                total_bytes: 64,
                total_tokens: 16,
            },
            chunks_dispatched: 1,
            chunks_from_cache: 0,
            prefiltered_chunks: Vec::new(),
            chunks_failed: 0,
            failed_chunk_errors: Vec::new(),
            cost_usd: Some(0.0),
            observed_cost_usd: 0.0,
            unresolved_provider_spend: false,
            dry_run: false,
            first_chunk_error: None,
        }
    }

    fn test_finding(rule_id: &str) -> crate::findings::Finding {
        crate::findings::Finding::new_tool(
            "full-mode",
            rule_id,
            "src/a.c",
            42,
            None,
            crate::findings::Severity::High,
            "test finding",
        )
    }
}
