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
    store.with_run_lifecycle(&scan_id, workspace.root(), || {
        for finding in &mut report.findings {
            finding.id = Some(store.insert_finding(&scan_id, finding)?);
        }
        Ok(((), report.findings.len()))
    })
}

pub(crate) fn run_classifier_score_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let run = prepare_classifier_score(&input, ctx, runtime)?;
    let routed = classifier_routed_runtime(run.runtime, ctx, run.workspace.root())?;
    let gate = classifier_gate(&routed, run.workspace, run.target_percentile)?;
    let (score, cost) = gate.score_with_cost(&run.finding, run.workspace.root())?;
    let should_audit = gate.should_deep_audit(score);
    let threshold = gate.current_threshold();
    let n = gate.samples_seen();
    save_classifier_skip_if_needed(&run, &gate, score, should_audit, cost)?;
    let mut result = classifier_score_response(&run.finding, score, should_audit, threshold, n);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

struct ClassifierScoreRun<'a> {
    runtime: &'a dyn AgentRuntime,
    workspace: &'a crate::WorkspaceTarget,
    store: FindingStore,
    finding: crate::findings::Finding,
    target_percentile: f32,
}

fn prepare_classifier_score<'a>(
    input: &Value,
    ctx: &'a ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<ClassifierScoreRun<'a>> {
    let runtime = required_classifier_runtime(runtime)?;
    let workspace = required_classifier_workspace(ctx)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = classifier_finding(input, &store)?;
    Ok(ClassifierScoreRun {
        runtime,
        workspace,
        store,
        finding,
        target_percentile: classifier_target_percentile(input),
    })
}

fn required_classifier_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| {
        anyhow::anyhow!(crate::runtime::missing_agent_runtime_message(
            "classifier-gate:score"
        ))
    })
}

fn required_classifier_workspace<'a>(
    ctx: &ToolExecutionContext<'a>,
) -> Result<&'a crate::WorkspaceTarget> {
    ctx.workspace.ok_or_else(|| {
        anyhow::anyhow!(crate::workspace::active_workspace_required_message(
            "classifier-gate:score"
        ))
    })
}

fn classifier_finding(input: &Value, store: &FindingStore) -> Result<crate::findings::Finding> {
    let fingerprint = input
        .get("findingFingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: findingFingerprint is required"))?;
    store
        .get_finding_by_reference(fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: no finding for {fingerprint:?}"))
}

fn classifier_target_percentile(input: &Value) -> f32 {
    input
        .get("targetPercentile")
        .and_then(Value::as_f64)
        .map(|v| v as f32)
        .unwrap_or(0.80)
}

fn classifier_routed_runtime<'a>(
    runtime: &'a dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    root: &std::path::Path,
) -> Result<crate::agent_router::RoutedRuntime<'a>> {
    routed_runtime_for_tool_context(runtime, ctx, Some(root))
}

fn classifier_gate<'a>(
    runtime: &'a crate::agent_router::RoutedRuntime<'a>,
    workspace: &crate::WorkspaceTarget,
    target_percentile: f32,
) -> Result<crate::capabilities::classifier_gate::LikelyVulnClassifier<'a>> {
    use crate::capabilities::classifier_gate::{ClassifierConfig, LikelyVulnClassifier};

    let cfg = ClassifierConfig {
        target_percentile,
        state_db: Some(workspace.findings_db_path()),
        ..Default::default()
    };
    LikelyVulnClassifier::new(runtime, cfg)
}

fn save_classifier_skip_if_needed(
    run: &ClassifierScoreRun<'_>,
    gate: &crate::capabilities::classifier_gate::LikelyVulnClassifier<'_>,
    score: f32,
    should_audit: bool,
    cost: crate::runtime::RuntimeCostReport,
) -> Result<()> {
    let Some(id) = run.finding.id.filter(|_| !should_audit) else {
        return Ok(());
    };
    let outcome = gate.skip_outcome_with_cost(score, cost);
    run.store.record_auto_triage(id, &outcome)
}

fn classifier_score_response(
    finding: &crate::findings::Finding,
    score: f32,
    should_audit: bool,
    threshold: f32,
    samples_seen: usize,
) -> Value {
    let summary = format!(
        "classifier-gate:score {:.3} ({})",
        score,
        if should_audit { "audit" } else { "skip" }
    );
    let data = json!({
        "findingId": finding.id,
        "fingerprint": finding.fingerprint,
        "score": score,
        "shouldDeepAudit": should_audit,
        "threshold": threshold,
        "samplesSeen": samples_seen,
    });
    crate::module_result::completed_output_result(summary.clone(), summary, data)
}
