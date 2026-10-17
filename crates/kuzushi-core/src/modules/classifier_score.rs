use super::*;

pub(crate) fn run_classifier_score_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let run = prepare_classifier_score(&input, ctx, runtime)?;
    let routed = classifier_routed_runtime(run.runtime, ctx, run.workspace.root())?;
    let gate = classifier_gate(&routed, run.workspace, run.target_percentile)?;
    let (assessment, cost) = gate.assess_with_cost(&run.finding, run.workspace.root())?;
    let should_audit = gate.should_deep_audit(assessment);
    let threshold = gate.current_threshold();
    let n = gate.samples_seen();
    let mut result = classifier_score_response(
        &run.finding,
        assessment,
        should_audit,
        threshold,
        n,
        run.target_percentile,
    );
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

struct ClassifierScoreRun<'a> {
    runtime: &'a dyn AgentRuntime,
    workspace: &'a crate::WorkspaceTarget,
    finding: crate::findings::Finding,
    target_percentile: f32,
}

fn prepare_classifier_score<'a>(
    input: &Value,
    ctx: &'a ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<ClassifierScoreRun<'a>> {
    let target_percentile = classifier_target_percentile(input)?;
    let runtime = required_classifier_runtime(runtime)?;
    let workspace = required_classifier_workspace(ctx)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = classifier_finding(input, &store)?;
    Ok(ClassifierScoreRun {
        runtime,
        workspace,
        finding,
        target_percentile,
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
        .get_finding_by_operator_reference(fingerprint)?
        .ok_or_else(|| anyhow::anyhow!("classifier-gate:score: no finding for {fingerprint:?}"))
}

fn classifier_target_percentile(input: &Value) -> Result<f32> {
    let value = input
        .get("targetPercentile")
        .and_then(Value::as_f64)
        .map(|v| v as f32)
        .unwrap_or(0.80);
    crate::capabilities::classifier_gate::ClassifierConfig {
        target_percentile: value,
        ..Default::default()
    }
    .validate()?;
    Ok(value)
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

fn classifier_score_response(
    finding: &crate::findings::Finding,
    assessment: crate::capabilities::classifier_gate::ClassifierAssessment,
    should_audit: bool,
    threshold: f32,
    samples_seen: usize,
    target_percentile: f32,
) -> Value {
    let summary = classifier_summary(assessment, should_audit);
    let output = format!("{summary}\nFinding: {}\nPrioritization opinion over finding metadata only; no source files read.\nHistorical workspace threshold: {threshold:.3}; percentile: {target_percentile:.3}; samples: {samples_seen}.\nNo follow-up started. Further investigation requires its own approved plan.", finding.fingerprint);
    let data = classifier_response_data(
        finding,
        assessment,
        should_audit,
        threshold,
        samples_seen,
        target_percentile,
    );
    if assessment.is_parse_degraded() {
        return crate::module_result::partial_output_result(summary, output,
            vec![json!("Classifier unscored. Expected a finite 0..1 score; saved reviews and samples are unchanged.")], data);
    }
    crate::module_result::completed_output_result(summary, output, data)
}

fn classifier_summary(
    assessment: crate::capabilities::classifier_gate::ClassifierAssessment,
    should_audit: bool,
) -> String {
    let Some(score) = assessment.score() else {
        return "Classifier unscored; no follow-up started.".into();
    };
    let hint = if should_audit {
        "review suggested"
    } else {
        "below threshold"
    };
    format!("Classifier score {score:.3}; {hint}.")
}

fn classifier_response_data(
    finding: &crate::findings::Finding,
    assessment: crate::capabilities::classifier_gate::ClassifierAssessment,
    should_audit: bool,
    threshold: f32,
    samples_seen: usize,
    target_percentile: f32,
) -> Value {
    json!({
        "findingId": finding.id,
        "fingerprint": finding.fingerprint,
        "score": assessment.score(),
        "parseDegraded": assessment.is_parse_degraded(),
        "shouldDeepAudit": should_audit,
        "threshold": threshold,
        "samplesSeen": samples_seen,
        "targetPercentile": target_percentile,
        "modelOpinionOnly": true,
        "sourceTextProvided": false,
        "thresholdScope": "workspace-history",
        "followupStarted": false,
        "findingDecisionChanged": false,
    })
}
