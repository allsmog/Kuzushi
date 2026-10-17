use super::super::source_context::prefix;
use super::*;
mod supplied_input;
pub(super) use supplied_input::prepare as prepare_input;

pub(super) const LEDGER_GUIDANCE: &str = "Review observations in the findings ledger. Any further work needs separate scope and allowance.";

pub(super) fn result(
    prepared: context::Prepared,
    supplied: Value,
    response: AgentQueryResponse,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    root: &Path,
) -> Result<Value> {
    let cost = response.checked_cost_report()?;
    let materialized = materialize(&prepared, &response, input, ctx, root, cost);
    let mut result = match materialized {
        Ok(report) => success(&prepared, &report, cost),
        Err(error) => crate::module_result::failed_output_result(
            "Deep discovery failed",
            format!("{error:#}. No repair or follow-up jobs started. Inspect retained raw output and any partial inert artifacts before retrying."),
            json!({"findings":[],"failure":format!("{error:#}")}),
        ),
    };
    result["data"]
        .as_object_mut()
        .context("Discovery result data is missing")?
        .extend(
            supplied
                .as_object()
                .context("Prepared discovery input is missing")?
                .clone(),
        );
    result["data"]["rawAgentOutput"] = json!(response::raw_value(&response).ok());
    result["data"]["rawAgentText"] = json!(prefix(&response.text, 128 * 1024));
    result["data"]["rawAgentTextTruncated"] = json!(response.text.len() > 128 * 1024);
    result["data"]["candidateAuthority"] =
        json!("unverified model observation; human decisions are separate");
    result["data"]["costUsd"] = json!(cost.exact_usd());
    result["data"]["observedCostUsd"] = json!(cost.observed_usd());
    result["data"]["costUsdExact"] = json!(cost.is_complete());
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn materialize(
    prepared: &context::Prepared,
    response: &AgentQueryResponse,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    root: &Path,
    cost: RuntimeCostReport,
) -> Result<SystemsHuntReport> {
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Deep discovery canceled after request; no findings published"
    );
    let maximum = input::Limits::parse(input)?.max_findings;
    let raw = response::validate(response, prepared, maximum)?;
    let artifacts = artifact_root(
        root,
        input["artifactDir"]
            .as_str()
            .unwrap_or(".kuzushi/systems-hunt"),
    )?;
    let run_artifacts = artifacts.join(ctx.finding_run_id());
    let (mut findings, artifacts) =
        normalize_deep_semantic_findings(raw.clone(), root, &run_artifacts, maximum)?;
    evidence::attach(&mut findings, &raw, prepared)?;
    anyhow::ensure!(
        !ctx.is_cancelled(),
        "Deep discovery canceled before ledger publication; inert artifacts may remain"
    );
    Ok(SystemsHuntReport {
        target: root.display().to_string(),
        count: findings.len(),
        findings,
        persisted: None,
        artifacts,
        cost_usd: cost.observed_usd(),
        cost_usd_exact: cost.is_complete(),
    })
}

fn success(
    prepared: &context::Prepared,
    report: &SystemsHuntReport,
    cost: RuntimeCostReport,
) -> Value {
    let partial = prepared.inspection["status"] == "partial";
    let summary = format!(
        "Deep discovery: {} {}; {} source context",
        report.count,
        if report.count == 1 {
            "candidate"
        } else {
            "candidates"
        },
        if partial { "partial" } else { "bounded" }
    );
    let output = output(prepared, report, cost);
    if partial {
        return crate::module_result::partial_output_result(
            summary,
            output,
            vec![json!(
                "Partial source context. A later pass missing a finding does not resolve it."
            )],
            json!(report),
        );
    }
    crate::module_result::completed_output_result(summary, output, json!(report))
}

fn output(
    prepared: &context::Prepared,
    report: &SystemsHuntReport,
    cost: RuntimeCostReport,
) -> String {
    let mut lines = observation_lines(&report.findings);
    lines.push("Unverified model observations. Evidence anchors identify supplied text; they do not establish a true positive.".into());
    lines.push(format!(
        "Scope: {}. Complete repository coverage is not established.",
        prepared.inspection["scope"]["kind"]
            .as_str()
            .unwrap_or("unavailable")
    ));
    if let Some(name) = prepared.inspection["scope"]["name"].as_str() {
        lines.push(format!("Scope name: {name}"));
    }
    let context_files = prepared
        .sources
        .keys()
        .filter(|path| !prepared.discovery.contains(*path))
        .count();
    lines.push(format!(
        "Supplied files: {} discovery, {context_files} context only. Selected classes: {}. {}.",
        prepared.discovery.len(),
        prepared.classes.len(),
        crate::run_lifecycle::cost_label(cost)
    ));
    lines.push(format!(
        "Source limits: files <= {}; bytes <= {}; bytes/file <= {}.",
        prepared.inspection["maxSourceFiles"],
        prepared.inspection["maxSourceBytes"],
        prepared.inspection["maxFileBytes"]
    ));
    lines.push("One fresh discovery session; one model turn requested. Transport retries share the approved allowance. Adapter token/turn support varies.".into());
    append_systems_source_coverage(&mut lines, &prepared.inspection);
    lines.join("\n")
}

fn observation_lines(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| {
            format!(
                "{} · {} · {}:{}",
                finding.title,
                finding.severity.as_str(),
                finding.file_path,
                finding.start_line
            )
        })
        .collect()
}
