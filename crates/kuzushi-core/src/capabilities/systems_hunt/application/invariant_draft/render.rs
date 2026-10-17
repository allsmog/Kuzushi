use super::*;
use crate::run_lifecycle::SafeText;
use crate::runtime::RuntimeCostReport;

pub(super) fn result(
    prepared: context::Prepared,
    supplied: Value,
    response: AgentQueryResponse,
    maximum: usize,
    canceled: bool,
) -> Result<Value> {
    let cost = response.checked_cost_report()?;
    let parsed = if canceled {
        Err(anyhow::anyhow!("Invariant drafting canceled after request"))
    } else {
        response::validate(&response, &prepared, maximum)
    };
    let mut result = match parsed {
        Ok(drafts) => valid(&prepared, &drafts, cost),
        Err(error) => crate::module_result::failed_output_result("Invariant context draft failed",
            format!("{error:#}. No repair request or follow-up work started. Inspect retained input and raw output before retrying."),
            json!({"invariants":[],"parseError":format!("{error:#}")})),
    };
    attach_retained_evidence(&mut result, supplied, &response)?;
    result["data"]["costUsd"] = json!(cost.exact_usd());
    result["data"]["observedCostUsd"] = json!(cost.observed_usd());
    result["data"]["costUsdExact"] = json!(cost.is_complete());
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    Ok(result)
}

fn attach_retained_evidence(
    result: &mut Value,
    supplied: Value,
    response: &AgentQueryResponse,
) -> Result<()> {
    result["data"]
        .as_object_mut()
        .context("Invariant result data missing")?
        .extend(
            supplied
                .as_object()
                .context("Prepared input missing")?
                .clone(),
        );
    result["data"]["rawAgentOutput"] = json!(response::raw_value(&response).ok());
    result["data"]["rawAgentText"] = json!(super::super::source_context::prefix(
        &response.text,
        64 * 1024
    ));
    result["data"]["rawAgentTextTruncated"] = json!(response.text.len() > 64 * 1024);
    result["data"]["accepted"] = json!(false);
    result["data"]["authority"] = json!("unverified model assumptions; cheapVerifiable is a legacy claim, not verification or execution approval");
    Ok(())
}

fn valid(
    prepared: &context::Prepared,
    drafts: &[SystemsInvariant],
    cost: RuntimeCostReport,
) -> Value {
    let partial = prepared.inspection["status"] == "partial";
    let summary = format!(
        "Invariant context drafts: {}; {} source context",
        drafts.len(),
        if partial { "partial" } else { "bounded" }
    );
    let output = output(prepared, drafts, &summary, cost);
    let data = json!(SystemsInvariantOutput {
        invariants: drafts.to_vec()
    });
    if partial {
        return crate::module_result::partial_output_result(
            summary,
            output,
            vec![json!(
                "Partial source context. Review omissions before accepting assumptions."
            )],
            data,
        );
    }
    crate::module_result::completed_output_result(summary, output, data)
}

fn output(
    prepared: &context::Prepared,
    drafts: &[SystemsInvariant],
    summary: &str,
    cost: RuntimeCostReport,
) -> String {
    let mut lines = vec![
        summary.into(),
        "Unverified safety assumptions. Review before accepting context.".into(),
    ];
    for draft in drafts {
        lines.push(format!(
            "{} · {}\n  Assumption: {}\n  Why: {}\n  Source: {}\n  Source quotes: {}",
            safe(&draft.id),
            safe(&draft.summary),
            safe(&draft.statement),
            safe(&draft.rationale),
            source_anchor(prepared, &draft.surface_id),
            safe(&draft.evidence.join(" · "))
        ));
    }
    lines.extend([
        format!("Surfaces: {} supplied, {} included, {} omitted. See Inputs for exact source and anchors.",
            prepared.inspection["suppliedSurfaces"], prepared.inspection["includedSurfaces"], prepared.inspection["omittedSurfaces"].as_array().map_or(0, Vec::len)),
        "Scope: repository-wide context planning. Selected discovery scopes are unsupported. Complete repository coverage is not established.".into(),
        "No findings, scan jobs, accepted context or phase completion. cheapVerifiable is an unverified legacy claim.".into(),
        format!("Consumption: one model turn requested; 4096 output tokens requested; no repair loop. {}. Adapter support varies; transport retries share the approved Context allowance.", crate::run_lifecycle::cost_label(cost)),
    ]);
    append_systems_source_coverage(&mut lines, &prepared.inspection);
    lines.join("\n")
}

fn safe(text: &str) -> String {
    SafeText::operator_visible(text).to_string()
}

fn source_anchor(prepared: &context::Prepared, surface_id: &str) -> String {
    prepared
        .surface_sources
        .get(surface_id)
        .map(|source| {
            format!(
                "{}:{} · {}",
                safe(&source.path),
                source.line,
                safe(surface_id)
            )
        })
        .unwrap_or_else(|| "unavailable anchor".into())
}
