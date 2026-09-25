use super::*;
use crate::capabilities::trace_expansion::{
    append_trace_expansion_evidence, run_trace_expansion, TraceEvidenceReceipt,
    TraceExpansionOutcome, TraceExpansionRequest,
};
use crate::static_evidence::StaticEvidenceStore;

/// `trace:expand` — run the bounded expansion agent for one finding and
/// append the recovered hops to the static-evidence store with operator
/// provenance. The tool result carries the parsed contract plus the append
/// receipt so the TUI can render immediately while the store stays the
/// durable source.
pub(in crate::modules) fn run_trace_expand(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "trace:expand",
        ))?;
    let store = ctx
        .findings_store
        .context("trace:expand requires a findings store for the active workspace")?;
    let runtime = runtime.context("trace:expand requires an agent runtime")?;

    let request = trace_expansion_request_from_input(&input)?;
    let Some(finding) = store.get_finding_by_operator_reference(&request.finding_fingerprint)? else {
        return Ok(serde_json::json!({
            "ok": false,
            "output": format!(
                "No finding with fingerprint '{}'",
                request.finding_fingerprint
            ),
        }));
    };

    let model = resolve_tool_model("trace:expand", &input, ctx)?;
    crate::workspace::source_snapshot::run_source_bound_tool(
        ctx,
        "trace:expand",
        workspace.root(),
        || {
            let outcome =
                run_trace_expansion(runtime, &model, workspace.root(), &finding, &request)?;
            let evidence_store = StaticEvidenceStore::open(workspace)?;
            let receipt = append_trace_expansion_evidence(&evidence_store, &outcome.result)?;
            trace_expansion_output(&outcome, &receipt)
        },
    )
}

fn trace_expansion_output(
    outcome: &TraceExpansionOutcome,
    receipt: &TraceEvidenceReceipt,
) -> Result<Value> {
    let result = &outcome.result;
    let mut data =
        serde_json::to_value(result).context("Could not serialize trace expansion result")?;
    data["tool"] = Value::from("trace:expand");
    data["nodesAppended"] = Value::from(receipt.node_ids.len());
    data["edgesAppended"] = Value::from(receipt.edge_ids.len());
    let summary = format!(
        "Trace expansion completed: {} steps, {} open questions, {} evidence notes.",
        result.steps.len(),
        result.open_questions.len(),
        result.evidence_deltas.len()
    );
    let mut output = serde_json::json!({"ok": true, "summary": summary, "data": data});
    crate::module_result::apply_runtime_cost_report(&mut output, expansion_cost(outcome)?);
    Ok(output)
}

fn expansion_cost(outcome: &TraceExpansionOutcome) -> Result<crate::runtime::RuntimeCostReport> {
    use crate::runtime::{RuntimeCost, RuntimeCostReport};
    let observed = RuntimeCost::from_usd(outcome.cost_usd, "trace expansion cost")?;
    if outcome.cost_usd_exact {
        return Ok(RuntimeCostReport::known(observed));
    }
    let estimate = outcome
        .estimated_cost_usd
        .map(|usd| RuntimeCost::from_usd(usd, "trace expansion estimated cost"))
        .transpose()?;
    Ok(RuntimeCostReport::incomplete(observed).with_unmetered_estimate(estimate))
}

fn trace_expansion_request_from_input(input: &Value) -> Result<TraceExpansionRequest> {
    let fingerprint = input
        .get("fingerprint")
        .or_else(|| input.get("findingFingerprint"))
        .or_else(|| input.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|fingerprint| !fingerprint.is_empty())
        .context("trace:expand requires a finding fingerprint")?;
    let mut request = TraceExpansionRequest::new(fingerprint);
    request.operator_instruction = input
        .get("instruction")
        .or_else(|| input.get("operatorInstruction"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|instruction| !instruction.is_empty())
        .map(str::to_string);
    request.current_path_node_ids = input
        .get("nodeIds")
        .or_else(|| input.get("currentPathNodeIds"))
        .and_then(Value::as_array)
        .map(|node_ids| {
            node_ids
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(request)
}

#[cfg(test)]
mod cost_tests {
    use super::*;
    use crate::capabilities::trace_expansion::TraceExpansionResult;

    fn outcome(exact: bool, estimate: Option<f64>) -> TraceExpansionOutcome {
        TraceExpansionOutcome {
            result: TraceExpansionResult {
                version: 1,
                finding_fingerprint: "fp".to_string(),
                steps: Vec::new(),
                evidence_deltas: Vec::new(),
                open_questions: Vec::new(),
            },
            cost_usd: 0.0,
            cost_usd_exact: exact,
            estimated_cost_usd: estimate,
        }
    }

    #[test]
    fn unmetered_expansion_spend_keeps_its_token_estimate() {
        let cost = expansion_cost(&outcome(false, Some(0.02))).unwrap();
        assert!(!cost.is_complete());
        assert_eq!(cost.unmetered_estimate_usd(), Some(0.02));
        assert!(expansion_cost(&outcome(true, None)).unwrap().is_complete());
    }
}
