use super::*;
use crate::capabilities::trace_expansion::{
    append_trace_expansion_evidence, run_trace_expansion, TraceExpansionRequest,
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
    let Some(finding) = store.get_finding_by_fingerprint(&request.finding_fingerprint)? else {
        return Ok(serde_json::json!({
            "ok": false,
            "output": format!(
                "No finding with fingerprint '{}'",
                request.finding_fingerprint
            ),
        }));
    };

    let model = resolve_tool_model("trace:expand", &input, ctx)?;
    let outcome = run_trace_expansion(runtime, &model, workspace.root(), &finding, &request)?;

    let evidence_store = StaticEvidenceStore::open(workspace)?;
    let receipt = append_trace_expansion_evidence(&evidence_store, &outcome.result)?;

    let mut data = serde_json::to_value(&outcome.result)
        .context("Could not serialize trace expansion result")?;
    if let Value::Object(object) = &mut data {
        object.insert("tool".to_string(), Value::String("trace:expand".to_string()));
        object.insert(
            "nodesAppended".to_string(),
            Value::from(receipt.node_ids.len()),
        );
        object.insert(
            "edgesAppended".to_string(),
            Value::from(receipt.edge_ids.len()),
        );
        object.insert("costUsd".to_string(), Value::from(outcome.cost_usd));
        object.insert(
            "costUsdExact".to_string(),
            Value::from(outcome.cost_usd_exact),
        );
    }
    Ok(serde_json::json!({ "ok": true, "data": data }))
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
