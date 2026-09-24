use super::{
    build_verify_prompt, normalize_verification_result, verification_result_schema,
    verify_system_prompt, VerifyFindingInput,
};
use crate::findings::FindingStore;
use crate::runtime::{AgentQueryRequest, AgentRuntime, RuntimeCost, RuntimeCostReport};
use crate::structured_output::{CostedStructuredJson, StructuredJsonContract};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

mod execution;
mod review_gate;

use review_gate::verify_review_gate_refusal;

pub(crate) struct VerifyFindingToolRequest<'a> {
    pub(crate) input: Value,
    pub(crate) workspace_root: &'a Path,
    pub(crate) store: &'a FindingStore,
    pub(crate) runtime: Option<&'a dyn AgentRuntime>,
    pub(crate) configured_model: Option<&'a str>,
    pub(crate) trace: Option<&'a crate::run_artifacts::TraceHandle>,
}

pub(crate) fn run_verify_finding_tool(request: VerifyFindingToolRequest<'_>) -> Result<Value> {
    execution::run(request)
}

fn bind_prompt_to_source_identity(
    prompt: String,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
) -> Result<String> {
    let canonical = crate::verification::canonical_source_identity(source_identity)?;
    Ok(format!(
        "{prompt}\n\nVerification source identity (canonical JSON):\n{canonical}\nBase every source claim on this exact captured identity."
    ))
}

/// A gate model identical to the primary verifier is not a cheaper first
/// opinion: it doubles model spend and makes the gate/panel stage ladder claim
/// a two-tier structure that does not exist. Refuse it explicitly rather than
/// silently running the same model twice.
fn require_distinct_gate_model(gate_model: Option<&str>, primary_model: &str) -> Result<()> {
    let Some(gate_model) = gate_model else {
        return Ok(());
    };
    let gate = crate::runtime::canonical_model_spec(gate_model)?;
    let primary = crate::runtime::canonical_model_spec(primary_model)?;
    if gate == primary {
        anyhow::bail!(
            "verify:finding gateModel must differ from the verifier model ({primary}); \
             a same-model gate doubles spend without a cheaper first opinion"
        );
    }
    Ok(())
}

/// The gate's involvement must stay visible in the result: a rejection that
/// never reached the full-strength panel reads differently from one that
/// did, and the operator can rerun without `gateModel` to override it.
fn annotate_gate_stage(result: &mut Value, gate_model: &str, escalated: bool) {
    if let Some(object) = result.as_object_mut() {
        object.insert(
            "gate".to_string(),
            json!({
                "stage": "plausibility",
                "model": gate_model,
                "escalated": escalated,
            }),
        );
    }
}

/// A split panel that was broken by a different, operator-named model must stay
/// visible: the operator can see which model resolved the tie and that it ran
/// only because the panel deadlocked. The `consensus` block is deliberately
/// untouched, so unanimity is never forged.
fn annotate_escalation_stage(
    result: &mut Value,
    escalation_model: &str,
    resolved_exploitable: Option<bool>,
    panel_passes: u64,
) {
    if let Some(object) = result.as_object_mut() {
        object.insert(
            "escalation".to_string(),
            json!({
                "stage": "tie-break",
                "model": escalation_model,
                "attempted": true,
                "resolvedExploitable": resolved_exploitable,
                // The full panel size that deadlocked, not the tie count — a
                // 4-pass 2-2 split reports panelPasses=4.
                "panelPasses": panel_passes,
            }),
        );
    }
}

/// A refused escalation (same model as the primary, or an invalid spec) is a
/// disclosed non-event: the split verdict stands and the operator sees why the
/// escalation did not run.
fn annotate_escalation_refused(result: &mut Value, reason: crate::runtime::TieBreakRefusal) {
    if let Some(object) = result.as_object_mut() {
        object.insert(
            "escalation".to_string(),
            json!({
                "stage": "tie-break",
                "attempted": false,
                "refusedReason": reason.operator_message(),
                "refusedToken": reason.token(),
            }),
        );
    }
}

/// An escalation pass that ERRORED (an overloaded/401 escalation model, a cost
/// overflow) must not destroy the already-computed, already-paid split verdict.
/// Escalation is a best-effort tie-breaker: its failure degrades to a disclosed
/// non-event exactly like a refusal — the split verdict stands and the operator
/// sees why the tie-break did not resolve. `attempted:false` routes the message
/// through the same `warnings[]`/stage-note refusal-disclosure path.
fn annotate_escalation_failed(result: &mut Value, escalation_model: &str, error: &anyhow::Error) {
    if let Some(object) = result.as_object_mut() {
        object.insert(
            "escalation".to_string(),
            json!({
                "stage": "tie-break",
                "model": escalation_model,
                "attempted": false,
                "refusedReason": format!(
                    "tie-break escalation attempt failed: {error}; split verdict unchanged"
                ),
                "refusedToken": "attempt-failed",
            }),
        );
    }
}

/// Adopt the escalation pass's verdict into the split panel result while keeping
/// the `consensus` block intact, then record the escalation stage.
fn apply_escalation_verdict(result: &mut Value, pass: &Value, escalation_model: &str) {
    let panel_passes = panel_pass_count(result);
    let resolved_exploitable = pass.get("exploitable").and_then(Value::as_bool);
    adopt_escalation_representative(result, pass);
    annotate_escalation_stage(result, escalation_model, resolved_exploitable, panel_passes);
}

fn panel_pass_count(result: &Value) -> u64 {
    result
        .get("consensus")
        .and_then(|consensus| consensus.get("passes"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Make the escalation pass the representative result, then re-attach the panel
/// `consensus` block (and any gate annotation) untouched. Field-by-field merging
/// could mix an `exploitable=true` verdict with a `proofVerdict`/`pocPayload`
/// inherited from the not-exploitable representative — a self-contradictory
/// result the proof candidate later rejects. Adopting the whole normalized pass
/// guarantees exploitable, proofVerdict, pocPayload, and citations are coherent
/// because they all come from the SAME pass. The consensus block is preserved
/// verbatim, so the split stays visible and unanimity is never forged.
fn adopt_escalation_representative(result: &mut Value, pass: &Value) {
    let consensus = result.get("consensus").cloned();
    let gate = result.get("gate").cloned();
    *result = pass.clone();
    let Some(object) = result.as_object_mut() else {
        return;
    };
    if let Some(consensus) = consensus {
        object.insert("consensus".to_string(), consensus);
    }
    if let Some(gate) = gate {
        object.insert("gate".to_string(), gate);
    }
}

/// Fold the gate/panel/escalation blocks into one durable, round-trippable
/// `stages: …` note stored on the result. Absent structure produces no note.
fn annotate_stage_note(result: &mut Value) {
    let Some(disclosure) = build_stage_disclosure(result) else {
        return;
    };
    let note = crate::findings::format_stage_note(&disclosure);
    if let Some(object) = result.as_object_mut() {
        object.insert("stageNote".to_string(), json!(note));
    }
}

fn build_stage_disclosure(result: &Value) -> Option<crate::findings::VerificationStageDisclosure> {
    let gate = stage_block_model(result.get("gate"));
    let panel_passes = consensus_pass_count(result);
    let split = super::verify_consensus::panel_verdict_is_split(result);
    let escalation = attempted_escalation_model(result);
    let refused = refused_escalation_token(result);
    if gate.is_none() && !split && escalation.is_none() && refused.is_none() {
        return None;
    }
    Some(crate::findings::VerificationStageDisclosure {
        gate,
        panel_passes,
        split,
        escalation,
        refused,
    })
}

fn stage_block_model(block: Option<&Value>) -> Option<String> {
    block?
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn consensus_pass_count(result: &Value) -> u32 {
    result
        .get("consensus")
        .and_then(|consensus| consensus.get("passes"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32
}

fn attempted_escalation_model(result: &Value) -> Option<String> {
    let escalation = result.get("escalation")?;
    (escalation.get("attempted").and_then(Value::as_bool) == Some(true))
        .then(|| stage_block_model(Some(escalation)))
        .flatten()
}

fn refused_escalation_token(result: &Value) -> Option<String> {
    let escalation = result.get("escalation")?;
    (escalation.get("attempted").and_then(Value::as_bool) == Some(false))
        .then(|| {
            escalation
                .get("refusedToken")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .flatten()
}

fn bind_verification_result(
    mut result: Value,
    finding: &crate::findings::Finding,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
) -> Result<Value> {
    annotate_stage_note(&mut result);
    let scan_id = finding
        .scan_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("verify:finding requires a canonical discovery run id")?;
    let object = result
        .as_object_mut()
        .context("normalized verification result must be an object")?;
    object.insert("verifiedScanId".to_string(), json!(scan_id));
    object.insert("identityId".to_string(), json!(finding.identity_id.clone()));
    object.insert("sourceIdentity".to_string(), json!(source_identity));
    Ok(result)
}

fn verify_finding_model(input: &Value, configured_model: Option<&str>) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        "verify:finding",
        input
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        configured_model,
    )
}

fn run_one_verify_pass(
    runtime: &dyn AgentRuntime,
    model: &str,
    workspace_root: &Path,
    prompt: &str,
    fingerprint: &str,
    input: &VerifyFindingInput,
) -> Result<CostedStructuredJson<Value>> {
    // Closed-world verify passes replay for free when the finding and its
    // embedded evidence are unchanged; `mcps` runs carry a tool policy and
    // the cached wrapper routes those live automatically.
    let cache = crate::semantic_cache::SemanticCache::open_for_target(workspace_root);
    crate::structured_output::query_cached_structured_json_with_cost(
        cache.as_ref(),
        runtime,
        verify_agent_query_request(model, workspace_root, prompt, input)?,
        StructuredJsonContract::new(
            "verify:finding",
            "VerificationResult",
            verification_result_schema(),
        ),
        |raw| normalize_verification_result(raw, fingerprint),
    )
    .map(|cached| cached.costed)
}

fn verify_agent_query_request(
    model: &str,
    workspace_root: &Path,
    prompt: &str,
    input: &VerifyFindingInput,
) -> Result<AgentQueryRequest> {
    let mut request = AgentQueryRequest::new(
        model,
        workspace_root.to_path_buf(),
        verify_system_prompt(),
        prompt.to_string(),
    );
    if input.mcps {
        request = request.with_tool_policy(
            crate::proof::whitebox_policy::try_whitebox_static_policy_for_target(workspace_root)?,
        );
    }
    let runtime_options = crate::runtime::AgentRuntimeOptions {
        mcp_tool_timeout_ms: input.mcp_tool_timeout_ms,
        max_model_turns: input.max_model_turns,
        ..Default::default()
    };
    if !runtime_options.is_empty() {
        request = request.with_runtime_options(runtime_options);
    }
    Ok(request)
}

fn missing_finding_response(fingerprint: &str) -> Value {
    let output = format!("[-] No finding with fingerprint '{fingerprint}'.");
    crate::module_result::failed_output_result(
        "verify:finding failed",
        output,
        json!({
            "fingerprint": fingerprint,
            "reason": "missing-finding",
        }),
    )
}

fn require_verify_finding_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "verify:finding requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn verify_finding_response(result: Value, cost: RuntimeCostReport) -> Result<Value> {
    let exploitable = super::verify_assessment::read_exploitability(&result)?;
    let assessment = super::verify_assessment::assessment_label(exploitable);
    let mut lines = vec![
        "[+] verify:finding complete".to_string(),
        format!("      {assessment}"),
    ];
    append_vector_line(&mut lines, &result);
    if let Some(ladder) = stage_ladder_line(&result) {
        lines.push(ladder);
    }
    append_cost_line(&mut lines, &cost);
    let summary = format!("verify:finding complete ({assessment})");
    let proof = verification_proof_snapshot(&result)?;
    let refusal_warning = escalation_refusal_warning(&result);
    let data = verification_response_data(result, &proof, &summary)?;
    let mut response = assessment_response(exploitable, summary, lines.join("\n"), data);
    add_verification_response_metadata(&mut response, proof, cost);
    if let Some(message) = refusal_warning {
        push_verification_warning(&mut response, message);
    }
    Ok(response)
}

fn assessment_response(
    exploitable: Option<bool>,
    summary: String,
    output: String,
    data: Value,
) -> Value {
    if exploitable.is_some() {
        return crate::module_result::completed_output_result(summary, output, data);
    }
    crate::module_result::partial_output_result(
        summary,
        output,
        vec![json!("Model assessment is inconclusive. Review missing evidence or panel disagreement before retrying; this result cannot replace selected proof.")],
        data,
    )
}

fn append_vector_line(lines: &mut Vec<String>, result: &Value) {
    if let Some(vector) = result
        .get("attackVector")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        lines.push(format!("      vector: {vector}"));
    }
}

fn append_cost_line(lines: &mut Vec<String>, cost: &RuntimeCostReport) {
    if cost.is_unavailable() {
        lines.push("      cost unavailable".to_string());
        return;
    }
    if let Some(estimate) = cost.estimated_total_usd().filter(|_| cost.is_estimated()) {
        lines.push(format!("      estimated cost=~${estimate:.4} (tokens × list price)"));
        return;
    }
    let cost_label = if cost.is_complete() {
        "cost"
    } else {
        "observed cost"
    };
    lines.push(format!("      {cost_label}=${:.4}", cost.observed_usd()));
}

/// One line naming every extra-tier model that ran beside the panel: the cheap
/// gate and/or the tie-break escalation. The panel's own model runs on every
/// call, so it stays implicit; `None` keeps a plain single-tier response quiet.
fn stage_ladder_line(result: &Value) -> Option<String> {
    let mut stages = Vec::new();
    if let Some(model) = result
        .get("gate")
        .and_then(|gate| gate.get("model"))
        .and_then(Value::as_str)
    {
        stages.push(format!("gate {model}"));
    }
    if let Some(model) = escalation_stage_model(result) {
        stages.push(format!("tie-break {model}"));
    }
    (!stages.is_empty()).then(|| format!("      stages: {}", stages.join(" · ")))
}

fn escalation_stage_model(result: &Value) -> Option<&str> {
    let escalation = result.get("escalation")?;
    (escalation.get("attempted").and_then(Value::as_bool) == Some(true))
        .then(|| escalation.get("model").and_then(Value::as_str))
        .flatten()
}

fn escalation_refusal_warning(result: &Value) -> Option<String> {
    let escalation = result.get("escalation")?;
    if escalation.get("attempted").and_then(Value::as_bool) != Some(false) {
        return None;
    }
    escalation
        .get("refusedReason")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// A refusal is a completed-with-warning outcome, never a failure: the verdict
/// stands and the reason rides in `warnings[]`.
fn push_verification_warning(response: &mut Value, message: String) {
    let Some(object) = response.as_object_mut() else {
        return;
    };
    let warnings = object
        .entry("warnings")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(array) = warnings.as_array_mut() {
        array.push(json!(message));
    }
}

fn add_verification_response_metadata(response: &mut Value, proof: Value, cost: RuntimeCostReport) {
    if let Some(object) = response.as_object_mut() {
        object.insert("proof".to_string(), proof);
    }
    crate::module_result::apply_runtime_cost_report(response, cost);
}

fn verification_response_data(result: Value, proof: &Value, summary: &str) -> Result<Value> {
    let mut data = result
        .as_object()
        .cloned()
        .context("normalized verification result must be an object")?;
    data.insert("summary".to_string(), json!(summary));
    data.insert("proof".to_string(), proof.clone());
    data.insert("verification".to_string(), result);
    Ok(Value::Object(data))
}

fn verification_proof_snapshot(result: &Value) -> Result<Value> {
    Ok(json!({
        "kind": "llm-exploitability-review",
        "empirical": false,
        "fingerprint": required_result_field(result, "fingerprint")?,
        "exploitable": required_result_field(result, "exploitable")?,
        "proofLevel": required_result_field(result, "proofLevel")?,
        "proofVerdict": required_result_field(result, "proofVerdict")?,
        "confidence": required_result_field(result, "confidence")?,
        "verifiedScanId": required_result_field(result, "verifiedScanId")?,
        "identityId": required_result_field(result, "identityId")?,
        "sourceIdentity": required_result_field(result, "sourceIdentity")?,
        // Mirror the stage blocks so the operator-facing `proof` snapshot stays
        // consistent with the `data` copy. These blocks are display-only: the
        // durable proof candidate deserializes only the verdict/identity fields,
        // so they are not part of its 4-way equality check (see the test
        // `stage_blocks_are_carried_outside_the_compared_candidate_fields`).
        "gate": result.get("gate").cloned().unwrap_or(Value::Null),
        "escalation": result.get("escalation").cloned().unwrap_or(Value::Null),
    }))
}

fn required_result_field(result: &Value, key: &str) -> Result<Value> {
    result
        .get(key)
        .cloned()
        .with_context(|| format!("normalized verification result missing `{key}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known_cost(cost_usd: f64) -> RuntimeCostReport {
        RuntimeCostReport::known(RuntimeCost::from_usd(cost_usd, "test cost").unwrap())
    }

    #[test]
    fn incomplete_response_preserves_uncertainty_cost_and_source() {
        let mut result = normalize_verification_result(
            json!({
                "fingerprint":"fp-1", "exploitable":false, "confidence":0.61,
                "proofLevel":2, "proofVerdict":"insufficient_finding_detail"
            }),
            "fp-1",
        )
        .unwrap();
        result["verifiedScanId"] = json!("scan-1");
        result["identityId"] = json!("identity-1");
        result["sourceIdentity"] = source_identity_fixture();
        let response = verify_finding_response(result, known_cost(0.25)).unwrap();
        assert_eq!(response["status"], "partial");
        assert_eq!(response["costUsd"], 0.25);
        assert!(response["summary"]
            .as_str()
            .unwrap()
            .contains("inconclusive"));
        assert!(!response["output"]
            .as_str()
            .unwrap()
            .contains("likely-not-exploitable"));
        for path in ["/data", "/data/verification", "/data/proof", "/proof"] {
            let proof = response.pointer(path).unwrap();
            assert!(proof["exploitable"].is_null());
            assert_eq!(proof["sourceIdentity"], source_identity_fixture());
        }
        assert!(response["warnings"][0]
            .as_str()
            .unwrap()
            .contains("cannot replace selected proof"));
    }

    #[test]
    fn an_inconclusive_escalation_does_not_invent_a_negative() {
        let mut result = json!({"consensus":{"passes":2,"exploitableVotes":1}});
        let pass = json!({"exploitable":null,"proofVerdict":"insufficient_finding_detail"});
        apply_escalation_verdict(&mut result, &pass, "test:explicit-model");
        assert!(result["exploitable"].is_null());
        assert!(result["escalation"]["resolvedExploitable"].is_null());
        assert_eq!(result["escalation"]["attempted"], true);
        assert_eq!(result["consensus"]["passes"], 2);
    }

    #[test]
    fn verify_response_exposes_non_empirical_proof_snapshot() {
        let response = verify_finding_response(
            json!({
                "fingerprint": "fp-1",
                "exploitable": true,
                "confidence": 0.7,
                "proofLevel": 2,
                "proofVerdict": "exploited",
                "verifiedScanId": "scan-1",
                "identityId": "identity-1",
                "sourceIdentity": source_identity_fixture()
            }),
            known_cost(0.25),
        )
        .unwrap();

        assert_eq!(response["status"], json!("completed"));
        assert_eq!(response["proof"]["empirical"], json!(false));
        assert_eq!(response["data"]["proof"]["fingerprint"], json!("fp-1"));
        assert_eq!(response["data"]["exploitable"], json!(true));
        assert_eq!(response["proof"]["verifiedScanId"], json!("scan-1"));
        assert_eq!(response["costUsd"], json!(0.25));
        assert!(response["artifacts"].as_array().unwrap().is_empty());
        assert_eq!(
            response["summary"],
            json!("verify:finding complete (likely-exploitable (model assessment))")
        );
        assert!(response["output"]
            .as_str()
            .unwrap()
            .contains("likely-exploitable (model assessment)"));
        assert!(!response["output"].as_str().unwrap().contains("VULNERABLE"));
    }

    #[test]
    fn verify_response_rejects_missing_proof_fields_instead_of_defaulting() {
        let error = verify_finding_response(
            json!({
                "fingerprint": "fp-1",
                "exploitable": false,
                "confidence": 0.2
            }),
            known_cost(0.0),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("missing `proofLevel`"));
    }

    #[test]
    fn verify_response_rejects_missing_exploitable_instead_of_defaulting() {
        let error = verify_finding_response(
            json!({
                "fingerprint": "fp-1",
                "confidence": 0.7
            }),
            known_cost(0.0),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("missing boolean or null `exploitable`"));
    }

    #[test]
    fn verify_response_omits_monetary_fields_when_cost_is_unavailable() {
        let response = verify_finding_response(
            json!({
                "fingerprint": "fp-1",
                "exploitable": false,
                "confidence": 0.7,
                "proofLevel": 2,
                "proofVerdict": "not_reproduced",
                "verifiedScanId": "scan-1",
                "identityId": null,
                "sourceIdentity": source_identity_fixture()
            }),
            RuntimeCostReport::UNAVAILABLE,
        )
        .unwrap();

        assert!(response.get("costUsd").is_none());
        assert!(response.get("observedCostUsd").is_none());
        assert!(response.get("providerSpendUnresolved").is_none());
        assert!(response["data"].get("costUsd").is_none());
        assert!(response["data"].get("observedCostUsd").is_none());
        assert!(response["output"]
            .as_str()
            .unwrap()
            .contains("cost unavailable"));
        assert_eq!(
            response["summary"],
            json!("verify:finding complete (likely-not-exploitable (model assessment))")
        );
        assert!(response["output"]
            .as_str()
            .unwrap()
            .contains("likely-not-exploitable (model assessment)"));
    }

    #[test]
    fn verification_binding_captures_the_exact_finding_generation() {
        let mut finding = crate::findings::Finding::default();
        finding.scan_id = Some("scan-current".to_string());
        finding.identity_id = Some("identity-current".to_string());

        let source_identity = source_identity_fixture_typed();
        let result =
            bind_verification_result(json!({"fingerprint": "fp"}), &finding, &source_identity)
                .unwrap();

        assert_eq!(result["verifiedScanId"], "scan-current");
        assert_eq!(result["identityId"], "identity-current");
        assert_eq!(result["sourceIdentity"], source_identity_fixture());
    }

    fn source_identity_fixture_typed() -> crate::workflow_attempts::TargetContentIdentity {
        crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
            snapshot_hash: crate::run_lifecycle::SafeText::operator_visible("a".repeat(64)),
            tree_hash: Some(crate::run_lifecycle::SafeText::operator_visible(
                "b".repeat(64),
            )),
        }
    }

    fn source_identity_fixture() -> Value {
        json!(source_identity_fixture_typed())
    }

    #[test]
    fn missing_finding_response_uses_failed_result_envelope() {
        let response = missing_finding_response("missing");

        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["status"], json!("failed"));
        assert_eq!(response["summary"], json!("verify:finding failed"));
        assert_eq!(response["data"]["reason"], json!("missing-finding"));
        assert!(response["errors"][0]
            .as_str()
            .unwrap()
            .contains("No finding with fingerprint 'missing'"));
    }

    #[test]
    fn verify_request_attaches_conditional_mcp_policy_and_timeout() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        std::fs::write(temp.path().join(".kuzushi/context-snapshot.json"), "{}").unwrap();
        let input = VerifyFindingInput {
            fingerprint: "F-1".to_string(),
            prompt_template: None,
            passes: 1,
            mcps: true,
            mcp_tool_timeout_ms: Some(12_345),
            max_model_turns: None,
            gate_model: None,
            escalation_model: None,
        };

        let request = verify_agent_query_request("model", temp.path(), "prompt", &input).unwrap();

        assert_eq!(request.tool_policy.profile, "whitebox-static");
        assert!(request.tool_policy.mcps);
        assert!(request
            .tool_policy
            .mcps_attached
            .iter()
            .any(|attachment| attachment.name == "treesitter"));
        assert_eq!(
            request.runtime_options.unwrap().mcp_tool_timeout_ms,
            Some(12_345)
        );
    }

    #[test]
    fn gate_rejection_is_annotated_and_never_marked_escalated() {
        let mut result = json!({"fingerprint": "fp", "exploitable": false});
        annotate_gate_stage(&mut result, "anthropic:claude-haiku-4-5", false);

        assert_eq!(result["gate"]["stage"], json!("plausibility"));
        assert_eq!(result["gate"]["model"], json!("anthropic:claude-haiku-4-5"));
        assert_eq!(result["gate"]["escalated"], json!(false));
    }

    #[test]
    fn escalated_panel_results_keep_the_gate_marker() {
        let mut result = json!({"fingerprint": "fp", "exploitable": true});
        annotate_gate_stage(&mut result, "anthropic:claude-haiku-4-5", true);

        assert_eq!(result["gate"]["escalated"], json!(true));
    }

    #[test]
    fn gate_model_equal_to_the_verifier_model_is_refused() {
        // Same spec, different spelling (surrounding whitespace normalized away).
        let error = require_distinct_gate_model(
            Some("  anthropic : claude-haiku-4-5  "),
            "anthropic:claude-haiku-4-5",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("must differ from the verifier model"),
            "{error}"
        );

        // A genuinely distinct gate model is allowed.
        require_distinct_gate_model(Some("openai:gpt-cheap"), "anthropic:claude-haiku-4-5")
            .expect("distinct gate model is allowed");

        // No gate model is a no-op (single-tier verification).
        require_distinct_gate_model(None, "anthropic:claude-haiku-4-5")
            .expect("absent gate model is allowed");
    }

    #[test]
    fn gate_model_input_is_validated_and_optional() {
        let with_gate = VerifyFindingInput::from_tool_input(
            &json!({"fingerprint": "F-1", "gateModel": "anthropic:claude-haiku-4-5"}),
            Path::new("."),
        )
        .unwrap();
        assert_eq!(
            with_gate.gate_model.as_deref(),
            Some("anthropic:claude-haiku-4-5")
        );

        let without_gate =
            VerifyFindingInput::from_tool_input(&json!({"fingerprint": "F-1"}), Path::new("."))
                .unwrap();
        assert_eq!(without_gate.gate_model, None);

        let invalid = VerifyFindingInput::from_tool_input(
            &json!({"fingerprint": "F-1", "gateModel": "not a model spec"}),
            Path::new("."),
        );
        assert!(invalid.is_err());
    }

    #[test]
    fn verify_request_can_disable_mcp_policy() {
        let input = VerifyFindingInput {
            fingerprint: "F-1".to_string(),
            prompt_template: None,
            passes: 1,
            mcps: false,
            mcp_tool_timeout_ms: None,
            max_model_turns: None,
            gate_model: None,
            escalation_model: None,
        };

        let request =
            verify_agent_query_request("model", Path::new("."), "prompt", &input).unwrap();

        assert!(request.tool_policy.is_default());
        assert!(request.runtime_options.is_none());
    }

    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use std::sync::Mutex;

    /// Local scripted runtime keyed by the request's model: the primary panel
    /// splits (first pass exploitable, second not), and the escalation model
    /// resolves exploitable. Kept out of the shared MockRuntime on purpose.
    struct ModelKeyedVerifyRuntime {
        primary: String,
        fingerprint: String,
        models: Mutex<Vec<String>>,
    }

    impl AgentRuntime for ModelKeyedVerifyRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let mut models = self.models.lock().unwrap();
            models.push(request.model.clone());
            let primary_calls = models.iter().filter(|m| **m == self.primary).count();
            let exploitable = if request.model == self.primary {
                primary_calls == 1
            } else {
                true
            };
            Ok(AgentQueryResponse {
                structured: Some(verify_result_json(exploitable, &self.fingerprint)),
                ..Default::default()
            })
        }

        fn triage_finding_blocking(
            &self,
            _: TriageRequest,
        ) -> Result<crate::findings::TriageOutcome> {
            unreachable!("verify:finding does not use the triage path")
        }
    }

    fn verify_result_json(exploitable: bool, fingerprint: &str) -> Value {
        json!({
            "fingerprint": fingerprint,
            "exploitable": exploitable,
            "confidence": if exploitable { 0.9 } else { 0.4 },
            "proofLevel": 2,
            "proofVerdict": if exploitable { "exploited" } else { "not_reproduced" },
            "attackVector": if exploitable { json!("sqli") } else { Value::Null },
        })
    }

    fn triaged_store(target: &Path) -> (crate::findings::FindingStore, crate::findings::Finding) {
        let store = crate::findings::FindingStore::open_in_memory().unwrap();
        store
            .record_run_started("scan-1", target, "running")
            .unwrap();
        let finding = crate::findings::Finding::new_tool(
            "verify-e2e",
            "verify-e2e/rule",
            "src/db.ts",
            1,
            None,
            crate::findings::Severity::High,
            "user input reaches sql",
        );
        let id = store.insert_finding("scan-1", &finding).unwrap();
        store
            .record_auto_triage(id, &crate::findings::TriageOutcome::default())
            .unwrap();
        let stored = store
            .get_finding_by_operator_reference(&finding.fingerprint)
            .unwrap()
            .unwrap();
        (store, stored)
    }

    #[test]
    fn verify_finding_escalates_a_split_panel_to_the_named_model() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let _cache_off =
            crate::test_env::ScopedEnv::set(crate::semantic_cache::SEMANTIC_CACHE_ENV, "off");
        let temp = tempfile::tempdir().unwrap();
        let (store, finding) = triaged_store(temp.path());
        let primary = "anthropic:primary";
        let runtime = ModelKeyedVerifyRuntime {
            primary: primary.to_string(),
            fingerprint: finding.fingerprint.clone(),
            models: Mutex::new(Vec::new()),
        };

        let response = run_verify_finding_tool(VerifyFindingToolRequest {
            input: json!({
                "fingerprint": finding.fingerprint,
                "VERIFY_PASSES": 2,
                "escalationModel": "openai:escalation",
                "mcps": false,
            }),
            workspace_root: temp.path(),
            store: &store,
            runtime: Some(&runtime),
            configured_model: Some(primary),
            trace: None,
        })
        .unwrap();

        let models = runtime.models.lock().unwrap();
        assert_eq!(models.len(), 3, "two panel passes plus one escalation pass");
        // The 3rd request carried the escalation model, not the primary — a
        // regression that escalated with the primary model would fail here.
        assert_eq!(models[2], "openai:escalation");
        assert_eq!(response["data"]["escalation"]["attempted"], json!(true));
        assert_eq!(
            response["data"]["escalation"]["model"],
            json!("openai:escalation")
        );
        // The ADOPTED verdict is the escalation pass's exploitable=true, not the
        // split panel's not-exploitable default: the tie was actually resolved.
        assert_eq!(
            response["data"]["exploitable"],
            json!(true),
            "the escalation pass's verdict must be adopted"
        );
        assert_eq!(
            response["data"]["escalation"]["resolvedExploitable"],
            json!(true)
        );
        // The escalation resolves the tie but never forges panel unanimity.
        assert_ne!(
            response["data"]["verification"]["consensus"]["unanimous"],
            json!(true)
        );
    }

    #[test]
    fn stored_invalid_escalation_model_on_a_split_stands_with_a_warning() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let _cache_off =
            crate::test_env::ScopedEnv::set(crate::semantic_cache::SEMANTIC_CACHE_ENV, "off");
        let temp = tempfile::tempdir().unwrap();
        let (store, finding) = triaged_store(temp.path());
        let primary = "anthropic:primary";
        let runtime = ModelKeyedVerifyRuntime {
            primary: primary.to_string(),
            fingerprint: finding.fingerprint.clone(),
            models: Mutex::new(Vec::new()),
        };

        // `claude-big` has no provider prefix — an invalid spec. It parses fine
        // (F1) and is only refused when the split panel actually consults it.
        let response = run_verify_finding_tool(VerifyFindingToolRequest {
            input: json!({
                "fingerprint": finding.fingerprint,
                "VERIFY_PASSES": 2,
                "escalationModel": "claude-big",
                "mcps": false,
            }),
            workspace_root: temp.path(),
            store: &store,
            runtime: Some(&runtime),
            configured_model: Some(primary),
            trace: None,
        })
        .unwrap();

        let models = runtime.models.lock().unwrap();
        assert_eq!(
            models.len(),
            2,
            "an invalid escalation never runs an extra pass"
        );
        assert_eq!(response["status"], json!("partial"));
        assert_eq!(response["data"]["escalation"]["attempted"], json!(false));
        assert_eq!(
            response["data"]["escalation"]["refusedToken"],
            json!("invalid-spec")
        );
        // The split verdict stands unchanged (splits remain inconclusive).
        assert!(response["data"]["exploitable"].is_null());
        assert!(
            !response["warnings"].as_array().unwrap().is_empty(),
            "the invalid-spec refusal reads as completed-with-warning"
        );
    }

    #[test]
    fn stored_invalid_escalation_model_on_a_non_split_run_is_a_normal_result() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let _cache_off =
            crate::test_env::ScopedEnv::set(crate::semantic_cache::SEMANTIC_CACHE_ENV, "off");
        let temp = tempfile::tempdir().unwrap();
        let (store, finding) = triaged_store(temp.path());
        let primary = "anthropic:primary";
        let runtime = ModelKeyedVerifyRuntime {
            primary: primary.to_string(),
            fingerprint: finding.fingerprint.clone(),
            models: Mutex::new(Vec::new()),
        };

        // A single-pass run never splits, so the invalid escalation spec is
        // stored but never consulted: no error, no escalation annotation.
        let response = run_verify_finding_tool(VerifyFindingToolRequest {
            input: json!({
                "fingerprint": finding.fingerprint,
                "VERIFY_PASSES": 1,
                "escalationModel": "claude-big",
                "mcps": false,
            }),
            workspace_root: temp.path(),
            store: &store,
            runtime: Some(&runtime),
            configured_model: Some(primary),
            trace: None,
        })
        .unwrap();

        assert_eq!(response["status"], json!("completed"));
        assert!(
            response["data"].get("escalation").is_none(),
            "a non-split run never annotates an escalation"
        );
        assert!(response["warnings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn verify_finding_discloses_a_refused_same_model_escalation() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let _cache_off =
            crate::test_env::ScopedEnv::set(crate::semantic_cache::SEMANTIC_CACHE_ENV, "off");
        let temp = tempfile::tempdir().unwrap();
        let (store, finding) = triaged_store(temp.path());
        let primary = "anthropic:primary";
        let runtime = ModelKeyedVerifyRuntime {
            primary: primary.to_string(),
            fingerprint: finding.fingerprint.clone(),
            models: Mutex::new(Vec::new()),
        };

        let response = run_verify_finding_tool(VerifyFindingToolRequest {
            input: json!({
                "fingerprint": finding.fingerprint,
                "VERIFY_PASSES": 2,
                "escalationModel": primary,
                "mcps": false,
            }),
            workspace_root: temp.path(),
            store: &store,
            runtime: Some(&runtime),
            configured_model: Some(primary),
            trace: None,
        })
        .unwrap();

        let models = runtime.models.lock().unwrap();
        assert_eq!(
            models.len(),
            2,
            "a same-model escalation never runs an extra pass"
        );
        assert_eq!(response["data"]["escalation"]["attempted"], json!(false));
        assert!(
            !response["warnings"].as_array().unwrap().is_empty(),
            "a refusal reads as completed-with-warning"
        );
        // The split verdict stands unchanged (splits remain inconclusive).
        assert!(response["data"]["exploitable"].is_null());
    }

    /// Splits the primary panel (first exploitable, second not) and then FAILS
    /// the escalation model's pass, so the tie-breaker's error can be observed
    /// without discarding the paid split verdict.
    struct SplitThenFailEscalationRuntime {
        primary: String,
        fingerprint: String,
        calls: Mutex<u32>,
    }

    impl AgentRuntime for SplitThenFailEscalationRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            if request.model != self.primary {
                anyhow::bail!("escalation model overloaded (503)");
            }
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            let exploitable = *calls == 1;
            Ok(AgentQueryResponse {
                structured: Some(verify_result_json(exploitable, &self.fingerprint)),
                ..Default::default()
            })
        }

        fn triage_finding_blocking(
            &self,
            _: TriageRequest,
        ) -> Result<crate::findings::TriageOutcome> {
            unreachable!("verify:finding does not use the triage path")
        }
    }

    #[test]
    fn verify_keeps_the_split_verdict_when_the_escalation_pass_errors() {
        let _lock = crate::test_env::semantic_cache_env_lock();
        let _cache_off =
            crate::test_env::ScopedEnv::set(crate::semantic_cache::SEMANTIC_CACHE_ENV, "off");
        let temp = tempfile::tempdir().unwrap();
        let (store, finding) = triaged_store(temp.path());
        let primary = "anthropic:primary";
        let runtime = SplitThenFailEscalationRuntime {
            primary: primary.to_string(),
            fingerprint: finding.fingerprint.clone(),
            calls: Mutex::new(0),
        };

        let response = run_verify_finding_tool(VerifyFindingToolRequest {
            input: json!({
                "fingerprint": finding.fingerprint,
                "VERIFY_PASSES": 2,
                "escalationModel": "openai:escalation",
                "mcps": false,
            }),
            workspace_root: temp.path(),
            store: &store,
            runtime: Some(&runtime),
            configured_model: Some(primary),
            trace: None,
        })
        .unwrap();

        // No top-level failure: the paid split verdict survives.
        assert_eq!(response["status"], json!("partial"));
        assert!(response["data"]["exploitable"].is_null());
        assert_eq!(response["data"]["escalation"]["attempted"], json!(false));
        assert_eq!(
            response["data"]["escalation"]["refusedToken"],
            json!("attempt-failed")
        );
        let warning = response["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            warning.contains("escalation attempt failed"),
            "the failure is disclosed as a warning: {warning}"
        );
    }

    #[test]
    fn adopting_an_escalation_verdict_is_coherent_across_exploitability_and_proof() {
        // The split panel's representative is a NOT-exploitable pass
        // (proofVerdict not_reproduced, no PoC). The escalation pass is
        // exploitable with its own proofVerdict/PoC.
        let mut result = json!({
            "fingerprint": "fp",
            "exploitable": false,
            "confidence": 0.4,
            "proofLevel": 2,
            "proofVerdict": "not_reproduced",
            "pocPayload": Value::Null,
            "consensus": {
                "passes": 2,
                "exploitableVotes": 1,
                "notExploitableVotes": 1,
                "verdict": "not-exploitable",
                "unanimous": false
            }
        });
        let escalation_pass = json!({
            "fingerprint": "fp",
            "exploitable": true,
            "confidence": 0.9,
            "proofLevel": 3,
            "proofVerdict": "exploited",
            "pocPayload": "X"
        });

        apply_escalation_verdict(&mut result, &escalation_pass, "openai:escalation");

        // All three fields come from the SAME (escalation) pass.
        assert_eq!(result["exploitable"], json!(true));
        assert_eq!(result["proofVerdict"], json!("exploited"));
        assert_eq!(result["pocPayload"], json!("X"));
        // This is exactly ModelProofCandidate::validate's contract: an
        // `exploited` verdict iff exploitable. Field-by-field merging used to
        // leave exploitable=true beside proofVerdict=not_reproduced, which the
        // proof candidate rejected.
        assert_eq!(
            result["proofVerdict"] == json!("exploited"),
            result["exploitable"] == json!(true)
        );
        // The consensus block is preserved verbatim: the split stays visible and
        // unanimity is never forged.
        assert_eq!(result["consensus"]["unanimous"], json!(false));
        assert_eq!(result["consensus"]["passes"], json!(2));
        // The escalation stage records the full panel size, not the tie count.
        assert_eq!(result["escalation"]["panelPasses"], json!(2));
    }
}
