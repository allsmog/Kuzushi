use super::{
    build_verify_prompt, normalize_verification_result, verification_result_schema,
    verify_system_prompt, VerifyFindingInput,
};
use crate::findings::FindingStore;
use crate::runtime::{AgentQueryRequest, AgentRuntime, RuntimeCost, RuntimeCostReport};
use crate::structured_output::{
    query_required_structured_json_with_cost, CostedStructuredJson, StructuredJsonContract,
};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) struct VerifyFindingToolRequest<'a> {
    pub(crate) input: Value,
    pub(crate) workspace_root: &'a Path,
    pub(crate) store: &'a FindingStore,
    pub(crate) runtime: Option<&'a dyn AgentRuntime>,
    pub(crate) configured_model: Option<&'a str>,
}

pub(crate) fn run_verify_finding_tool(request: VerifyFindingToolRequest<'_>) -> Result<Value> {
    let input = VerifyFindingInput::from_tool_input(&request.input, request.workspace_root)?;
    let Some(finding) = request.store.get_finding_by_reference(&input.fingerprint)? else {
        return Ok(missing_finding_response(&input.fingerprint));
    };
    // Require a triage verdict to exist before spending a verify pass, but
    // deliberately do NOT forward the triage reasoning to the verifier — it
    // must reach its own verdict from the claim and the code (see
    // build_verify_prompt).
    if finding.triage.is_none() {
        return Ok(untriaged_finding_response(&finding.fingerprint));
    }

    let runtime = require_verify_finding_runtime(request.runtime)?;
    let model = verify_finding_model(&request.input, request.configured_model)?;
    let prompt = build_verify_prompt(&finding, input.prompt_template.as_deref())?;

    // Each pass is an independent adversarial verifier with no shared
    // context; a strict majority must agree before a finding is confirmed
    // exploitable (see verify_consensus). passes == 1 is the single-pass
    // default and skips the consensus machinery entirely.
    let mut passes = Vec::with_capacity(input.passes as usize);
    for _ in 0..input.passes {
        passes.push(run_one_verify_pass(
            runtime,
            &model,
            request.workspace_root,
            &prompt,
            &finding.fingerprint,
            &input,
        )?);
    }
    let cost = passes.iter().try_fold(
        RuntimeCostReport::known(RuntimeCost::ZERO),
        |total, pass| total.checked_add(pass.cost_report()?, "verification consensus cost"),
    )?;
    let result = super::verify_consensus::combine_verify_passes(
        passes.into_iter().map(|pass| pass.value).collect(),
    )?;

    verify_finding_response(result, cost)
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
    query_required_structured_json_with_cost(
        runtime,
        verify_agent_query_request(model, workspace_root, prompt, input),
        StructuredJsonContract::new(
            "verify:finding",
            "VerificationResult",
            verification_result_schema(),
        ),
        |raw| normalize_verification_result(raw, fingerprint),
    )
}

fn verify_agent_query_request(
    model: &str,
    workspace_root: &Path,
    prompt: &str,
    input: &VerifyFindingInput,
) -> AgentQueryRequest {
    let mut request = AgentQueryRequest::new(
        model,
        workspace_root.to_path_buf(),
        verify_system_prompt(),
        prompt.to_string(),
    );
    if input.mcps {
        request = request.with_tool_policy(
            crate::proof::whitebox_policy::whitebox_static_policy_for_target(workspace_root),
        );
    }
    if let Some(timeout_ms) = input.mcp_tool_timeout_ms {
        let runtime_options = crate::runtime::AgentRuntimeOptions {
            mcp_tool_timeout_ms: Some(timeout_ms),
            ..Default::default()
        };
        request = request.with_runtime_options(runtime_options);
    }
    request
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

fn untriaged_finding_response(fingerprint: &str) -> Value {
    let output =
        format!("[-] Finding '{fingerprint}' has no triage verdict. Run triage:run first.");
    crate::module_result::failed_output_result(
        "verify:finding failed",
        output,
        json!({
            "fingerprint": fingerprint,
            "reason": "missing-triage",
        }),
    )
}

fn require_verify_finding_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "verify:finding requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn verify_finding_response(result: Value, cost: RuntimeCostReport) -> Result<Value> {
    let exploitable = required_result_bool(&result, "exploitable")?;
    let verdict = if exploitable {
        "VULNERABLE"
    } else {
        "not-exploitable"
    };
    let mut lines = vec![
        "[+] verify:finding complete".to_string(),
        format!("      {verdict}"),
    ];
    if let Some(vector) = result
        .get("attackVector")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        lines.push(format!("      vector: {vector}"));
    }
    if cost.is_unavailable() {
        lines.push("      cost unavailable".to_string());
    } else {
        let cost_label = if cost.is_complete() {
            "cost"
        } else {
            "observed cost"
        };
        lines.push(format!("      {cost_label}=${:.4}", cost.observed_usd()));
    }
    let summary = format!("verify:finding complete ({verdict})");
    let proof = verification_proof_snapshot(&result)?;
    let data = verification_response_data(result, &proof, &summary)?;
    let mut response =
        crate::module_result::completed_output_result(summary, lines.join("\n"), data);
    add_verification_response_metadata(&mut response, proof, cost);
    Ok(response)
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
    }))
}

fn required_result_field(result: &Value, key: &str) -> Result<Value> {
    result
        .get(key)
        .cloned()
        .with_context(|| format!("normalized verification result missing `{key}`"))
}

fn required_result_bool(result: &Value, key: &str) -> Result<bool> {
    let value = result
        .get(key)
        .with_context(|| format!("normalized verification result missing boolean `{key}`"))?;
    value.as_bool().with_context(|| {
        format!(
            "normalized verification result field `{key}` must be boolean, got {}",
            value_type_name(value)
        )
    })
}

fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known_cost(cost_usd: f64) -> RuntimeCostReport {
        RuntimeCostReport::known(RuntimeCost::from_usd(cost_usd, "test cost").unwrap())
    }

    #[test]
    fn verify_response_exposes_non_empirical_proof_snapshot() {
        let response = verify_finding_response(
            json!({
                "fingerprint": "fp-1",
                "exploitable": true,
                "confidence": 0.7,
                "proofLevel": 2,
                "proofVerdict": "not_reproduced"
            }),
            known_cost(0.25),
        )
        .unwrap();

        assert_eq!(response["status"], json!("completed"));
        assert_eq!(response["proof"]["empirical"], json!(false));
        assert_eq!(response["data"]["proof"]["fingerprint"], json!("fp-1"));
        assert_eq!(response["data"]["exploitable"], json!(true));
        assert_eq!(response["costUsd"], json!(0.25));
        assert!(response["artifacts"].as_array().unwrap().is_empty());
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

        assert!(error.contains("missing boolean `exploitable`"));
    }

    #[test]
    fn verify_response_omits_monetary_fields_when_cost_is_unavailable() {
        let response = verify_finding_response(
            json!({
                "fingerprint": "fp-1",
                "exploitable": false,
                "confidence": 0.7,
                "proofLevel": 2,
                "proofVerdict": "not_reproduced"
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
        };

        let request = verify_agent_query_request("model", temp.path(), "prompt", &input);

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
    fn verify_request_can_disable_mcp_policy() {
        let input = VerifyFindingInput {
            fingerprint: "F-1".to_string(),
            prompt_template: None,
            passes: 1,
            mcps: false,
            mcp_tool_timeout_ms: None,
        };

        let request = verify_agent_query_request("model", Path::new("."), "prompt", &input);

        assert!(request.tool_policy.is_default());
        assert!(request.runtime_options.is_none());
    }
}
