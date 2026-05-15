use super::{
    build_verify_prompt, normalize_verification_result, verification_result_schema,
    VerifyFindingInput, VERIFY_SYSTEM_PROMPT,
};
use crate::findings::FindingStore;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
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
        return Ok(json!({
            "ok": false,
            "output": format!("[-] No finding with fingerprint '{}'.", input.fingerprint),
        }));
    };
    let Some(triage) = finding.triage.clone() else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "[-] Finding '{}' has no triage verdict. Run triage:run first.",
                finding.fingerprint
            ),
        }));
    };

    let runtime = require_verify_finding_runtime(request.runtime)?;
    let model =
        crate::runtime::require_configured_model("verify:finding", request.configured_model)?;
    let prompt = build_verify_prompt(&finding, &triage, input.prompt_template.as_deref())?;
    let result = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            request.workspace_root.to_path_buf(),
            VERIFY_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new(
            "verify:finding",
            "VerificationResult",
            verification_result_schema(),
        ),
        |raw| normalize_verification_result(raw, &finding.fingerprint),
    )?;

    Ok(verify_finding_response(result))
}

fn require_verify_finding_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "verify:finding requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn verify_finding_response(result: Value) -> Value {
    let exploitable = result
        .get("exploitable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
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
    lines.push("      cost=$0.0000".to_string());
    let summary = format!("verify:finding complete ({verdict})");
    let proof = verification_proof_snapshot(&result);

    json!({
        "ok": true,
        "status": "completed",
        "summary": summary,
        "output": lines.join("\n"),
        "artifacts": [],
        "warnings": [],
        "errors": [],
        "data": verification_response_data(result, &proof, &summary),
        "proof": proof,
        "costUsd": 0.0,
    })
}

fn verification_response_data(result: Value, proof: &Value, summary: &str) -> Value {
    let mut data = result.as_object().cloned().unwrap_or_default();
    data.insert("summary".to_string(), json!(summary));
    data.insert("proof".to_string(), proof.clone());
    data.insert("verification".to_string(), result);
    Value::Object(data)
}

fn verification_proof_snapshot(result: &Value) -> Value {
    json!({
        "kind": "llm-exploitability-review",
        "empirical": false,
        "fingerprint": result.get("fingerprint").cloned().unwrap_or(Value::Null),
        "exploitable": result.get("exploitable").cloned().unwrap_or(json!(false)),
        "proofLevel": result.get("proofLevel").cloned().unwrap_or(json!(1)),
        "proofVerdict": result.get("proofVerdict").cloned().unwrap_or(json!("not_reproduced")),
        "confidence": result.get("confidence").cloned().unwrap_or(json!(0.0)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_response_exposes_non_empirical_proof_snapshot() {
        let response = verify_finding_response(json!({
            "fingerprint": "fp-1",
            "exploitable": true,
            "confidence": 0.7,
            "proofLevel": 2,
            "proofVerdict": "not_reproduced"
        }));

        assert_eq!(response["status"], json!("completed"));
        assert_eq!(response["proof"]["empirical"], json!(false));
        assert_eq!(response["data"]["proof"]["fingerprint"], json!("fp-1"));
        assert_eq!(response["data"]["exploitable"], json!(true));
        assert!(response["artifacts"].as_array().unwrap().is_empty());
    }
}
