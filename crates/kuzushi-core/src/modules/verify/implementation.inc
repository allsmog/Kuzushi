use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::findings::{Finding, TriageOutcome};
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};

use super::input::resolve_prompt_override;
use super::json_fields::{
    normalize_attack_path, normalize_code_citations, normalize_controls, normalize_object_array,
    read_object_bool, read_object_f64, read_object_nullable_string, read_object_string,
    read_object_string_array, read_object_u64, string_or_null,
};
use super::ToolExecutionContext;

#[derive(Debug, Clone)]
struct VerifyFindingInput {
    fingerprint: String,
    prompt_template: Option<String>,
}

impl VerifyFindingInput {
    fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        let fingerprint = match input.get("fingerprint") {
            Some(Value::String(value)) if !value.trim().is_empty() => value.trim().to_string(),
            Some(_) => anyhow::bail!("verify:finding fingerprint must be a non-empty string"),
            None => anyhow::bail!("verify:finding requires a fingerprint"),
        };
        let prompt_template = match input.get("VERIFY_PROMPT") {
            Some(Value::String(value)) if !value.trim().is_empty() => {
                Some(resolve_prompt_override(value.trim(), cwd)?)
            }
            Some(Value::String(_)) | None => None,
            Some(_) => anyhow::bail!("verify:finding VERIFY_PROMPT must be a string"),
        };

        Ok(Self {
            fingerprint,
            prompt_template,
        })
    }
}

const VERIFY_SYSTEM_PROMPT: &str = r#"You are Kuzushi's exploitability verification agent.
Return only JSON with these fields:
{"fingerprint":"...","exploitable":true|false,"poc_payload":string|null,"poc_description":"...","attack_vector":string|null,"preconditions":["..."],"confidence":0.0-1.0}."#;

fn verification_result_schema() -> Value {
    json!({
        "type": "object",
        "required": ["fingerprint", "exploitable", "confidence"],
        "additionalProperties": true,
        "properties": {
            "fingerprint": {"type": "string"},
            "exploitable": {"type": "boolean"},
            "pocPayload": {"type": ["string", "null"]},
            "poc_payload": {"type": ["string", "null"]},
            "pocDescription": {"type": "string"},
            "poc_description": {"type": "string"},
            "attackVector": {"type": ["string", "null"]},
            "attack_vector": {"type": ["string", "null"]},
            "preconditions": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number"}
        }
    })
}

pub(in crate::modules) fn run_verify_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "verify:finding needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("verify:finding requires a findings store for the active workspace")?;
    let input = VerifyFindingInput::from_tool_input(&input, workspace.root())?;
    let Some(finding) = store.get_finding_by_reference(&input.fingerprint)? else {
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
    let runtime = runtime.context(
        "verify:finding requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = ctx.config.model.clone().context(
        "verify:finding requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model",
    )?;

    let prompt = build_verify_prompt(&finding, &triage, input.prompt_template.as_deref())?;
    let result = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            workspace.root().to_path_buf(),
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

    Ok(json!({
        "ok": true,
        "output": lines.join("\n"),
        "data": result,
        "costUsd": 0.0,
    }))
}

/// Empirical exploit-gated verify: scaffolds a sandboxed test harness from
/// the finding's location and observes whether it crashes. Promotes to
/// `proof_level=4` only on observed crash inside an isolating sandbox.
/// Complementary to (not a replacement for) the LLM-driven `verify:finding`.
pub(in crate::modules) fn run_verify_exploit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "verify:exploit needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("verify:exploit requires a findings store for the active workspace")?;

    let input = VerifyExploitInput::from_tool_input(&input)?;
    let Some(finding) = store.get_finding_by_reference(&input.fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!("[-] No finding with fingerprint '{}'.", input.fingerprint),
        }));
    };

    let outcome = run_empirical_verify(&finding, &input)?;
    let persisted_id = persist_verify_exploit_outcome(store, &finding, &outcome);
    let response = verify_exploit_response(&finding, &outcome, persisted_id);
    let _ = workspace;
    Ok(response)
}

#[derive(Debug, Clone)]
struct VerifyExploitInput {
    fingerprint: String,
    trust_plain_backend: bool,
    timeout_ms: u64,
}

impl VerifyExploitInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            fingerprint: verify_exploit_fingerprint(input)?,
            trust_plain_backend: verify_exploit_bool_input(
                input,
                "trustPlainBackend",
                "trust_plain_backend",
                false,
            ),
            timeout_ms: verify_exploit_u64_input(input, "timeoutMs", "timeout_ms", 60_000),
        })
    }
}

fn verify_exploit_fingerprint(input: &Value) -> Result<String> {
    match input.get("fingerprint") {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        Some(_) => anyhow::bail!("verify:exploit fingerprint must be a non-empty string"),
        None => anyhow::bail!("verify:exploit requires a fingerprint"),
    }
}

fn verify_exploit_bool_input(
    input: &Value,
    camel_key: &str,
    snake_key: &str,
    default: bool,
) -> bool {
    input
        .get(camel_key)
        .or_else(|| input.get(snake_key))
        .and_then(Value::as_bool)
        .unwrap_or(default)
}

fn verify_exploit_u64_input(input: &Value, camel_key: &str, snake_key: &str, default: u64) -> u64 {
    input
        .get(camel_key)
        .or_else(|| input.get(snake_key))
        .and_then(Value::as_u64)
        .unwrap_or(default)
}

fn run_empirical_verify(
    finding: &Finding,
    input: &VerifyExploitInput,
) -> Result<crate::verify::VerificationOutcome> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("verify:exploit could not start a tokio runtime")?
        .block_on(crate::verify::verify_finding(
            finding,
            crate::verify::VerifyOptions {
                backend: None,
                timeout_ms: input.timeout_ms,
                trust_plain_backend: input.trust_plain_backend,
            },
        ))
}

fn persist_verify_exploit_outcome(
    store: &crate::findings::FindingStore,
    finding: &Finding,
    outcome: &crate::verify::VerificationOutcome,
) -> Option<i64> {
    let finding_db_id = finding.id?;
    save_verify_exploit_outcome(store, finding_db_id, finding, outcome)
}

fn save_verify_exploit_outcome(
    store: &crate::findings::FindingStore,
    finding_db_id: i64,
    finding: &Finding,
    outcome: &crate::verify::VerificationOutcome,
) -> Option<i64> {
    let record = outcome.to_persisted();
    match store.save_verification(finding_db_id, &record) {
        Ok(id) => Some(id),
        Err(err) => {
            eprintln!(
                "[verify:exploit] could not persist verification for finding {}: {err}",
                finding.fingerprint
            );
            None
        }
    }
}

fn verify_exploit_response(
    finding: &Finding,
    outcome: &crate::verify::VerificationOutcome,
    persisted_id: Option<i64>,
) -> Value {
    let mut response = crate::verify::to_tool_json(finding, outcome);
    if let Some(obj) = response.as_object_mut() {
        obj.insert(
            "output".to_string(),
            Value::String(verify_exploit_summary(outcome)),
        );
        obj.insert("costUsd".to_string(), json!(outcome.cost_usd));
        insert_verification_row_id(obj, persisted_id);
    }
    response
}

fn verify_exploit_summary(outcome: &crate::verify::VerificationOutcome) -> String {
    format!(
        "[+] verify:exploit  proof_level={}  verdict={}  backend={:?}  duration_ms={}",
        outcome.proof_level,
        outcome.proof_verdict.as_str(),
        outcome.backend,
        outcome.duration_ms
    )
}

fn insert_verification_row_id(obj: &mut Map<String, Value>, persisted_id: Option<i64>) {
    if let Some(id) = persisted_id {
        obj.insert("verificationRowId".to_string(), json!(id));
    }
}

fn build_verify_prompt(
    finding: &Finding,
    triage: &TriageOutcome,
    template: Option<&str>,
) -> Result<String> {
    let finding_json =
        serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let triage_json = serde_json::to_string_pretty(triage).context("Could not serialize triage")?;
    let prefix = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(
            "Verify exploitability for this triaged finding. Be conservative and return non-exploitable when runtime evidence is incomplete.",
        );
    Ok(format!(
        "{prefix}\n\nFinding JSON:\n{finding_json}\n\nTriage JSON:\n{triage_json}"
    ))
}

fn normalize_verification_result(raw: Value, fallback_fingerprint: &str) -> Result<Value> {
    let Value::Object(object) = raw else {
        anyhow::bail!("verification output parse failed: expected a JSON object");
    };

    let fingerprint = read_object_string(&object, &["fingerprint"])
        .unwrap_or_else(|| fallback_fingerprint.to_string());
    let exploitable = read_object_bool(&object, &["exploitable"]).unwrap_or(false);
    let poc_payload = read_object_nullable_string(&object, &["pocPayload", "poc_payload"]);
    let poc_description =
        read_object_string(&object, &["pocDescription", "poc_description"]).unwrap_or_default();
    let attack_vector = read_object_nullable_string(&object, &["attackVector", "attack_vector"]);
    let preconditions = read_object_string_array(&object, &["preconditions"]);
    let confidence = read_object_f64(&object, &["confidence"])
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);

    let mut result = Map::new();
    result.insert("fingerprint".to_string(), json!(fingerprint));
    result.insert("exploitable".to_string(), json!(exploitable));
    result.insert("pocPayload".to_string(), string_or_null(poc_payload));
    result.insert("pocDescription".to_string(), json!(poc_description));
    result.insert("attackVector".to_string(), string_or_null(attack_vector));
    result.insert("preconditions".to_string(), json!(preconditions));
    result.insert("confidence".to_string(), json!(confidence));

    if let Some(level) = read_object_u64(&object, &["proofLevel", "proof_level"])
        .filter(|level| (1..=4).contains(level))
    {
        result.insert("proofLevel".to_string(), json!(level));
    }
    if let Some(verdict) = read_object_string(&object, &["proofVerdict", "proof_verdict"]) {
        result.insert("proofVerdict".to_string(), json!(verdict));
    }
    if let Some(value) = normalize_object_array(&object, &["bypassAttempts", "bypass_attempts"]) {
        result.insert("bypassAttempts".to_string(), value);
    }
    if let Some(value) = normalize_code_citations(&object) {
        result.insert("codeCitations".to_string(), value);
    }
    if let Some(value) = normalize_attack_path(&object) {
        result.insert("attackPath".to_string(), value);
    }
    if let Some(value) = normalize_object_array(&object, &["assumptions"]) {
        result.insert("assumptions".to_string(), value);
    }
    if let Some(value) = normalize_controls(&object) {
        result.insert("controls".to_string(), value);
    }
    if let Some(value) = normalize_object_array(&object, &["blindspots"]) {
        result.insert("blindspots".to_string(), value);
    }

    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::super::json_fields::parse_json_object_from_agent_text;
    use super::*;
    use crate::config::V2Config;
    use crate::findings::FindingStore;
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn normalizes_verification_result_aliases_and_clamps_confidence() {
        let result = normalize_verification_result(
            json!({
                "exploitable": true,
                "poc_payload": "curl /admin",
                "poc_description": "reachable admin action",
                "attack_vector": "HTTP POST",
                "preconditions": [" authenticated "],
                "confidence": 1.5,
                "proof_level": 4,
                "proof_verdict": "exploited",
                "bypass_attempts": ["csrf token replay"],
                "code_citations": [{
                    "file_path": "src/admin.rs",
                    "start_line": 44,
                    "description": "sink"
                }]
            }),
            "fallback-fp",
        )
        .unwrap();

        assert_eq!(result["fingerprint"], "fallback-fp");
        assert_eq!(result["exploitable"], true);
        assert_eq!(result["pocPayload"], "curl /admin");
        assert_eq!(result["attackVector"], "HTTP POST");
        assert_eq!(result["confidence"], 1.0);
        assert_eq!(result["proofLevel"], 4);
        assert_eq!(result["codeCitations"][0]["filePath"], "src/admin.rs");
    }

    #[test]
    fn rejects_non_object_verification_output() {
        let err = normalize_verification_result(json!(["nope"]), "fp")
            .unwrap_err()
            .to_string();

        assert!(err.contains("expected a JSON object"));
    }

    #[test]
    fn builds_prompt_with_template_and_payloads() {
        let finding = Finding::new_tool(
            "semgrep",
            "demo.rule",
            "src/db.rs",
            7,
            None,
            crate::findings::Severity::High,
            "SQL injection",
        );
        let triage = TriageOutcome {
            rationale: "confirmed".to_string(),
            ..Default::default()
        };

        let prompt = build_verify_prompt(&finding, &triage, Some("Custom verify")).unwrap();

        assert!(prompt.starts_with("Custom verify"));
        assert!(prompt.contains("SQL injection"));
        assert!(prompt.contains("confirmed"));
    }

    #[test]
    fn parses_structured_agent_text_through_shared_json_helper() {
        let parsed = parse_json_object_from_agent_text("text {\"exploitable\":false}").unwrap();
        assert_eq!(parsed["exploitable"], false);
    }

    #[test]
    fn run_verify_exploit_reports_missing_finding_without_running_backend() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };

        let response = run_verify_exploit(json!({"fingerprint": "missing"}), &ctx).unwrap();

        assert_eq!(response["ok"], json!(false));
        assert!(response["output"]
            .as_str()
            .unwrap()
            .contains("No finding with fingerprint 'missing'"));
    }
}
