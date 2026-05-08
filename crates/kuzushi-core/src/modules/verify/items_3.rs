use super::prelude::*;
use super::*;

impl VerifyExploitInput {
    pub(in crate::modules) fn from_tool_input(input: &Value) -> Result<Self> {
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

pub(in crate::modules) fn verify_exploit_fingerprint(input: &Value) -> Result<String> {
    match input.get("fingerprint") {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        Some(_) => anyhow::bail!("verify:exploit fingerprint must be a non-empty string"),
        None => anyhow::bail!("verify:exploit requires a fingerprint"),
    }
}

pub(in crate::modules) fn verify_exploit_bool_input(
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

pub(in crate::modules) fn verify_exploit_u64_input(
    input: &Value,
    camel_key: &str,
    snake_key: &str,
    default: u64,
) -> u64 {
    input
        .get(camel_key)
        .or_else(|| input.get(snake_key))
        .and_then(Value::as_u64)
        .unwrap_or(default)
}

pub(in crate::modules) fn run_empirical_verify(
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

pub(in crate::modules) fn persist_verify_exploit_outcome(
    store: &crate::findings::FindingStore,
    finding: &Finding,
    outcome: &crate::verify::VerificationOutcome,
) -> Option<i64> {
    let finding_db_id = finding.id?;
    save_verify_exploit_outcome(store, finding_db_id, finding, outcome)
}

pub(in crate::modules) fn save_verify_exploit_outcome(
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

pub(in crate::modules) fn verify_exploit_response(
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

pub(in crate::modules) fn verify_exploit_summary(
    outcome: &crate::verify::VerificationOutcome,
) -> String {
    format!(
        "[+] verify:exploit  proof_level={}  verdict={}  backend={:?}  duration_ms={}",
        outcome.proof_level,
        outcome.proof_verdict.as_str(),
        outcome.backend,
        outcome.duration_ms
    )
}
