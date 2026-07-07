use anyhow::{Context, Result};
use serde_json::Value;

pub(super) fn stable_fp_from_payload(payload: &Value) -> Option<&str> {
    payload
        .get("stableFp")
        .or_else(|| payload.get("oldFp"))
        .or_else(|| payload.get("stable_fp"))
        .and_then(Value::as_str)
}

pub(super) fn payload_str<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

pub(super) fn require_payload_str<'a>(payload: &'a Value, key: &str) -> Result<&'a str> {
    payload_str(payload, key).with_context(|| format!("event payload missing {key}"))
}

pub(super) fn payload_i64(payload: &Value, key: &str) -> Option<i64> {
    payload.get(key).and_then(Value::as_i64)
}

pub(super) fn require_payload_i64(payload: &Value, key: &str) -> Result<i64> {
    payload_i64(payload, key).with_context(|| format!("event payload missing integer {key}"))
}

pub(super) fn payload_u64(payload: &Value, key: &str) -> Option<u64> {
    payload.get(key).and_then(Value::as_u64)
}

pub(super) fn require_payload_u64(payload: &Value, key: &str) -> Result<u64> {
    payload_u64(payload, key).with_context(|| format!("event payload missing integer {key}"))
}

pub(super) fn payload_f64(payload: &Value, key: &str) -> Option<f64> {
    payload.get(key).and_then(Value::as_f64)
}

pub(super) fn require_payload_f64(payload: &Value, key: &str) -> Result<f64> {
    payload_f64(payload, key).with_context(|| format!("event payload missing number {key}"))
}

pub(super) fn triage_verdict_for_review(verdict: &str) -> Result<Option<&'static str>> {
    Ok(match verdict {
        "confirmed" => Some("true_positive"),
        "rejected_false_positive" => Some("false_positive"),
        "accepted_risk" => Some("by_design"),
        "needs_review" => Some("needs_review"),
        "suppressed" | "deferred" => None,
        _ => anyhow::bail!("unknown review verdict {verdict:?}"),
    })
}
