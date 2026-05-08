use super::prelude::*;
use super::*;

pub(in crate::modules) fn parse_triage_prompt_template(
    input: &Value,
    cwd: &Path,
) -> Result<Option<String>> {
    optional_nonempty_string(input, "TRIAGE_PROMPT")?
        .map(|value| resolve_prompt_override(&value, cwd))
        .transpose()
}

pub(in crate::modules) fn parse_triage_scan_id(input: &Value) -> Result<Option<String>> {
    Ok(optional_nonempty_string(input, "scanId")?.or(optional_nonempty_string(input, "scan_id")?))
}

pub(in crate::modules) fn parse_triage_concurrency(input: &Value) -> Result<usize> {
    match input.get("concurrency") {
        Some(Value::Number(n)) => Ok(n.as_u64().unwrap_or(8).clamp(1, 64) as usize),
        None => Ok(8),
        Some(_) => anyhow::bail!("triage:run concurrency must be a positive integer"),
    }
}

pub(in crate::modules) fn parse_triage_cost_cap_usd(input: &Value) -> Result<Option<f64>> {
    match input
        .get("costCapUsd")
        .or_else(|| input.get("cost_cap_usd"))
    {
        Some(Value::Number(n)) => Ok(n.as_f64()),
        None => Ok(cost_cap_from_env()),
        Some(_) => anyhow::bail!("triage:run costCapUsd must be a number"),
    }
}

pub(in crate::modules) fn cost_cap_from_env() -> Option<f64> {
    std::env::var("KUZUSHI_COST_CAP_USD")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
}

pub(in crate::modules) fn parse_triage_prefilter_threshold(input: &Value) -> i64 {
    input
        .get("prefilterThreshold")
        .or_else(|| input.get("prefilter_threshold"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

pub(in crate::modules) fn parse_triage_stage2_tier(input: &Value) -> Result<ModelTier> {
    match input
        .get("stage2Tier")
        .or_else(|| input.get("stage2_tier"))
        .and_then(Value::as_str)
    {
        Some("cheap") | None => Ok(ModelTier::Cheap),
        Some("mid") => Ok(ModelTier::Mid),
        Some("deep") => Ok(ModelTier::Deep),
        Some(other) => {
            anyhow::bail!("triage:run stage2Tier must be one of cheap|mid|deep (got {other:?})")
        }
    }
}

pub(in crate::modules) fn prefilter_score(finding: &Finding) -> i64 {
    let mut score: i64 = match finding.severity {
        Severity::Critical => 8,
        Severity::High => 5,
        Severity::Medium => 3,
        Severity::Low | Severity::Info | Severity::Unknown => 1,
    };
    let msg = finding.message.to_ascii_lowercase();
    for keyword in [
        "attacker",
        "untrusted",
        "user-controlled",
        "user controlled",
        "out-of-bounds",
        "use-after-free",
        "race condition",
        "buffer overflow",
        "integer overflow",
        "memory corruption",
        "command injection",
        "sql injection",
    ] {
        if msg.contains(keyword) {
            score += 2;
        }
    }
    match finding.tool.as_str() {
        "codeql" | "cargo-audit" | "iac-scan" | "secret-scan" => score += 2,
        "semgrep" => score += 1,
        _ => {}
    }
    score
}
