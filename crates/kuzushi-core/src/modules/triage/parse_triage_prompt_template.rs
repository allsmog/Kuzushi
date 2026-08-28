use super::*;

pub(in crate::modules) fn parse_triage_prompt_template(
    input: &Value,
    cwd: &Path,
) -> Result<Option<String>> {
    optional_nonempty_string(input, "TRIAGE_PROMPT")?
        .map(|value| resolve_prompt_override(&value, cwd))
        .transpose()
}

/// Fold the persisted threat-model digest into the stage-2 prompt template so
/// verdicts weigh modeled threats. Deliberately part of the template: the
/// runtime cache key hashes it, so a changed threat model re-triages instead
/// of replaying verdicts judged under stale context.
pub(in crate::modules) fn apply_threat_model_triage_context(
    input: &mut TriageRunInput,
    root: &Path,
) -> Result<()> {
    let Some(digest) = crate::capabilities::agentic_sast::threat_model_scan_context(root)? else {
        return Ok(());
    };
    let base = input
        .prompt_template
        .clone()
        .unwrap_or_else(|| crate::runtime::DEFAULT_TRIAGE_PROMPT.to_string());
    input.prompt_template = Some(format!(
        "{base}\n\nWeigh whether the finding realizes one of the modeled threats below when \
judging impact; the digest is derived context, not ground truth.\n{}",
        crate::runbooks::untrusted::render_untrusted_derived_block("threat-model-digest", &digest),
    ));
    Ok(())
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
        None => Ok(None),
        Some(_) => anyhow::bail!("triage:run costCapUsd must be a number"),
    }
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
        "codeql" | "cargo-audit" | "iac-scan" | "license-scan" | "secret-scan" => score += 2,
        "semgrep" => score += 1,
        _ => {}
    }
    score
}
