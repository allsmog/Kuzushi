use super::prelude::*;
use super::*;

pub fn parse_budget_flag(value: &str) -> Result<Vec<(Operation, f64)>> {
    let mut out = Vec::new();
    for raw in value.split(',') {
        let pair = raw.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, val) = pair.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("budget pair {pair:?} must use op=USD form (e.g. deep-audit=200)")
        })?;
        let key = key.trim().replace('-', "_").to_lowercase();
        let op = Operation::from_db_str(&key).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown budget op {key:?}; known: triage, classifier_gate, deep_audit, full_mode_multi, patch"
            )
        })?;
        let usd: f64 = val
            .trim()
            .parse()
            .with_context(|| format!("budget value for {key} is not a number: {val:?}"))?;
        anyhow::ensure!(
            usd.is_finite() && usd >= 0.0,
            "budget for {key} must be non-negative, got {usd}"
        );
        out.push((op, usd));
    }
    Ok(out)
}
