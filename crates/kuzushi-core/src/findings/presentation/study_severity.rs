use crate::capabilities::campaign::ScanBatchGateOutcome;

/// Describe the recorded severity cutoff without implying a security verdict.
pub fn batch_severity_summary(gate: Option<&ScanBatchGateOutcome>) -> String {
    let Some(gate) = gate else {
        return "Severity assessment: unavailable".into();
    };
    let Some(threshold) = gate.threshold else {
        return "Severity cutoff: not configured".into();
    };
    configured_cutoff_summary(threshold, gate.blocking_safe_fold_count)
}

fn configured_cutoff_summary(threshold: crate::findings::Severity, count: usize) -> String {
    let threshold = threshold.as_str();
    let result = if count == 0 { "not reached" } else { "reached" };
    let noun = if count == 1 { "finding" } else { "findings" };
    format!("Severity cutoff {threshold}: {result} · {count} qualifying {noun} in completed passes")
}

#[cfg(test)]
mod tests;
