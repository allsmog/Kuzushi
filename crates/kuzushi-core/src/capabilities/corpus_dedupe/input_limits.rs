use super::*;
use crate::findings::DedupeLedgerLimits;

pub(super) fn ledger_limits(input: &Value) -> Result<DedupeLedgerLimits> {
    let defaults = DedupeLedgerLimits::default();
    let limits = DedupeLedgerLimits {
        max_observations: bounded_count(input, "maxLedgerObservations", defaults.max_observations)?,
        max_bytes: bounded_count(input, "maxLedgerBytes", defaults.max_bytes)?,
        read_ms: bounded_count(input, "maxLedgerReadMs", defaults.read_ms as usize)? as u64,
    };
    limits.validate()?;
    Ok(limits)
}

pub(super) fn judge_prompt_limit(input: &Value) -> Result<usize> {
    let bytes = bounded_count(input, "maxJudgePromptBytes", 131_072)?;
    anyhow::ensure!(
        (1..=524_288).contains(&bytes),
        "maxJudgePromptBytes must be between 1 and 524288"
    );
    Ok(bytes)
}

pub(super) fn confirmation_limit(input: &Value) -> Result<usize> {
    let bytes = bounded_count(input, "maxConfirmationBytes", 262_144)?;
    anyhow::ensure!(
        (1..=8_388_608).contains(&bytes),
        "maxConfirmationBytes must be between 1 and 8388608"
    );
    Ok(bytes)
}
