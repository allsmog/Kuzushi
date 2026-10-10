use anyhow::{Context, Result};
use serde_json::Value;

#[derive(Clone, Copy)]
pub(super) struct GroundingLimits {
    pub(super) findings: usize,
    pub(super) per_file: usize,
    pub(super) total_bytes: usize,
}

impl GroundingLimits {
    pub(super) fn from_input(input: &Value) -> Result<Self> {
        Ok(Self {
            findings: count(input, "limit", 500, 100_000, true)?,
            per_file: count(
                input,
                "maxBytesPerFile",
                8 * 1024 * 1024,
                8 * 1024 * 1024,
                false,
            )?,
            total_bytes: count(
                input,
                "maxTotalBytes",
                64 * 1024 * 1024,
                512 * 1024 * 1024,
                false,
            )?,
        })
    }
}

fn count(
    input: &Value,
    key: &str,
    default: usize,
    ceiling: usize,
    zero_allowed: bool,
) -> Result<usize> {
    let value = input
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .with_context(|| format!("{key} must be a non-negative integer"))
        })
        .transpose()?
        .unwrap_or(default as u64);
    anyhow::ensure!(zero_allowed || value > 0, "{key} must be positive");
    anyhow::ensure!(value <= ceiling as u64, "{key} must not exceed {ceiling}");
    Ok(value as usize)
}
