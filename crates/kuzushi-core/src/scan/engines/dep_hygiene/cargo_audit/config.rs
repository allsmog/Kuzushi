use super::*;
use std::time::Duration;

pub const DEFAULT_TIMEOUT_MS: u64 = 600_000;
pub(crate) const MAX_TIMEOUT_MS: u64 = 86_400_000;
pub const DEFAULT_LOCKFILE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_LOCKFILE_BYTES: usize = 64 * 1024 * 1024;

pub(super) struct AuditConfig {
    pub binary: String,
    pub database: Option<String>,
    pub offline: bool,
    pub allow_stale: bool,
    pub timeout: Duration,
    pub max_lockfile_bytes: usize,
}

impl AuditConfig {
    pub(super) fn from_input(input: &Value) -> Result<Self> {
        let max_bytes = input
            .get("maxLockfileBytes")
            .map(|v| {
                v.as_u64()
                    .context("maxLockfileBytes must be a positive integer")
            })
            .transpose()?
            .unwrap_or(DEFAULT_LOCKFILE_BYTES as u64);
        anyhow::ensure!(
            (1..=MAX_LOCKFILE_BYTES as u64).contains(&max_bytes),
            "maxLockfileBytes must be within 1..={MAX_LOCKFILE_BYTES}"
        );
        Ok(Self {
            binary: text_option(input, "binary")?.unwrap_or_else(|| "cargo-audit".into()),
            database: text_option(input, "advisoryDb")?,
            offline: bool_option(input, "offline")?,
            allow_stale: bool_option(input, "allowStale")?,
            timeout: crate::bounded_subprocess::timeout_from_input(
                input,
                &["timeoutMs", "timeout_ms"],
                DEFAULT_TIMEOUT_MS,
                MAX_TIMEOUT_MS,
                "cargo-audit timeoutMs",
            )?,
            max_lockfile_bytes: max_bytes as usize,
        })
    }
}

fn text_option(input: &Value, name: &str) -> Result<Option<String>> {
    let Some(value) = input.get(name).filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .with_context(|| format!("{name} must be text"))?;
    anyhow::ensure!(!text.trim().is_empty(), "{name} must not be empty");
    Ok(Some(text.into()))
}

fn bool_option(input: &Value, name: &str) -> Result<bool> {
    input
        .get(name)
        .map(|v| {
            v.as_bool()
                .with_context(|| format!("{name} must be true or false"))
        })
        .transpose()
        .map(|v| v.unwrap_or(false))
}
