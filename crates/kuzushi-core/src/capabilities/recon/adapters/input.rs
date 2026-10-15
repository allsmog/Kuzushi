use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;

/// Extract a required `path` field from a tool input, returning a PathBuf.
/// Used by the recon and bounty import adapters (M2 §2.2 / §2.3) so each
/// importer surfaces the same "<tool> needs a `path` field" error shape.
pub(crate) fn required_path(input: &Value, key: &str, message: &str) -> Result<PathBuf> {
    let raw = input
        .get(key)
        .and_then(Value::as_str)
        .filter(|raw| !raw.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!(message.to_string()))?;
    Ok(PathBuf::from(raw))
}

pub(crate) fn required_string(input: &Value, key: &str, message: &str) -> Result<String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!(message.to_string()))
}

pub(crate) fn optional_string(input: &Value, keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::String(value) => {
                    Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty()))
                }
                Value::Null => Ok(None),
                _ => anyhow::bail!("{key} must be a string"),
            };
        }
    }
    Ok(None)
}

pub(crate) fn optional_u64(input: &Value, keys: &[&str]) -> Result<Option<u64>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::Number(number) => number
                    .as_u64()
                    .map(Some)
                    .with_context(|| format!("{key} must be a non-negative integer")),
                Value::String(value) => value
                    .parse::<u64>()
                    .map(Some)
                    .with_context(|| format!("{key} must be a non-negative integer")),
                Value::Null => Ok(None),
                _ => anyhow::bail!("{key} must be a non-negative integer"),
            };
        }
    }
    Ok(None)
}

pub(crate) fn recon_timeout(input: &Value, default: u64) -> Result<u64> {
    let seconds = optional_u64(input, &["timeoutSeconds", "timeout_seconds"])?.unwrap_or(default);
    anyhow::ensure!(
        (1..=300).contains(&seconds),
        "Recon timeoutSeconds must be from 1 to 300"
    );
    Ok(seconds)
}

pub(crate) fn checked_recon_domain(domain: String) -> Result<String> {
    anyhow::ensure!(
        !domain.is_empty() && domain.len() <= 253,
        "Recon domain must contain 1 to 253 bytes"
    );
    let normalized = domain.strip_suffix('.').unwrap_or(&domain);
    for label in normalized.split('.') {
        anyhow::ensure!(
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-'),
            "Recon domain contains an invalid label"
        );
        anyhow::ensure!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "Recon domain must use ASCII DNS labels; supply international names in punycode"
        );
    }
    Ok(normalized.to_ascii_lowercase())
}

pub(crate) fn checked_recon_ports(ports: String) -> Result<String> {
    if matches!(ports.as_str(), "top100" | "top1000") {
        return Ok(ports);
    }
    anyhow::ensure!(
        !ports.is_empty() && ports.len() <= 4096,
        "Recon ports must be a bounded numeric list or top100/top1000"
    );
    for item in ports.split(',') {
        check_recon_port_item(item)?;
    }
    Ok(ports)
}

fn check_recon_port_item(item: &str) -> Result<()> {
    let (first, last) = item
        .split_once('-')
        .map_or((item, item), |(first, last)| (first, last));
    let start = first
        .parse::<u16>()
        .context("Recon port must be a number from 1 to 65535")?;
    let end = last
        .parse::<u16>()
        .context("Recon port range end must be a number from 1 to 65535")?;
    anyhow::ensure!(
        start > 0 && end >= start,
        "Recon port range must be ascending and exclude zero"
    );
    Ok(())
}
