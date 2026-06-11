use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;

/// Extract a required `path` field from a tool input, returning a PathBuf.
/// Used by the recon and bounty import adapters (M2 §2.2 / §2.3) so each
/// importer surfaces the same "<tool> needs a `path` field" error shape.
pub(crate) fn required_path(input: &Value, key: &str, message: &str) -> Result<PathBuf> {
    let raw = required_string(input, key, message)?;
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
