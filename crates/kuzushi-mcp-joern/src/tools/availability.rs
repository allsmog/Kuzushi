use anyhow::Result;
use kuzushi_mcp_common::doctor::which;
use serde_json::Value;

pub(crate) fn ensure_joern_available() -> Result<()> {
    if which("joern-parse").is_none() && which("joern").is_none() {
        anyhow::bail!(
            "BackendUnavailable: joern not on PATH. Install via https://docs.joern.io/installation."
        );
    }
    Ok(())
}

pub(crate) fn require_str<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

pub(crate) fn parse_raw_json_or_string(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or(Value::String(raw))
}
