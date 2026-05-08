use super::prelude::*;
use super::*;

pub(crate) fn parse_bridge_stdout(
    stdout: &[u8],
) -> std::result::Result<serde_json::Value, serde_json::Error> {
    serde_json::from_slice(stdout)
}

pub(crate) fn bridge_ping_error(parsed: &serde_json::Value) -> Option<String> {
    if parsed.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        return None;
    }
    Some(
        parsed
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(no error message)")
            .to_string(),
    )
}

pub(crate) fn bridge_ping_summary(parsed: &serde_json::Value) -> String {
    let auth_mode = parsed
        .get("auth_mode")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let latency_ms = parsed
        .get("latency_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let in_tok = parsed
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let out_tok = parsed
        .get("output_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let cost = parsed
        .get("cost_usd")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    format!(
        "round-trip ok via {auth_mode} ({latency_ms}ms, {in_tok}/{out_tok} tokens, ~${cost:.5})"
    )
}

pub(crate) fn format_unix_ms(ms: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let when = UNIX_EPOCH + Duration::from_millis(ms);
    let now = SystemTime::now();
    let delta = match when.duration_since(now) {
        Ok(d) => format!("in {}s", d.as_secs()),
        Err(e) => format!("{}s ago", e.duration().as_secs()),
    };
    format!("{ms}ms unix; {delta}")
}

pub(crate) fn modules_command(json: bool) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &registry
                    .modules()
                    .map(|module| module.metadata())
                    .collect::<Vec<_>>()
            )?
        );
    } else {
        for module in registry.modules() {
            println!(
                "{} - {}",
                module.metadata().id,
                module.metadata().description
            );
        }
    }
    Ok(())
}

pub(crate) fn tools_command(json: bool) -> Result<()> {
    let registry = ModuleRegistry::with_v2_builtins();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&registry.tools().collect::<Vec<_>>())?
        );
    } else {
        for tool in registry.tools() {
            println!("{} - {}", tool.name, tool.description);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DoctorStatus {
    Ok,
    Warn,
    Fail,
}
