use super::auth_ping::AuthPingLog;
use anyhow::{Context, Result};

pub(crate) fn auth_ping_bridge_command(config: &kuzushi_core::V2Config) -> Vec<String> {
    config
        .runtime
        .agent_bridge_command
        .clone()
        .unwrap_or_else(|| {
            vec![
                "node".to_string(),
                "scripts/pi-agent-core-bridge.mjs".to_string(),
            ]
        })
}

pub(crate) fn auth_ping_envelope(
    config: &kuzushi_core::V2Config,
    model: String,
) -> serde_json::Value {
    serde_json::json!({
        "type": "ping",
        "model": model,
        "apiKeyEnv": config.runtime.api_key_env,
        "apiKey": std::env::var(&config.runtime.api_key_env).ok(),
    })
}

pub(crate) fn run_auth_ping_bridge(
    bridge_command: &[String],
    envelope: &serde_json::Value,
    log: &mut AuthPingLog,
) -> Result<serde_json::Value> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(&bridge_command[0])
        .args(&bridge_command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("could not start bridge {}", bridge_command[0]))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("could not open bridge stdin")?;
        stdin.write_all(serde_json::to_vec(&envelope)?.as_slice())?;
    }
    let output = child
        .wait_with_output()
        .context("could not read bridge output")?;
    match parse_bridge_stdout(&output.stdout) {
        Ok(value) => Ok(value),
        Err(e) => {
            log.record(false, format!("bridge returned non-JSON output: {e}"));
            eprintln!("    stdout: {}", String::from_utf8_lossy(&output.stdout));
            eprintln!("    stderr: {}", String::from_utf8_lossy(&output.stderr));
            std::process::exit(1);
        }
    }
}

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
