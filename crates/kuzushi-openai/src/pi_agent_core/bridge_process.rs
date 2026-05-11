use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use super::bridge_payloads::{
    BridgeRequest, BridgeResponse, NextStepBridgeRequest, NextStepBridgeResponse,
};

pub(crate) fn run_next_step_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
) -> Result<NextStepBridgeResponse> {
    run_json_bridge(command, request, "next-step bridge")
}

pub(crate) fn run_bridge(command: &[String], request: &BridgeRequest) -> Result<BridgeResponse> {
    run_json_bridge(command, request, "pi-agent-core bridge")
}

fn run_json_bridge<T, R>(command: &[String], request: &T, label: &str) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("could not start {label} {}", command[0]))?;

    write_bridge_request(&mut child, request, label)?;
    let output = child
        .wait_with_output()
        .with_context(|| format!("could not read {label} output"))?;
    if !output.status.success() {
        if !output.stdout.is_empty() {
            if let Ok(response) = serde_json::from_slice::<R>(&output.stdout) {
                return Ok(response);
            }
        }
        anyhow::bail!(
            "{label} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice::<R>(&output.stdout).with_context(|| {
        format!(
            "could not parse {label} JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn write_bridge_request<T: Serialize>(
    child: &mut std::process::Child,
    request: &T,
    label: &str,
) -> Result<()> {
    let stdin = child
        .stdin
        .as_mut()
        .with_context(|| format!("could not open {label} stdin"))?;
    let body =
        serde_json::to_vec(request).with_context(|| format!("could not encode {label} request"))?;
    stdin.write_all(&body)?;
    Ok(())
}

pub(crate) fn default_bridge_command(source_root: &Path) -> Vec<String> {
    if let Some(command) = bridge_command_at(source_root) {
        return command;
    }
    if let Some(command) = bridge_command_near_executable() {
        return command;
    }

    vec![
        "node".to_string(),
        "scripts/pi-agent-core-bridge.mjs".to_string(),
    ]
}

fn bridge_command_at(source_root: &Path) -> Option<Vec<String>> {
    let bridge = source_root.join("scripts").join("pi-agent-core-bridge.mjs");
    bridge
        .exists()
        .then(|| vec!["node".to_string(), bridge.display().to_string()])
}

fn bridge_command_near_executable() -> Option<Vec<String>> {
    let exe = std::env::current_exe().ok()?;
    let mut cursor = exe.parent();
    while let Some(dir) = cursor {
        if let Some(command) = bridge_command_at(dir) {
            return Some(command);
        }
        cursor = dir.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bridge_command_resolves_from_source_root_when_present() {
        let temp = tempfile::tempdir().unwrap();
        let scripts = temp.path().join("scripts");
        std::fs::create_dir(&scripts).unwrap();
        let bridge = scripts.join("pi-agent-core-bridge.mjs");
        std::fs::write(&bridge, "// stub\n").unwrap();

        let command = default_bridge_command(temp.path());

        assert_eq!(command[0], "node");
        assert_eq!(command[1], bridge.display().to_string());
    }
}
