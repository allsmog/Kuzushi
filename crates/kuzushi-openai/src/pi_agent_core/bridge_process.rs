use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
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

    // The caller's cwd (`source_root`) is the natural lookup spot when
    // kuzushi is invoked from inside the Kuzushi repo. When kuzushi is
    // invoked against an external target the cwd is the *target*, not
    // the Kuzushi tree, so fall back to the script that lives next to
    // the kuzushi executable.
    if let Some(exe_bridge) = bridge_next_to_executable() {
        return vec!["node".to_string(), exe_bridge.display().to_string()];
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

fn bridge_next_to_executable() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    bridge_near_executable(&exe)
}

fn bridge_near_executable(exe: &Path) -> Option<PathBuf> {
    // Walk up to 6 ancestors so we cover the layouts kuzushi ships in:
    //   target/release/kuzushi          -> ../../scripts/...   (2 hops)
    //   target/debug/kuzushi            -> ../../scripts/...   (2 hops)
    //   native/<plat>-<arch>/kuzushi    -> ../../scripts/...   (2 hops)
    //   bin/kuzushi (npm package)       -> ../scripts/...      (1 hop)
    //   share/kuzushi/bin/kuzushi       -> ../../scripts/...   (2 hops)
    // 6 keeps the search bounded and well clear of `/`.
    let mut dir = exe.parent();
    for _ in 0..6 {
        let Some(parent) = dir else { return None };
        let candidate = parent.join("scripts").join("pi-agent-core-bridge.mjs");
        if candidate.exists() {
            return Some(candidate);
        }
        dir = parent.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{bridge_near_executable, default_bridge_command};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn default_bridge_command_finds_bridge_in_source_root() {
        let tmp = tempdir().unwrap();
        let scripts = tmp.path().join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        let bridge = scripts.join("pi-agent-core-bridge.mjs");
        fs::write(&bridge, "/* test */").unwrap();

        let cmd = default_bridge_command(tmp.path());
        assert_eq!(cmd[0], "node");
        assert_eq!(cmd[1], bridge.display().to_string());
    }

    #[test]
    fn bridge_near_executable_walks_up_to_find_scripts_dir() {
        let tmp = tempdir().unwrap();
        let release = tmp.path().join("target").join("release");
        fs::create_dir_all(&release).unwrap();
        let exe = release.join("kuzushi");
        fs::write(&exe, b"#!/bin/sh\n").unwrap();
        let scripts = tmp.path().join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        let bridge = scripts.join("pi-agent-core-bridge.mjs");
        fs::write(&bridge, "/* test */").unwrap();

        let resolved = bridge_near_executable(&exe).expect("walks up to <root>/scripts");
        assert_eq!(resolved, bridge);
    }

    #[test]
    fn bridge_near_executable_returns_none_when_absent() {
        let tmp = tempdir().unwrap();
        let exe = tmp.path().join("kuzushi");
        fs::write(&exe, b"#!/bin/sh\n").unwrap();
        assert!(bridge_near_executable(&exe).is_none());
    }
}
