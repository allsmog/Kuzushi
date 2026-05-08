use super::prelude::*;
use super::*;

pub(crate) fn run_next_step_bridge(
    command: &[String],
    request: &NextStepBridgeRequest,
) -> Result<NextStepBridgeResponse> {
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("could not start next-step bridge {}", command[0]))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("could not open next-step bridge stdin")?;
        let body = serde_json::to_vec(request).context("could not encode next-step request")?;
        stdin.write_all(&body)?;
    }
    let output = child
        .wait_with_output()
        .context("could not read next-step bridge output")?;
    if !output.status.success() {
        if !output.stdout.is_empty() {
            if let Ok(parsed) = serde_json::from_slice::<NextStepBridgeResponse>(&output.stdout) {
                return Ok(parsed);
            }
        }
        anyhow::bail!(
            "next-step bridge exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "could not parse next-step bridge JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

pub(crate) const TRIAGE_SYSTEM_PROMPT: &str = r#"You are Kuzushi's security triage agent.
Return only JSON matching:
{"verdict":"true_positive|false_positive|needs_review","confidence":0.0-1.0,"rationale":"short evidence-based reason"}."#;

pub(crate) fn triage_prompt(
    finding: &kuzushi_core::Finding,
    template: Option<&str>,
) -> Result<String> {
    let json = serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let prefix = template
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(
        "Triage this SAST finding. Be conservative; use needs_review when evidence is incomplete.",
    );
    Ok(format!("{prefix}\n\nFinding JSON:\n{json}"))
}

pub(crate) fn run_bridge(command: &[String], request: &BridgeRequest) -> Result<BridgeResponse> {
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Could not start pi-agent-core bridge {}", command[0]))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("Could not open pi-agent-core bridge stdin")?;
        let body = serde_json::to_vec(request).context("Could not encode bridge request")?;
        stdin.write_all(&body)?;
    }

    let output = child
        .wait_with_output()
        .context("Could not read pi-agent-core bridge output")?;
    if !output.status.success() {
        if !output.stdout.is_empty() {
            if let Ok(response) = serde_json::from_slice::<BridgeResponse>(&output.stdout) {
                return Ok(response);
            }
        }
        anyhow::bail!(
            "pi-agent-core bridge exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice::<BridgeResponse>(&output.stdout).with_context(|| {
        format!(
            "Could not parse bridge JSON: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

pub(crate) fn default_bridge_command(source_root: &Path) -> Vec<String> {
    let source_bridge = source_root.join("scripts").join("pi-agent-core-bridge.mjs");
    if source_bridge.exists() {
        return vec!["node".to_string(), source_bridge.display().to_string()];
    }

    vec![
        "node".to_string(),
        "scripts/pi-agent-core-bridge.mjs".to_string(),
    ]
}

pub(crate) fn clamp_outcome(mut outcome: TriageOutcome) -> TriageOutcome {
    outcome.confidence = outcome.confidence.clamp(0.0, 1.0);
    outcome
}
