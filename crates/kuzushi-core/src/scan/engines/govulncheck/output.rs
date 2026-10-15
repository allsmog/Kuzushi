use super::*;
use crate::findings::{Severity, StaticProofState};
use serde::Deserialize;
use std::collections::BTreeMap;

pub fn parse_govulncheck_json(target: &Path, text: &str) -> Result<Vec<Finding>> {
    let events = govulncheck_events(text)?;
    validate_stream_config(&events)?;
    let advisories = govulncheck_advisories(&events);
    events
        .iter()
        .filter_map(|event| event.finding.as_ref())
        .enumerate()
        .map(|(index, finding)| {
            govulncheck_finding(target, finding, &advisories)
                .with_context(|| format!("govulncheck finding event {} is invalid", index + 1))
        })
        .collect()
}

fn govulncheck_events(text: &str) -> Result<Vec<GovulncheckEvent>> {
    anyhow::ensure!(
        text.len() <= 16 * 1024 * 1024,
        "govulncheck output exceeds the 16 MiB parsing limit"
    );
    serde_json::Deserializer::from_str(text)
        .into_iter::<GovulncheckEvent>()
        .enumerate()
        .map(|(index, event)| {
            anyhow::ensure!(index < 100_000, "govulncheck output exceeds 100000 events");
            let event = event.with_context(|| {
                format!("govulncheck returned malformed JSON event {}", index + 1)
            })?;
            validate_event(&event)?;
            Ok(event)
        })
        .collect()
}

fn validate_stream_config(events: &[GovulncheckEvent]) -> Result<()> {
    let config = events
        .first()
        .and_then(|event| event.config.as_ref())
        .context(
            "govulncheck output must begin with a protocol config; no clean result is established",
        )?;
    anyhow::ensure!(
        config.protocol_version == "v1.0.0",
        "unsupported govulncheck protocol version {:?}",
        config.protocol_version
    );
    anyhow::ensure!(
        !events.iter().skip(1).any(|event| event.config.is_some()),
        "govulncheck output contains repeated protocol config"
    );
    Ok(())
}

fn validate_event(event: &GovulncheckEvent) -> Result<()> {
    let fields = [
        event.config.is_some(),
        event.progress.is_some(),
        event.sbom.is_some(),
        event.osv.is_some(),
        event.finding.is_some(),
    ];
    anyhow::ensure!(
        fields.into_iter().filter(|present| *present).count() == 1,
        "govulncheck event must contain exactly one recognized message"
    );
    Ok(())
}

fn govulncheck_advisories(events: &[GovulncheckEvent]) -> BTreeMap<String, GovulncheckAdvisory> {
    events
        .iter()
        .filter_map(|event| event.osv.clone())
        .map(|advisory| (advisory.id.clone(), advisory))
        .collect()
}

fn govulncheck_finding(
    target: &Path,
    finding: &GovulncheckFinding,
    advisories: &BTreeMap<String, GovulncheckAdvisory>,
) -> Result<Finding> {
    let advisory_id = finding
        .osv
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .context("missing non-empty osv id")?;
    let advisory = advisories.get(advisory_id);
    let (file_path, line) = finding_location(target, finding);
    Ok(Finding::new_tool(
        "govulncheck",
        format!("govulncheck/{advisory_id}"),
        file_path,
        line,
        None,
        Severity::High,
        finding_message(advisory_id, advisory, finding),
    )
    .with_static_proof_state(StaticProofState::SignalOnly))
}

fn valid_position(frame: &GovulncheckFrame) -> Option<&GovulncheckPosition> {
    let position = frame.position.as_ref()?;
    let file = position.filename.as_deref()?.trim();
    (!file.is_empty() && position.line.is_some_and(|line| line > 0)).then_some(position)
}

fn finding_location(target: &Path, finding: &GovulncheckFinding) -> (String, u32) {
    finding
        .trace
        .iter()
        .flatten()
        .filter_map(valid_position)
        .find_map(|position| {
            position
                .filename
                .as_deref()
                .map(|file| (file, position.line))
        })
        .map(|(file, line)| {
            (
                relative_display(target, Path::new(file)),
                line.unwrap_or(1).max(1),
            )
        })
        .unwrap_or_else(|| ("go.mod".to_string(), 1))
}

fn relative_display(root: &Path, path: &Path) -> String {
    if path.is_absolute() {
        return path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
    }
    path.to_string_lossy().replace('\\', "/")
}

fn finding_message(
    advisory_id: &str,
    advisory: Option<&GovulncheckAdvisory>,
    finding: &GovulncheckFinding,
) -> String {
    let summary = advisory
        .and_then(|advisory| advisory.summary.as_deref())
        .unwrap_or(advisory_id);
    let mut message = format!("{advisory_id}: {summary}");
    if let Some(version) = finding
        .fixed_version
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        message.push_str(&format!("; fixed in {version}"));
    }
    if let Some(frame) = first_trace_label(finding) {
        message.push_str(&format!("; {} {frame}", finding_trace_label(finding)));
    }
    message
}

fn finding_trace_label(finding: &GovulncheckFinding) -> &'static str {
    let Some(frame) = finding.trace.as_ref().and_then(|trace| trace.first()) else {
        return "scanner signal; reachability unknown";
    };
    if frame
        .function
        .as_deref()
        .is_some_and(|name| !name.trim().is_empty())
    {
        return "scanner-reported symbol";
    }
    if frame
        .package
        .as_deref()
        .is_some_and(|name| !name.trim().is_empty())
    {
        return "imported package; call reachability unassessed";
    }
    "required module; call reachability unassessed"
}

fn first_trace_label(finding: &GovulncheckFinding) -> Option<String> {
    finding.trace.iter().flatten().find_map(|frame| {
        frame
            .function
            .as_deref()
            .or(frame.package.as_deref())
            .or(frame.module.as_deref())
            .map(str::to_string)
    })
}

#[derive(Debug, Clone, Deserialize)]
struct GovulncheckEvent {
    #[serde(default)]
    config: Option<GovulncheckConfig>,
    #[serde(default)]
    progress: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, rename = "SBOM")]
    sbom: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    osv: Option<GovulncheckAdvisory>,
    #[serde(default)]
    finding: Option<GovulncheckFinding>,
}

#[derive(Debug, Clone, Deserialize)]
struct GovulncheckConfig {
    protocol_version: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GovulncheckAdvisory {
    id: String,
    #[serde(default)]
    summary: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GovulncheckFinding {
    #[serde(default)]
    osv: Option<String>,
    #[serde(default, alias = "fixedVersion")]
    fixed_version: Option<String>,
    #[serde(default)]
    trace: Option<Vec<GovulncheckFrame>>,
}

#[derive(Debug, Clone, Deserialize)]
struct GovulncheckFrame {
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    function: Option<String>,
    #[serde(default)]
    position: Option<GovulncheckPosition>,
}

#[derive(Debug, Clone, Deserialize)]
struct GovulncheckPosition {
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    line: Option<u32>,
}

#[cfg(test)]
mod tests;
