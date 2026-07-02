use crate::findings::{Finding, Severity, StaticProofState};
use crate::scan::{ScanCancellation, ScanEngine};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Default)]
pub struct GovulncheckScanner;

impl ScanEngine for GovulncheckScanner {
    fn id(&self) -> &'static str {
        "govulncheck"
    }

    fn preflight(&self) -> Result<()> {
        ensure_govulncheck_available()
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        if cancellation.is_cancelled() {
            anyhow::bail!("govulncheck scan cancelled");
        }
        ensure_govulncheck_available()?;
        let output = Command::new("govulncheck")
            .args(["-json", "./..."])
            .current_dir(target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| "govulncheck: failed to invoke `govulncheck -json ./...`")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let findings = parse_govulncheck_json(target, &stdout);
        if !output.status.success() && findings.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("govulncheck failed: {}", stderr.trim());
        }
        Ok(findings)
    }
}

pub fn parse_govulncheck_json(target: &Path, text: &str) -> Vec<Finding> {
    let events = govulncheck_events(text);
    let advisories = govulncheck_advisories(&events);
    events
        .iter()
        .filter_map(|event| event.finding.as_ref())
        .filter_map(|finding| govulncheck_finding(target, finding, &advisories))
        .collect()
}

fn govulncheck_events(text: &str) -> Vec<GovulncheckEvent> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<GovulncheckEvent>(line).ok())
        .collect()
}

fn govulncheck_advisories(
    events: &[GovulncheckEvent],
) -> BTreeMap<String, GovulncheckAdvisory> {
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
) -> Option<Finding> {
    let advisory_id = finding.osv.as_deref()?;
    let advisory = advisories.get(advisory_id);
    let (file_path, line) = finding_location(target, finding);
    Some(
        Finding::new_tool(
            "govulncheck",
            format!("govulncheck/{advisory_id}"),
            file_path,
            line,
            None,
            Severity::High,
            finding_message(advisory_id, advisory, finding),
        )
        .with_static_proof_state(StaticProofState::CodeCited),
    )
}

fn finding_location(target: &Path, finding: &GovulncheckFinding) -> (String, u32) {
    finding
        .trace
        .iter()
        .flatten()
        .filter_map(|frame| frame.position.as_ref())
        .find_map(|position| position.filename.as_deref().map(|file| (file, position.line)))
        .map(|(file, line)| (relative_display(target, Path::new(file)), line.unwrap_or(1).max(1)))
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
    if let Some(version) = finding.fixed_version.as_deref().filter(|value| !value.is_empty()) {
        message.push_str(&format!("; fixed in {version}"));
    }
    if let Some(frame) = first_trace_label(finding) {
        message.push_str(&format!("; reachable via {frame}"));
    }
    message
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

fn ensure_govulncheck_available() -> Result<()> {
    if crate::process_lookup::executable_on_path("govulncheck").is_some() {
        return Ok(());
    }
    anyhow::bail!(
        "govulncheck: binary not found. Install it with `go install golang.org/x/vuln/cmd/govulncheck@latest`, then rerun the focused component scan."
    )
}

#[derive(Debug, Clone, Deserialize)]
struct GovulncheckEvent {
    #[serde(default)]
    osv: Option<GovulncheckAdvisory>,
    #[serde(default)]
    finding: Option<GovulncheckFinding>,
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
mod tests {
    use super::*;

    #[test]
    fn parses_reachable_vulnerability_events() {
        let json = r#"{"osv":{"id":"GO-2024-0001","summary":"path traversal in proxy"}}"#.to_string()
            + "\n"
            + r#"{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.2.3","trace":[{"function":"main.run","position":{"filename":"cmd/proxy/main.go","line":42}}]}}"#;

        let findings = parse_govulncheck_json(Path::new("/repo"), &json);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "govulncheck");
        assert_eq!(findings[0].rule_id, "govulncheck/GO-2024-0001");
        assert_eq!(findings[0].file_path, "cmd/proxy/main.go");
        assert_eq!(findings[0].start_line, 42);
        assert!(findings[0].message.contains("fixed in v1.2.3"));
    }
}
