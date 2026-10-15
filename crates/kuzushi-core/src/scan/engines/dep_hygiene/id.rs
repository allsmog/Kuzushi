use super::*;

impl ScanEngine for CargoAuditScanner {
    fn id(&self) -> &'static str {
        "cargo-audit"
    }

    fn rebind_scoped_finding(&self, finding: &mut Finding, file_path: String) {
        super::cargo_audit::rebind_audit_finding(finding, file_path);
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let Some(_) = cargo_audit_lockfile(target, cancellation)? else {
            return Ok(Vec::new());
        };
        super::ConfiguredCargoAuditScanner::from_tool_input(&json!({}))?.scan(target, cancellation)
    }
}

fn cargo_audit_lockfile(target: &Path, cancellation: &ScanCancellation) -> Result<Option<PathBuf>> {
    if cancellation.is_cancelled() {
        anyhow::bail!("cargo-audit scan cancelled");
    }
    let lockfile = target.join("Cargo.lock");
    Ok(lockfile.exists().then_some(lockfile))
}

pub(super) fn cargo_audit_findings_from_output(
    output: std::process::Output,
) -> Result<Vec<Finding>> {
    // cargo-audit exits non-zero when vulnerabilities are found; that's
    // expected. Malformed or shape-invalid output is never a clean scan.
    let stderr = String::from_utf8_lossy(&output.stderr);
    anyhow::ensure!(
        cargo_audit_status_is_usable(output.status.success(), output.status.code()),
        "cargo-audit failed: {}",
        stderr.trim()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings = parse_cargo_audit_output(&stdout)
        .map_err(|error| anyhow::anyhow!("{error}; cargo-audit stderr: {}", stderr.trim()))?;
    anyhow::ensure!(
        output.status.success() || !findings.is_empty(),
        "cargo-audit reported vulnerabilities but emitted no usable advisory entries"
    );
    Ok(findings)
}

pub fn parse_cargo_audit_output(json: &str) -> Result<Vec<Finding>> {
    let value: Value = serde_json::from_str(json).context("cargo-audit returned malformed JSON")?;
    if let Some(entries) = cargo_audit_entries(&value) {
        return cargo_audit_findings(entries);
    }
    if value
        .pointer("/vulnerabilities/found")
        .and_then(Value::as_bool)
        == Some(false)
    {
        return Ok(Vec::new());
    }
    anyhow::bail!("cargo-audit JSON is missing vulnerabilities.list")
}

fn cargo_audit_entries(value: &Value) -> Option<&[Value]> {
    value
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn cargo_audit_findings(entries: &[Value]) -> Result<Vec<Finding>> {
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            cargo_audit_finding(entry)
                .with_context(|| format!("cargo-audit advisory entry {} is invalid", index + 1))
        })
        .collect()
}

fn cargo_audit_finding(entry: &Value) -> Result<Finding> {
    let advisory = entry.get("advisory").context("missing advisory object")?;
    let id = required_cargo_audit_field(advisory, "id")?.to_string();
    let title = required_cargo_audit_field(advisory, "title")?;
    let package = entry.get("package").context("missing package object")?;
    let package_name = required_cargo_audit_field(package, "name")?;
    let version = required_cargo_audit_field(package, "version")?;
    let severity = severity_from_cvss(advisory.get("cvss").and_then(Value::as_str));
    let message = format!("{id}: {package_name}@{version} · {title}");

    // One advisory can affect several locked versions; the locked package
    // names which instance of the advisory this finding is.
    let locator = format!("Cargo.lock#{package_name}@{version}");
    Ok(
        Finding::new_tool("cargo-audit", id, "Cargo.lock", 1, None, severity, message)
            .with_structural_locator(locator)
            .with_static_proof_state(StaticProofState::SignalOnly),
    )
}

fn required_cargo_audit_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("missing non-empty {field}"))
}

fn cargo_audit_status_is_usable(success: bool, code: Option<i32>) -> bool {
    success || code == Some(1)
}

#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn only_the_documented_vulnerability_exit_is_accepted() {
        assert!(cargo_audit_status_is_usable(true, Some(0)));
        assert!(cargo_audit_status_is_usable(false, Some(1)));
        assert!(!cargo_audit_status_is_usable(false, Some(2)));
        assert!(!cargo_audit_status_is_usable(false, None));
    }

    #[test]
    fn cancelled_scan_stops_before_cargo_audit_preflight() {
        let cancellation = ScanCancellation::default();
        cancellation.cancel();

        let error = cargo_audit_lockfile(Path::new("."), &cancellation).unwrap_err();

        assert!(error.to_string().contains("cancelled"));
    }
}

pub(crate) fn severity_from_cvss(cvss: Option<&str>) -> Severity {
    let Some(s) = cvss else {
        return Severity::Medium;
    };
    let trimmed = s.trim();
    if let Some(severity) = numeric_cvss_severity(trimmed) {
        return severity;
    }
    textual_cvss_severity(trimmed)
}

pub(crate) fn numeric_cvss_severity(value: &str) -> Option<Severity> {
    let score = value.parse::<f64>().ok()?;
    Some(match score {
        x if x >= 9.0 => Severity::Critical,
        x if x >= 7.0 => Severity::High,
        x if x >= 4.0 => Severity::Medium,
        x if x > 0.0 => Severity::Low,
        _ => Severity::Unknown,
    })
}
