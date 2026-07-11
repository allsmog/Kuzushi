use super::*;

impl ScanEngine for CargoAuditScanner {
    fn id(&self) -> &'static str {
        "cargo-audit"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        if cancellation.is_cancelled() {
            anyhow::bail!("cargo-audit scan cancelled");
        }

        let lockfile = target.join("Cargo.lock");
        if !lockfile.exists() {
            return Ok(Vec::new());
        }
        ensure_cargo_audit_available()?;

        let mut command = Command::new("cargo");
        command
            .args(["audit", "--json"])
            .arg("--file")
            .arg(&lockfile)
            .current_dir(target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = crate::bounded_subprocess::output(&mut command, "cargo audit")
            .with_context(|| "cargo-audit: failed to invoke `cargo audit`")?;

        // cargo-audit exits non-zero when vulnerabilities are found; that's
        // expected. Malformed or shape-invalid output is never a clean scan.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let findings = parse_cargo_audit_output(&stdout)?;
        if !cargo_audit_status_is_usable(output.status.success(), output.status.code()) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("cargo-audit failed: {}", stderr.trim());
        }
        anyhow::ensure!(
            output.status.success() || !findings.is_empty(),
            "cargo-audit reported vulnerabilities but emitted no usable advisory entries"
        );
        Ok(findings)
    }
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
    let message = format!("{id}: {package_name}@{version} — {title}");

    Ok(
        Finding::new_tool("cargo-audit", id, "Cargo.lock", 1, None, severity, message)
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
}

fn ensure_cargo_audit_available() -> Result<()> {
    if CargoAuditScanner::binary_available() {
        return Ok(());
    }
    anyhow::bail!(
        "cargo-audit: `cargo audit` was not found. Install cargo-audit with `cargo install cargo-audit`, then rerun `kuzushi scan <repo> --tasks cargo-audit` or `kuzushi --target <repo> run sast:scan --input '{{\"tasks\":[\"cargo-audit\"]}}'`."
    )
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
