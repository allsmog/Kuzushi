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

        let output = Command::new("cargo")
            .args(["audit", "--json"])
            .arg("--file")
            .arg(&lockfile)
            .current_dir(target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| "cargo-audit: failed to invoke `cargo audit`")?;

        // cargo-audit exits non-zero when vulnerabilities are found; that's
        // expected. Any output that fails to parse is treated as no findings.
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_cargo_audit_output(&stdout))
    }
}

pub fn parse_cargo_audit_output(json: &str) -> Vec<Finding> {
    let Some(value) = parse_cargo_audit_json(json) else {
        return Vec::new();
    };
    cargo_audit_entries(&value).map_or_else(Vec::new, cargo_audit_findings)
}

fn parse_cargo_audit_json(json: &str) -> Option<Value> {
    serde_json::from_str(json).ok()
}

fn cargo_audit_entries(value: &Value) -> Option<&[Value]> {
    value
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn cargo_audit_findings(entries: &[Value]) -> Vec<Finding> {
    entries.iter().filter_map(cargo_audit_finding).collect()
}

fn cargo_audit_finding(entry: &Value) -> Option<Finding> {
    let advisory = entry.get("advisory")?;
    let id = cargo_audit_advisory_field(advisory, "id", "RUSTSEC-UNKNOWN").to_string();
    let title = cargo_audit_advisory_field(advisory, "title", "(no title)");
    let package = cargo_audit_package_field(entry, "name");
    let version = cargo_audit_package_field(entry, "version");
    let severity = severity_from_cvss(advisory.get("cvss").and_then(Value::as_str));
    let message = format!("{id}: {package}@{version} — {title}");

    Some(Finding::new_tool(
        "cargo-audit",
        id,
        "Cargo.lock",
        1,
        None,
        severity,
        message,
    ))
}

fn cargo_audit_advisory_field<'a>(
    advisory: &'a Value,
    field: &str,
    fallback: &'static str,
) -> &'a str {
    advisory
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or(fallback)
}

fn cargo_audit_package_field<'a>(entry: &'a Value, field: &str) -> &'a str {
    entry
        .get("package")
        .and_then(|package| package.get(field))
        .and_then(Value::as_str)
        .unwrap_or("?")
}

fn ensure_cargo_audit_available() -> Result<()> {
    if CargoAuditScanner::binary_available() {
        return Ok(());
    }
    anyhow::bail!(
        "cargo-audit: `cargo audit` was not found. Install cargo-audit with `cargo install cargo-audit`, then rerun `kuzushi scan --tasks cargo-audit` or `kuzushi run sast:scan --input '{{\"tasks\":[\"cargo-audit\"]}}'`."
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
