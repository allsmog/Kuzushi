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
        if !Self::binary_available() {
            return Ok(Vec::new());
        }

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
    let value: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();
    let list = value
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(Value::as_array);
    let Some(list) = list else {
        return findings;
    };

    for entry in list {
        let advisory = match entry.get("advisory") {
            Some(a) => a,
            None => continue,
        };
        let id = advisory
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("RUSTSEC-UNKNOWN")
            .to_string();
        let title = advisory
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("(no title)")
            .to_string();
        let package = entry
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("?");
        let version = entry
            .get("package")
            .and_then(|p| p.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("?");
        let cvss = advisory.get("cvss").and_then(Value::as_str);
        let severity = severity_from_cvss(cvss);
        let message = format!("{id}: {package}@{version} — {title}");

        findings.push(Finding::new_tool(
            "cargo-audit",
            id,
            "Cargo.lock",
            1,
            None,
            severity,
            message,
        ));
    }

    findings
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
