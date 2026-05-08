use super::*;

pub(super) fn append_secret_hits(
    root: &Path,
    rel_path: &str,
    text: &str,
    max_findings: usize,
    findings: &mut Vec<SecretScanFinding>,
) {
    for hit in detect_secrets_in_text(text) {
        findings.push(secret_finding_from_hit(root, rel_path, text, &hit));
        if findings.len() >= max_findings {
            break;
        }
    }
}

fn secret_finding_from_hit(
    root: &Path,
    rel_path: &str,
    text: &str,
    hit: &SecretHit,
) -> SecretScanFinding {
    let location = locate_match(text, hit.index);
    let fingerprint = fingerprint_for(root, hit.detector.id, rel_path, location.line, &hit.matched);
    let redacted = redact_secret(&hit.captured_secret);
    let evidence_line = location
        .line_text
        .replacen(&hit.captured_secret, &redacted, 1)
        .trim()
        .to_string();
    let severity = hit.detector.severity;

    SecretScanFinding {
        task_id: "secret-scan".to_string(),
        fingerprint,
        rule_id: format!("secret-scan/{}", hit.detector.id),
        file_path: rel_path.to_string(),
        start_line: location.line,
        severity,
        message: format!("{}: {}", hit.detector.name, hit.detector.description),
        evidence: format!("{}:{}: {}", rel_path, location.line, evidence_line),
        scanner_confidence: detector_confidence(hit.detector),
        subcategory: vec!["secret".to_string()],
        likelihood: severity_risk_label(severity),
        impact: severity_risk_label(severity),
        cwe: vec![hit.detector.cwe.to_string()],
        score: severity_score(severity),
    }
}

fn detector_confidence(detector: Detector) -> String {
    if detector.entropy_threshold.is_some() {
        "MEDIUM".to_string()
    } else {
        "HIGH".to_string()
    }
}

fn severity_risk_label(severity: SecretSeverity) -> String {
    if severity == SecretSeverity::Error {
        "HIGH".to_string()
    } else {
        "MEDIUM".to_string()
    }
}

fn severity_score(severity: SecretSeverity) -> u32 {
    match severity {
        SecretSeverity::Error => 30,
        SecretSeverity::Warning => 20,
        SecretSeverity::Info => 10,
    }
}
