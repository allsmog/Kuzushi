use super::*;

pub(super) fn output(pass: &pass::GroundingPass) -> String {
    let counts = pass
        .counts
        .iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut lines = vec![
        format!(
            "findings:ground checked {} citation(s) from {} selected: {counts}",
            pass.checked, pass.selected
        ),
        "Citation inspection only. Finding verdicts remain unchanged.".into(),
    ];
    lines.extend(pass.inspections.iter().take(20).map(inspection_line));
    if pass.inspections.len() > 20 {
        lines.push(
            "Preview shows 20 citations; complete checks are retained in the run result.".into(),
        );
    }
    lines.extend(warnings(pass));
    lines.join("\n")
}

fn inspection_line(value: &Value) -> String {
    let reference = value["fingerprint"]
        .as_str()
        .unwrap_or("unknown")
        .chars()
        .take(12)
        .collect::<String>();
    format!(
        "{reference} · {}:{} · {}",
        value["source"]["file"].as_str().unwrap_or("no file anchor"),
        value["line"],
        value["status"]["status"].as_str().unwrap_or("unavailable")
    )
}

pub(super) fn warnings(pass: &pass::GroundingPass) -> Vec<String> {
    let mut warnings = Vec::new();
    if pass.has_more {
        warnings.push("Additional ledger candidates were not inspected. Request a specific larger limit to check them.".into());
    }
    if pass.counts.get("unavailable").copied().unwrap_or(0) > 0 {
        warnings.push("Some citation sources were unavailable or exceeded the read limits. They are not classified as missing.".into());
    }
    if let Some(reason) = &pass.stopped {
        warnings.push(reason.clone());
    }
    warnings
}
