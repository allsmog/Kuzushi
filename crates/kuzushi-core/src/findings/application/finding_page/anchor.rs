//! Navigation continuity does not bind a review decision to another generation.
use super::{finding_page_anchor, Finding};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContinuityAnchor {
    version: u8,
    exact: String,
    identity: String,
    fingerprint: String,
}

pub fn finding_page_continuity_anchor(finding: &Finding) -> String {
    let exact = finding_page_anchor(finding);
    match finding.identity_id.as_deref().filter(|id| !id.is_empty()) {
        Some(identity) => format!(
            "continuity:{}",
            serde_json::json!({
                "version":1,"exact":exact,"identity":identity,"fingerprint":finding.fingerprint,
            })
        ),
        None => exact,
    }
}

pub fn finding_page_anchor_index(findings: &[Finding], anchor: &str) -> Option<usize> {
    if let Some(index) = exact_index(findings, anchor) {
        return Some(index);
    }
    let continuity: ContinuityAnchor =
        serde_json::from_str(anchor.strip_prefix("continuity:")?).ok()?;
    if continuity.version != 1 {
        return None;
    }
    exact_index(findings, &continuity.exact)
        .or_else(|| unique_identity_index(findings, &continuity))
}

fn exact_index(findings: &[Finding], anchor: &str) -> Option<usize> {
    findings
        .iter()
        .position(|finding| finding_page_anchor(finding) == anchor)
}

fn unique_identity_index(findings: &[Finding], anchor: &ContinuityAnchor) -> Option<usize> {
    if anchor.identity.is_empty() {
        return None;
    }
    let mut matches = findings.iter().enumerate().filter(|(_, finding)| {
        finding.identity_id.as_deref() == Some(anchor.identity.as_str())
            && finding.fingerprint == anchor.fingerprint
    });
    let (index, _) = matches.next()?;
    matches.next().is_none().then_some(index)
}

#[cfg(test)]
mod tests;
