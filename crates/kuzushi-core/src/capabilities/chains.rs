//! Deterministic entry→pivot→impact chain fold over confirmed findings.
//!
//! `findings:chains` composes the confirmed findings ledger into candidate
//! attack chains without any model call: findings are classified into
//! entry / pivot / impact roles from their recorded text, grouped by code
//! surface, and paired where an entry-class and an impact-class finding
//! share a surface. Candidates are advisory leads for operator review —
//! the model-backed `exploit-chain:scan` remains the source-grounded pass.

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::findings::{Finding, Severity};

const DEFAULT_MAX_CHAINS: usize = 16;
const MAX_PIVOTS_PER_CHAIN: usize = 3;

const ENTRY_MARKERS: &[&str] = &[
    "unauthenticated",
    "pre-auth",
    "network",
    "remote",
    "request",
    "thrift",
    "grpc",
    "rpc",
    "rest",
    "endpoint",
    "server-controlled",
    "server-supplied",
    "guest",
    "peer",
    "client-supplied",
    "attacker-controlled",
    "caller-controlled",
    "untrusted",
    "listener",
    "socket",
    "parses",
    "parser",
    "deserial",
];

const PIVOT_MARKERS: &[&str] = &[
    "credential",
    "password",
    "secret",
    "token",
    "private key",
    "cert",
    "leak",
    "disclosure",
    "traversal",
    "bypass",
    "ssrf",
    "mitm",
    "hostname verification",
    "symlink",
    "redirect",
    "idor",
];

const IMPACT_MARKERS: &[&str] = &[
    "injection",
    "overflow",
    "out-of-bounds",
    "oob",
    "heap write",
    "arbitrary write",
    "arbitrary file",
    "rce",
    "exec",
    "command",
    "corruption",
    "format string",
    "use-after-free",
    "double free",
    "privilege",
    "escalation",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainRole {
    Entry,
    Pivot,
    Impact,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainLink {
    pub fingerprint: String,
    pub title: String,
    pub severity: String,
    pub file_path: String,
    pub role: ChainRole,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCandidate {
    pub surface: String,
    pub entry: ChainLink,
    pub pivots: Vec<ChainLink>,
    pub impact: ChainLink,
    pub score: u32,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainReport {
    pub confirmed_count: usize,
    pub surface_count: usize,
    pub chains: Vec<ChainCandidate>,
}

/// Roles a finding can play in a chain, from its recorded text only.
/// A finding may qualify for several roles; an empty result means the
/// finding never participates in a candidate.
pub fn chain_roles(finding: &Finding) -> Vec<ChainRole> {
    let text = format!(
        "{} {} {}",
        finding.title, finding.message, finding.rule_id
    )
    .to_lowercase();
    let mut roles = Vec::new();
    if contains_any(&text, ENTRY_MARKERS) {
        roles.push(ChainRole::Entry);
    }
    if contains_any(&text, PIVOT_MARKERS) {
        roles.push(ChainRole::Pivot);
    }
    if contains_any(&text, IMPACT_MARKERS) {
        roles.push(ChainRole::Impact);
    }
    roles
}

fn contains_any(text: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| text.contains(marker))
}

/// Grouping key: the leading directory components of the finding's path,
/// so findings in one service/module surface fold together.
///
/// JVM-package trees (`.../com/<org>/<area>/<module>/...`) anchor at the
/// package org instead of the raw depth-4 prefix — otherwise every Scala
/// finding under `src/java/core/src` folds into one giant pseudo-surface and
/// unrelated subsystems (SAML auth, network throttle) pair as chains.
pub fn surface_key(file_path: &str) -> String {
    let components: Vec<&str> = file_path
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let dirs = components.len().saturating_sub(1);
    let dir_components = &components[..dirs];
    if let Some(anchor) = package_org_anchor(dir_components) {
        return dir_components[..(anchor + 4).min(dirs)].join("/");
    }
    dir_components[..dirs.min(4)].join("/")
}

/// Index of a `com`/`org` package segment that is followed by an org name,
/// e.g. `com/acme` — the two segments after the org are the subsystem.
fn package_org_anchor(dir_components: &[&str]) -> Option<usize> {
    dir_components
        .iter()
        .position(|part| *part == "com" || *part == "org")
        .filter(|index| index + 1 < dir_components.len())
}

fn severity_weight(severity: &Severity) -> u32 {
    match severity {
        Severity::Critical => 8,
        Severity::High => 4,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info | Severity::Unknown => 0,
    }
}

fn chain_link(finding: &Finding, role: ChainRole) -> ChainLink {
    ChainLink {
        fingerprint: finding.fingerprint.clone(),
        title: finding.title.clone(),
        severity: format!("{:?}", finding.severity).to_lowercase(),
        file_path: finding.file_path.clone(),
        role,
    }
}

/// Fold confirmed findings into ranked same-surface chain candidates.
pub fn fold_chains(confirmed: &[Finding], max_chains: usize) -> ChainReport {
    let surfaces = group_by_surface(confirmed);
    let mut chains: Vec<ChainCandidate> = surfaces
        .iter()
        .flat_map(|(surface, members)| surface_chains(surface, members))
        .collect();
    chains.sort_by_key(|chain| std::cmp::Reverse(chain.score));
    chains.truncate(max_chains);
    ChainReport {
        confirmed_count: confirmed.len(),
        surface_count: surfaces.len(),
        chains,
    }
}

fn group_by_surface(confirmed: &[Finding]) -> BTreeMap<String, Vec<&Finding>> {
    let mut surfaces: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in confirmed {
        surfaces
            .entry(surface_key(&finding.file_path))
            .or_default()
            .push(finding);
    }
    surfaces
}

fn surface_chains(surface: &str, members: &[&Finding]) -> Vec<ChainCandidate> {
    let classified: Vec<(&Finding, Vec<ChainRole>)> = members
        .iter()
        .map(|finding| (*finding, chain_roles(finding)))
        .collect();
    let entries = with_role(&classified, ChainRole::Entry);
    let impacts = with_role(&classified, ChainRole::Impact);
    let pivots = with_role(&classified, ChainRole::Pivot);
    entries
        .iter()
        .flat_map(|entry| impact_pairs(surface, entry, &impacts, &pivots))
        .collect()
}

fn with_role<'a>(
    classified: &[(&'a Finding, Vec<ChainRole>)],
    role: ChainRole,
) -> Vec<&'a Finding> {
    classified
        .iter()
        .filter(|(_, roles)| roles.contains(&role))
        .map(|(finding, _)| *finding)
        .collect()
}

fn impact_pairs(
    surface: &str,
    entry: &Finding,
    impacts: &[&Finding],
    pivots: &[&Finding],
) -> Vec<ChainCandidate> {
    impacts
        .iter()
        .filter(|impact| impact.fingerprint != entry.fingerprint)
        .map(|impact| candidate(surface, entry, impact, pivots))
        .collect()
}

fn candidate(
    surface: &str,
    entry: &Finding,
    impact: &Finding,
    pivots: &[&Finding],
) -> ChainCandidate {
    let bridge: Vec<ChainLink> = pivots
        .iter()
        .filter(|pivot| {
            pivot.fingerprint != entry.fingerprint && pivot.fingerprint != impact.fingerprint
        })
        .take(MAX_PIVOTS_PER_CHAIN)
        .map(|pivot| chain_link(pivot, ChainRole::Pivot))
        .collect();
    let base_score =
        severity_weight(&entry.severity) + severity_weight(&impact.severity) + bridge.len() as u32;
    // Entry and impact in one file almost always sit behind the same trust
    // boundary (facets of one handler), so composing them escalates nothing.
    let same_file = entry.file_path == impact.file_path;
    let score = if same_file { base_score / 2 } else { base_score };
    let rationale = format!(
        "entry `{}` and impact `{}` share surface `{}`{}{}",
        entry.title,
        impact.title,
        surface,
        if bridge.is_empty() {
            String::new()
        } else {
            format!(" with {} pivot lead(s)", bridge.len())
        },
        if same_file {
            "; same-file pair (same boundary) — discounted"
        } else {
            ""
        }
    );
    ChainCandidate {
        surface: surface.to_string(),
        entry: chain_link(entry, ChainRole::Entry),
        pivots: bridge,
        impact: chain_link(impact, ChainRole::Impact),
        score,
        rationale,
    }
}

/// `findings:chains` executor — deterministic, read-mostly; writes the
/// report JSON only when the `output` option names a path.
pub fn execute_findings_chains(
    input: &Value,
    ctx: &crate::modules::ToolExecutionContext<'_>,
) -> Result<Value> {
    let store = ctx
        .findings_store
        .context("findings:chains requires the findings store")?;
    let confirmed = confirmed_findings(store)?;
    let max_chains = max_chains_from_input(input)?;
    let report = fold_chains(&confirmed, max_chains);
    let report_json = serde_json::to_value(&report)?;
    write_optional_report(input, ctx, &report_json)?;
    let output = report_summary(&report);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        report_json,
    ))
}

fn confirmed_findings(store: &crate::findings::FindingStore) -> Result<Vec<Finding>> {
    let findings = store.list_all_findings()?;
    let decisions = store.list_review_decisions_for_findings(&findings)?;
    let confirmed_ids =
        crate::capabilities::campaign::coverage::confirmed_finding_ids_from_decisions(&decisions);
    Ok(findings
        .into_iter()
        .filter(|finding| !finding.suppressed)
        .filter(|finding| finding.id.is_some_and(|id| confirmed_ids.contains(&id)))
        .collect())
}

fn max_chains_from_input(input: &Value) -> Result<usize> {
    let Some(value) = input.get("maxChains") else {
        return Ok(DEFAULT_MAX_CHAINS);
    };
    let max = value
        .as_u64()
        .context("findings:chains: maxChains must be a positive integer")?;
    anyhow::ensure!(max > 0, "findings:chains: maxChains must be positive");
    Ok(max as usize)
}

fn write_optional_report(
    input: &Value,
    ctx: &crate::modules::ToolExecutionContext<'_>,
    report_json: &Value,
) -> Result<()> {
    let Some(path) = input.get("output").and_then(Value::as_str) else {
        return Ok(());
    };
    let workspace = ctx
        .workspace
        .context("findings:chains: output requires an active workspace target")?;
    let resolved = workspace.root().join(path);
    if let Some(parent) = resolved.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&resolved, serde_json::to_string_pretty(report_json)?)?;
    Ok(())
}

fn report_summary(report: &ChainReport) -> String {
    format!(
        "findings:chains — {} candidate chain(s) from {} confirmed finding(s) across {} surface(s)",
        report.chains.len(),
        report.confirmed_count,
        report.surface_count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(fingerprint: &str, title: &str, severity: Severity, path: &str) -> Finding {
        let mut finding = Finding::new_tool("test", "rule", path, 1, None, severity, title);
        finding.fingerprint = fingerprint.to_string();
        finding.id = Some(fingerprint.len() as i64);
        finding
    }

    #[test]
    fn classifies_roles_from_recorded_text() {
        let entry = finding(
            "fp-entry",
            "Unauthenticated Thrift request reaches parser",
            Severity::High,
            "src/svc/a/handler.cpp",
        );
        let impact = finding(
            "fp-impact",
            "Heap overflow via unchecked length",
            Severity::High,
            "src/svc/a/decode.cpp",
        );
        assert!(chain_roles(&entry).contains(&ChainRole::Entry));
        assert!(chain_roles(&impact).contains(&ChainRole::Impact));
        assert!(chain_roles(&finding(
            "fp-none",
            "Stale comment cleanup",
            Severity::Low,
            "src/svc/a/notes.cpp",
        ))
        .is_empty());
    }

    #[test]
    fn surface_key_folds_leading_directories() {
        assert_eq!(
            surface_key("src/cpp/code/appliance/agentserver/netapp/client.cpp"),
            "src/cpp/code/appliance"
        );
        assert_eq!(surface_key("main.cpp"), "");
    }

    #[test]
    fn surface_key_anchors_jvm_package_trees_at_the_org() {
        // Without the anchor these two would share `src/java/core/src` and
        // pair unrelated subsystems (the SAML↔network-throttle regression).
        assert_eq!(
            surface_key(
                "src/java/core/src/main/scala/com/acme/apps/security/policy/impl/PolicyUtilImpl.scala"
            ),
            "src/java/core/src/main/scala/com/acme/apps/security"
        );
        assert_eq!(
            surface_key(
                "src/java/core/src/main/scala/com/acme/common/ratelimit/ShaperWrapper.scala"
            ),
            "src/java/core/src/main/scala/com/acme/common/ratelimit"
        );
        assert_ne!(
            surface_key(
                "src/java/core/src/main/scala/com/acme/auth/saml/SamlUtil.scala"
            ),
            surface_key(
                "src/java/core/src/main/scala/com/acme/common/ratelimit/ShaperWrapper.scala"
            ),
        );
        // A bare `com` with nothing after it must not anchor.
        assert_eq!(surface_key("com/x.scala"), "com");
    }

    #[test]
    fn same_file_entry_impact_pairs_are_discounted() {
        let confirmed = vec![
            finding(
                "fp-entry-sf",
                "Remote peer request path unbound",
                Severity::Critical,
                "src/svc/a/server.cpp",
            ),
            finding(
                "fp-impact-sf",
                "Arbitrary write via peer-supplied path",
                Severity::Critical,
                "src/svc/a/server.cpp",
            ),
            finding(
                "fp-impact-xf",
                "Command injection in helper",
                Severity::Critical,
                "src/svc/a/exec.cpp",
            ),
        ];
        let report = fold_chains(&confirmed, DEFAULT_MAX_CHAINS);
        let cross_file = report
            .chains
            .iter()
            .find(|chain| chain.impact.fingerprint == "fp-impact-xf")
            .expect("cross-file pair present");
        let same_file = report
            .chains
            .iter()
            .find(|chain| chain.impact.fingerprint == "fp-impact-sf")
            .expect("same-file pair present");
        assert!(cross_file.score > same_file.score);
        assert!(same_file.rationale.contains("same-file pair"));
        assert_eq!(report.chains[0].impact.fingerprint, "fp-impact-xf");
    }

    #[test]
    fn folds_same_surface_entry_and_impact_into_a_chain() {
        let confirmed = vec![
            finding(
                "fp-entry",
                "Remote peer request parsed without auth",
                Severity::High,
                "src/svc/a/handler.cpp",
            ),
            finding(
                "fp-impact-x",
                "Command injection in helper",
                Severity::Critical,
                "src/svc/a/exec.cpp",
            ),
            finding(
                "fp-pivot",
                "Credential leak into logs",
                Severity::Medium,
                "src/svc/a/log.cpp",
            ),
        ];
        let report = fold_chains(&confirmed, DEFAULT_MAX_CHAINS);
        assert_eq!(report.chains.len(), 1);
        let chain = &report.chains[0];
        assert_eq!(chain.entry.fingerprint, "fp-entry");
        assert_eq!(chain.impact.fingerprint, "fp-impact-x");
        assert_eq!(chain.pivots.len(), 1);
        assert!(chain.score >= 12);
    }

    #[test]
    fn different_surfaces_never_pair() {
        let confirmed = vec![
            finding(
                "fp-entry",
                "Unauthenticated network listener",
                Severity::High,
                "src/svc/a/handler.cpp",
            ),
            finding(
                "fp-impact-y",
                "Stack overflow from response",
                Severity::High,
                "src/other/b/decode.cpp",
            ),
        ];
        let report = fold_chains(&confirmed, DEFAULT_MAX_CHAINS);
        assert!(report.chains.is_empty());
        assert_eq!(report.surface_count, 2);
    }

    #[test]
    fn chains_rank_by_score_and_truncate() {
        let mut confirmed = vec![
            finding(
                "fp-entry",
                "Remote request parser",
                Severity::Critical,
                "src/svc/a/handler.cpp",
            ),
            finding(
                "fp-impact-hi",
                "Arbitrary write primitive",
                Severity::Critical,
                "src/svc/a/write.cpp",
            ),
            finding(
                "fp-impact-lo",
                "Format string in logger",
                Severity::Low,
                "src/svc/a/fmt.cpp",
            ),
        ];
        confirmed.rotate_left(1);
        let report = fold_chains(&confirmed, 1);
        assert_eq!(report.chains.len(), 1);
        assert_eq!(report.chains[0].impact.fingerprint, "fp-impact-hi");
    }
}
