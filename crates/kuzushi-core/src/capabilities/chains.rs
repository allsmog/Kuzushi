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
use std::collections::{BTreeMap, BTreeSet};

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
    pub start_line: u32,
    pub role: ChainRole,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainCandidate {
    /// Stable identity over the constituent finding fingerprints: the same
    /// confirmed set always folds to the same chain id, so durable chain
    /// artifacts survive re-runs and can be referenced across sessions.
    pub id: String,
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
    let text = format!("{} {} {}", finding.title, finding.message, finding.rule_id).to_lowercase();
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
        start_line: finding.start_line,
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
    chains.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.entry.fingerprint.cmp(&b.entry.fingerprint))
            .then_with(|| a.impact.fingerprint.cmp(&b.impact.fingerprint))
    });
    let mut chains = dedupe_mirrored_pairs(chains);
    chains.truncate(max_chains);
    ChainReport {
        confirmed_count: confirmed.len(),
        surface_count: surfaces.len(),
        chains,
    }
}

/// When two findings each classify as both entry and impact, the pair folds
/// once per orientation; the mirrored duplicate carries no new information,
/// so only the highest-ranked orientation survives (the sort above makes the
/// survivor deterministic on score ties).
fn dedupe_mirrored_pairs(chains: Vec<ChainCandidate>) -> Vec<ChainCandidate> {
    let mut seen: BTreeSet<[String; 2]> = BTreeSet::new();
    chains
        .into_iter()
        .filter(|chain| {
            let mut pair = [
                chain.entry.fingerprint.clone(),
                chain.impact.fingerprint.clone(),
            ];
            pair.sort();
            seen.insert(pair)
        })
        .collect()
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
    let bridge = candidate_bridge(entry, impact, pivots);
    let same_file = entry.file_path == impact.file_path;
    let id = chain_identity(surface, entry, &bridge, impact);
    let score = candidate_score(entry, impact, bridge.len(), same_file);
    let rationale = candidate_rationale(surface, entry, impact, bridge.len(), same_file);
    ChainCandidate {
        id,
        surface: surface.to_string(),
        entry: chain_link(entry, ChainRole::Entry),
        pivots: bridge,
        impact: chain_link(impact, ChainRole::Impact),
        score,
        rationale,
    }
}

fn candidate_bridge(entry: &Finding, impact: &Finding, pivots: &[&Finding]) -> Vec<ChainLink> {
    pivots
        .iter()
        .filter(|pivot| {
            pivot.fingerprint != entry.fingerprint && pivot.fingerprint != impact.fingerprint
        })
        .take(MAX_PIVOTS_PER_CHAIN)
        .map(|pivot| chain_link(pivot, ChainRole::Pivot))
        .collect()
}

fn candidate_score(entry: &Finding, impact: &Finding, pivots: usize, same_file: bool) -> u32 {
    let base_score =
        severity_weight(&entry.severity) + severity_weight(&impact.severity) + pivots as u32;
    // Entry and impact in one file almost always sit behind the same trust
    // boundary (facets of one handler), so composing them escalates nothing.
    if same_file {
        base_score / 2
    } else {
        base_score
    }
}

fn candidate_rationale(
    surface: &str,
    entry: &Finding,
    impact: &Finding,
    pivots: usize,
    same_file: bool,
) -> String {
    format!(
        "entry `{}` and impact `{}` share surface `{}`{}{}",
        entry.title,
        impact.title,
        surface,
        if pivots == 0 {
            String::new()
        } else {
            format!(" with {pivots} pivot lead(s)")
        },
        if same_file {
            "; same-file pair (same boundary) — discounted"
        } else {
            ""
        }
    )
}

/// Deterministic chain identity over the constituent finding fingerprints.
fn chain_identity(
    surface: &str,
    entry: &Finding,
    pivots: &[ChainLink],
    impact: &Finding,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(surface.as_bytes());
    hasher.update(b"|");
    hasher.update(entry.fingerprint.as_bytes());
    for pivot in pivots {
        hasher.update(b"|");
        hasher.update(pivot.fingerprint.as_bytes());
    }
    hasher.update(b"|");
    hasher.update(impact.fingerprint.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("AC-{hex}")
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
    let mut report_json = serde_json::to_value(&report)?;
    persist_chain_artifacts(ctx, &report, &report_json)?;
    persist_chain_findings_when_enabled(input, ctx, &report, &mut report_json)?;
    write_optional_report(input, ctx, &report_json)?;
    let output = report_summary(&report);
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        report_json,
    ))
}

/// Opt-in: persist each chain candidate as an ordinary finding (tool
/// `chains`, rule `chains/candidate`) so `triage:run` can triage the chain
/// itself. The deterministic message keeps the fingerprint stable across
/// re-folds, so an already-triaged chain is not re-billed.
fn persist_chain_findings_when_enabled(
    input: &Value,
    ctx: &crate::modules::ToolExecutionContext<'_>,
    report: &ChainReport,
    report_json: &mut Value,
) -> Result<()> {
    if !chain_persist_findings_enabled(input) || report.chains.is_empty() {
        return Ok(());
    }
    let workspace = ctx
        .workspace
        .context("findings:chains: persistFindings requires an active workspace target")?;
    let findings: Vec<Finding> = report.chains.iter().map(chain_candidate_finding).collect();
    let persisted = crate::findings::persist_tool_findings(
        ctx.finding_run_id(),
        workspace.root(),
        &findings,
        ctx.workspace,
        ctx.findings_store,
    )?;
    if let Some(object) = report_json.as_object_mut() {
        object.insert(
            "persistedRunId".to_string(),
            match persisted {
                Some(run) => Value::String(run.run_id),
                None => Value::Null,
            },
        );
        object.insert("persistedCount".to_string(), Value::from(findings.len()));
    }
    Ok(())
}

fn chain_persist_findings_enabled(input: &Value) -> bool {
    input
        .get("persistFindings")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Map a chain candidate onto a triageable finding. Location is the entry
/// link (where the attacker enters); the message is a deterministic ordered
/// narrative naming every constituent fingerprint, so the chain's identity
/// is a pure function of its members.
pub fn chain_candidate_finding(candidate: &ChainCandidate) -> Finding {
    Finding::new_tool(
        "chains",
        "chains/candidate",
        candidate.entry.file_path.clone(),
        candidate.entry.start_line,
        None,
        Severity::from_label(&candidate.impact.severity),
        chain_finding_message(candidate),
    )
    .with_dedup_key(format!("chain:{}", candidate.id))
    .with_source_signature(candidate.id.clone())
}

fn chain_finding_message(candidate: &ChainCandidate) -> String {
    let mut lines = vec![
        format!(
            "Attack chain {}: {} -> {}",
            candidate.id, candidate.entry.title, candidate.impact.title
        ),
        String::new(),
        format!("Surface: {}", candidate.surface),
        format!("Rationale: {}", candidate.rationale),
        String::new(),
        "Attack path:".to_string(),
        chain_step_line(1, &candidate.entry),
    ];
    let mut step = 2;
    for pivot in &candidate.pivots {
        lines.push(chain_step_line(step, pivot));
        step += 1;
    }
    lines.push(chain_step_line(step, &candidate.impact));
    lines.push(String::new());
    lines.push(format!(
        "Members: {}",
        chain_member_fingerprints(candidate).join(", ")
    ));
    lines.join("\n")
}

fn chain_step_line(step: usize, link: &ChainLink) -> String {
    format!(
        "{step}. [{role:?}] {title} at {file}:{line} [finding {fp}]",
        role = link.role,
        title = link.title,
        file = link.file_path,
        line = link.start_line,
        fp = link.fingerprint,
    )
}

fn chain_member_fingerprints(candidate: &ChainCandidate) -> Vec<String> {
    let mut members = vec![candidate.entry.fingerprint.clone()];
    members.extend(candidate.pivots.iter().map(|p| p.fingerprint.clone()));
    members.push(candidate.impact.fingerprint.clone());
    members
}

pub(crate) fn confirmed_findings(store: &crate::findings::FindingStore) -> Result<Vec<Finding>> {
    let findings = store.list_relevant_findings()?;
    let decisions = store.latest_review_decisions_for_findings(&findings, false)?;
    Ok(findings
        .into_iter()
        .filter(|finding| finding_is_confirmed(finding, &decisions))
        .collect())
}

fn finding_is_confirmed(
    finding: &Finding,
    decisions: &std::collections::BTreeMap<String, crate::findings::ReviewDecision>,
) -> bool {
    let decision = review_decision_key(finding)
        .and_then(|key| decisions.get(&key))
        .map(|decision| decision.verdict)
        .or_else(|| {
            finding.triage.as_ref().map(|triage| {
                crate::findings::ReviewDecisionVerdict::from_triage_verdict(triage.verdict)
            })
        });
    matches!(
        decision,
        Some(
            crate::findings::ReviewDecisionVerdict::Confirmed
                | crate::findings::ReviewDecisionVerdict::ToFix
        )
    )
}

fn review_decision_key(finding: &Finding) -> Option<String> {
    finding
        .identity_id
        .as_ref()
        .map(|identity| format!("identity:{identity}"))
        .or_else(|| finding.id.map(|id| format!("finding:{id}")))
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

/// Chains are durable artifacts, not a transient view: every fold persists
/// the canonical report (`.kuzushi/v3/reports/chains.json`) and the scene
/// snapshot the ATTACK CHAINS screen renders from, each chain carrying its
/// stable identity and the constituent finding fingerprints.
fn persist_chain_artifacts(
    ctx: &crate::modules::ToolExecutionContext<'_>,
    report: &ChainReport,
    report_json: &Value,
) -> Result<()> {
    let Some(workspace) = ctx.workspace else {
        return Ok(());
    };
    let pretty = format!("{}\n", serde_json::to_string_pretty(report_json)?);
    crate::workspace::write_workspace_state_file(
        workspace.root(),
        std::path::Path::new(crate::workspace::KUZUSHI_STATE_DIR).join("v3/reports/chains.json"),
        pretty.as_bytes(),
    )?;
    // Per-run archive: the canonical chains.json is overwritten on every
    // fold, so repeated folds at the same SHA keep their own snapshots.
    if let Some(run_id) = ctx.run_id() {
        crate::workspace::write_workspace_state_file(
            workspace.root(),
            std::path::Path::new(crate::workspace::KUZUSHI_STATE_DIR)
                .join(format!("v3/reports/chains/{run_id}.json")),
            pretty.as_bytes(),
        )?;
    }
    crate::capabilities::save_persistent_exploit_chains(
        workspace.root(),
        &scene_chain_payload(report),
    )?;
    Ok(())
}

/// Scene-snapshot shape consumed by the attack-tree visualization: one step
/// per constituent finding, ordered entry → pivots → impact.
fn scene_chain_payload(report: &ChainReport) -> Value {
    let chains: Vec<Value> = report
        .chains
        .iter()
        .map(|chain| {
            let mut steps = vec![scene_chain_step(&chain.entry)];
            steps.extend(chain.pivots.iter().map(scene_chain_step));
            steps.push(scene_chain_step(&chain.impact));
            serde_json::json!({
                "id": chain.id,
                "name": format!("{} → {}", chain.entry.title, chain.impact.title),
                "overallSeverity": chain.impact.severity,
                "narrative": chain.rationale,
                "preconditions": [format!("surface `{}` reachable", chain.surface)],
                "steps": steps,
            })
        })
        .collect();
    serde_json::json!({ "chains": chains })
}

fn scene_chain_step(link: &ChainLink) -> Value {
    serde_json::json!({
        "role": format!("{:?}", link.role).to_lowercase(),
        "description": format!("{} · finding {}", link.title, link.fingerprint),
        "filePath": link.file_path,
        "startLine": link.start_line,
    })
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
    fn mirrored_pair_folds_to_a_single_chain() {
        // Both findings classify as entry AND impact (peer-supplied input
        // that is itself a write primitive), so the naive fold emits the
        // pair in both orientations; only one may survive.
        let a = finding(
            "fp-a",
            "handlePullContent peer-supplied patch file path arbitrary write",
            Severity::High,
            "src/svc/transfer/pull.cpp",
        );
        let b = finding(
            "fp-b",
            "Replication pull trusts peer-returned extent count: OOB vector index + write",
            Severity::High,
            "src/svc/transfer/extent.cpp",
        );
        let roles_a = chain_roles(&a);
        let roles_b = chain_roles(&b);
        assert!(
            roles_a.contains(&ChainRole::Entry) && roles_a.contains(&ChainRole::Impact),
            "fixture must be dual-role: {roles_a:?}"
        );
        assert!(
            roles_b.contains(&ChainRole::Entry) && roles_b.contains(&ChainRole::Impact),
            "fixture must be dual-role: {roles_b:?}"
        );

        let report = fold_chains(&[a, b], 16);
        assert_eq!(
            report.chains.len(),
            1,
            "mirrored orientations must dedupe: {:?}",
            report
                .chains
                .iter()
                .map(|c| (c.entry.fingerprint.clone(), c.impact.fingerprint.clone()))
                .collect::<Vec<_>>()
        );
        // Deterministic survivor on tied score: lowest entry fingerprint.
        assert_eq!(report.chains[0].entry.fingerprint, "fp-a");
    }

    #[test]
    fn surface_key_folds_leading_directories() {
        assert_eq!(
            surface_key("src/cpp/code/svc/agentserver/netapp/client.cpp"),
            "src/cpp/code/svc"
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
            surface_key("src/java/core/src/main/scala/com/acme/auth/saml/SamlUtil.scala"),
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
    fn confirmed_identity_remains_chain_eligible_after_later_observation() {
        let store = crate::findings::FindingStore::open_in_memory().unwrap();
        let finding = Finding::new_tool(
            "agentic-sast",
            "rule/entry",
            "src/svc/a/handler.rs",
            8,
            None,
            Severity::High,
            "remote request reaches an unguarded handler",
        );
        store
            .record_run_started("scan-a", std::path::Path::new("/repo"), "completed")
            .unwrap();
        let first_id = store.insert_finding("scan-a", &finding).unwrap();
        store.record_run_finished("scan-a", "completed", 1).unwrap();
        store
            .append_user_review_decision(
                first_id,
                &crate::findings::ReviewDecision {
                    verdict: crate::findings::ReviewDecisionVerdict::Confirmed,
                    author: crate::findings::TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "confirmed by operator".to_string(),
                    dismiss_reason: None,
                    actor: Some("operator".to_string()),
                },
            )
            .unwrap();
        store
            .record_run_started("scan-b", std::path::Path::new("/repo"), "completed")
            .unwrap();
        store.insert_finding("scan-b", &finding).unwrap();
        store.record_run_finished("scan-b", "completed", 1).unwrap();

        let confirmed = confirmed_findings(&store).unwrap();
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].scan_id.as_deref(), Some("scan-b"));
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

    /// Chain identity is stable over the constituent finding fingerprints:
    /// the same confirmed set always folds to the same durable id.
    #[test]
    fn chain_identity_is_stable_and_fingerprint_derived() {
        let confirmed = vec![
            finding(
                "fp-entry",
                "Unauthenticated request handler",
                Severity::High,
                "svc/api/entry.py",
            ),
            finding(
                "fp-impact",
                "Command injection in worker",
                Severity::High,
                "svc/api/worker.py",
            ),
        ];

        let first = fold_chains(&confirmed, 4);
        let second = fold_chains(&confirmed, 4);

        assert_eq!(first.chains.len(), 1);
        let id = &first.chains[0].id;
        assert!(id.starts_with("AC-") && id.len() == 15, "{id}");
        assert_eq!(id, &second.chains[0].id, "identity must be deterministic");
    }

    /// The persisted scene payload references the real finding fingerprints
    /// so the ATTACK CHAINS screen renders chains as artifacts over
    /// constituent findings, not detached narrative.
    #[test]
    fn scene_payload_orders_steps_and_references_finding_fingerprints() {
        let confirmed = vec![
            finding(
                "fp-entry",
                "Unauthenticated request handler",
                Severity::High,
                "svc/api/entry.py",
            ),
            finding(
                "fp-pivot",
                "Hardcoded password in config",
                Severity::Medium,
                "svc/api/config.py",
            ),
            finding(
                "fp-impact",
                "Command injection in worker",
                Severity::High,
                "svc/api/worker.py",
            ),
        ];
        let report = fold_chains(&confirmed, 4);

        let payload = scene_chain_payload(&report);

        let chain = &payload["chains"][0];
        assert_eq!(chain["id"], report.chains[0].id.as_str());
        let steps = chain["steps"].as_array().unwrap();
        assert_eq!(steps[0]["role"], "entry");
        assert_eq!(steps.last().unwrap()["role"], "impact");
        assert!(steps[0]["description"]
            .as_str()
            .unwrap()
            .contains("finding fp-entry"));
        assert!(steps.last().unwrap()["description"]
            .as_str()
            .unwrap()
            .contains("finding fp-impact"));
    }
}
