use super::suppression_rule::{SuppressionOrigin, SuppressionPredicate, SuppressionReason, SuppressionRule};
use crate::findings::{Finding, Severity};
use crate::workspace::{ProgramScope, ScopeVerdict};
use serde::Serialize;

/// Stable projection key for a finding: its identity id when present,
/// otherwise its fingerprint. Mirrors `V3IdentityRef::stable_fp`.
pub fn finding_stable_fp(finding: &Finding) -> String {
    finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone())
}

#[derive(Debug, Clone, Serialize)]
pub struct SuppressionMatch {
    pub rule_id: String,
    pub reason: SuppressionReason,
    pub statement: String,
    pub origin: SuppressionOrigin,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SuppressionState {
    /// A live rule suppresses this finding.
    Active(SuppressionMatch),
    /// A rule matches but has lapsed — the finding is OPEN and should reopen.
    Expired { rule_id: String, expired_at_unix: u64 },
    /// No rule matches.
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuppressionStateEntry {
    pub stable_fp: String,
    pub fingerprint: String,
    pub state: SuppressionState,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuppressionReport {
    pub states: Vec<SuppressionStateEntry>,
    pub active_count: usize,
    /// `(stable_fp, rule_id)` pairs whose suppressing rule lapsed.
    pub reopened_by_expiry: Vec<(String, String)>,
    pub expired_rules: Vec<String>,
    pub malformed_ignore_comments: Vec<String>,
    /// Always true. Suppression annotates; it never hides a finding.
    pub findings_remain_visible: bool,
}

/// Pure evaluation. `now_unix` and `scope` are injected — no IO, no clock.
pub fn evaluate_suppressions(
    findings: &[Finding],
    rules: &[SuppressionRule],
    scope: Option<&ProgramScope>,
    now_unix: u64,
) -> SuppressionReport {
    evaluate_with_comment_diagnostics(findings, rules, scope, now_unix, Vec::new())
}

/// Same as [`evaluate_suppressions`] but carries forward malformed
/// in-source comment diagnostics collected by the comment scanner.
pub fn evaluate_with_comment_diagnostics(
    findings: &[Finding],
    rules: &[SuppressionRule],
    scope: Option<&ProgramScope>,
    now_unix: u64,
    malformed_ignore_comments: Vec<String>,
) -> SuppressionReport {
    let ordered = specificity_ordered(rules);
    let mut states = Vec::with_capacity(findings.len());
    let mut active_count = 0;
    let mut reopened_by_expiry = Vec::new();
    for finding in findings {
        let state = evaluate_finding(finding, &ordered, scope, now_unix);
        match &state {
            SuppressionState::Active(_) => active_count += 1,
            SuppressionState::Expired { rule_id, .. } => {
                reopened_by_expiry.push((finding_stable_fp(finding), rule_id.clone()));
            }
            SuppressionState::None => {}
        }
        states.push(SuppressionStateEntry {
            stable_fp: finding_stable_fp(finding),
            fingerprint: finding.fingerprint.clone(),
            state,
        });
    }
    SuppressionReport {
        states,
        active_count,
        reopened_by_expiry,
        expired_rules: expired_rule_ids(rules, now_unix),
        malformed_ignore_comments,
        findings_remain_visible: true,
    }
}

fn specificity_ordered(rules: &[SuppressionRule]) -> Vec<&SuppressionRule> {
    let mut ordered: Vec<&SuppressionRule> = rules.iter().collect();
    ordered.sort_by_key(|rule| rule.origin.specificity_rank());
    ordered
}

fn expired_rule_ids(rules: &[SuppressionRule], now_unix: u64) -> Vec<String> {
    rules
        .iter()
        .filter(|rule| rule.is_expired(now_unix))
        .map(|rule| rule.id.clone())
        .collect()
}

/// First live match wins. If no rule is live but at least one lapsed rule
/// matches, the finding is `Expired` (a candidate to reopen).
fn evaluate_finding(
    finding: &Finding,
    ordered: &[&SuppressionRule],
    scope: Option<&ProgramScope>,
    now_unix: u64,
) -> SuppressionState {
    let mut lapsed: Option<&SuppressionRule> = None;
    for rule in ordered {
        if !match_rule(&rule.predicate, finding, scope) {
            continue;
        }
        if rule.is_expired(now_unix) {
            lapsed.get_or_insert(rule);
            continue;
        }
        return SuppressionState::Active(SuppressionMatch {
            rule_id: rule.id.clone(),
            reason: rule.reason,
            statement: rule.statement.clone(),
            origin: rule.origin,
            expires_at_unix: rule.expires_at_unix,
        });
    }
    match lapsed {
        Some(rule) => SuppressionState::Expired {
            rule_id: rule.id.clone(),
            expired_at_unix: rule.expires_at_unix.unwrap_or(now_unix),
        },
        None => SuppressionState::None,
    }
}

/// Conjunctive: every present predicate field must match.
fn match_rule(
    predicate: &SuppressionPredicate,
    finding: &Finding,
    scope: Option<&ProgramScope>,
) -> bool {
    finding_ref_matches(predicate, finding)
        && exact_matches(predicate.rule_id.as_deref(), &finding.rule_id)
        && exact_matches(predicate.tool.as_deref(), &finding.tool)
        && module_matches(predicate.module.as_deref(), &finding.tool)
        && path_matches(predicate, finding)
        && severity_matches_below(predicate.severity_below, finding.severity)
        && scope_status_matches(predicate.scope_status, finding, scope)
}

fn finding_ref_matches(predicate: &SuppressionPredicate, finding: &Finding) -> bool {
    match &predicate.finding_id {
        Some(reference) => reference.matches(finding),
        None => true,
    }
}

fn exact_matches(expected: Option<&str>, actual: &str) -> bool {
    match expected {
        Some(value) => value == actual,
        None => true,
    }
}

fn module_matches(module: Option<&str>, tool: &str) -> bool {
    let Some(module) = module else {
        return true;
    };
    let finding_module = tool.split(':').next().unwrap_or(tool);
    finding_module == module
}

fn path_matches(predicate: &SuppressionPredicate, finding: &Finding) -> bool {
    match &predicate.path_glob {
        Some(glob) => glob.is_match(&finding.file_path),
        None => true,
    }
}

/// Matches strictly below the threshold. `Unknown` is never below any bar —
/// an unclassified finding must never be silently muted by a severity gate.
fn severity_matches_below(threshold: Option<Severity>, severity: Severity) -> bool {
    match threshold {
        Some(threshold) => severity != Severity::Unknown && severity < threshold,
        None => true,
    }
}

fn scope_status_matches(
    expected: Option<ScopeVerdict>,
    finding: &Finding,
    scope: Option<&ProgramScope>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(scope) = scope else {
        return false;
    };
    finding_scope_verdict(finding, scope) == Some(expected)
}

/// Resolve a finding's scope verdict from its http-request evidence host.
/// Code findings carry no host, so this returns `None` and a `scope_status`
/// predicate never matches them.
fn finding_scope_verdict(finding: &Finding, scope: &ProgramScope) -> Option<ScopeVerdict> {
    let host = finding_host(finding)?;
    Some(scope.verdict(&host))
}

fn finding_host(finding: &Finding) -> Option<String> {
    finding
        .evidence
        .iter()
        .find(|evidence| evidence.kind == "http-request")
        .and_then(|evidence| evidence.request_blob.as_deref())
        .and_then(request_blob_host)
}

/// Best-effort host extraction from a raw HTTP request blob. Reads the URL
/// from the request line or a `Host:` header. `ProgramScope::verdict`
/// re-parses the host component, so a full URL is acceptable here.
fn request_blob_host(blob: &str) -> Option<String> {
    for line in blob.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Host:").or_else(|| trimmed.strip_prefix("host:"))
        {
            let host = rest.trim();
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
        if let Some(url) = request_line_url(trimmed) {
            return Some(url);
        }
    }
    None
}

fn request_line_url(line: &str) -> Option<String> {
    let candidate = line.split_whitespace().find(|token| token.contains("://"))?;
    Some(candidate.to_string())
}
