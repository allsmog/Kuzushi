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

/// Resolve a finding's scope verdict from the host its http-request evidence
/// names. Code findings carry no host, so this returns `None` and a
/// `scope_status` predicate never matches them.
fn finding_scope_verdict(finding: &Finding, scope: &ProgramScope) -> Option<ScopeVerdict> {
    let host = finding_host(finding)?;
    Some(scope.verdict(&host))
}

/// The host a finding's `http-request` evidence names.
///
/// The capture importers gate on the absolute URL the capture recorded
/// (`request.url` in HAR, `<url>` in Burp) and write that same string into the
/// evidence's `file_path` — HTTP evidence carries a URL there by the
/// persistence contract, never a target-relative source path. Reading it keeps
/// this sweep's verdict the one the import gate already reached on the same
/// finding; the raw request is read only for evidence that recorded no URL.
fn finding_host(finding: &Finding) -> Option<String> {
    let evidence = finding
        .evidence
        .iter()
        .find(|evidence| evidence.kind == "http-request")?;
    recorded_target_url(&evidence.file_path)
        .or_else(|| evidence.request_blob.as_deref().and_then(request_head_host))
}

/// The absolute URL this evidence recorded as its target. Requiring a scheme
/// keeps a `file_path` that is not a URL out of the host reading: `verdict`
/// would read `src/app.rs` as the host `src`, matching no rule.
fn recorded_target_url(file_path: &str) -> Option<String> {
    let url = file_path.trim();
    let (scheme, _) = url.split_once("://")?;
    is_uri_scheme(scheme).then(|| url.to_string())
}

/// The host a raw HTTP request names, read from its message head alone.
///
/// A request states its target host in exactly two places: the request line's
/// absolute-form target, which takes precedence, or the `Host` header field
/// (RFC 9112 §3.2, §3.3). Every other URL in the message names something else
/// — a `Referer` or `Origin` is where the request came from, a query parameter
/// such as `?next=https://elsewhere/` is a value the request carries, and the
/// body is not part of the head at all. `ProgramScope::verdict` re-parses the
/// host component, so returning a whole URL is acceptable.
fn request_head_host(blob: &str) -> Option<String> {
    let mut lines = blob.lines();
    let request_line = lines.next()?;
    absolute_form_target(request_line).or_else(|| {
        lines
            .take_while(|line| !line.trim().is_empty())
            .find_map(host_field_value)
    })
}

/// The absolute-form target of a request line (`GET https://host/path
/// HTTP/1.1`), or `None` for the origin, authority, and asterisk forms. The
/// target is the line's second field and must itself begin with a scheme; a
/// `://` further along the line belongs to a value the target carries.
fn absolute_form_target(request_line: &str) -> Option<String> {
    let target = request_line.split_whitespace().nth(1)?;
    let (scheme, _) = target.split_once("://")?;
    is_uri_scheme(scheme).then(|| target.to_string())
}

/// RFC 3986 §3.1: a scheme starts with a letter, then letters, digits, `+`,
/// `-`, and `.`.
fn is_uri_scheme(scheme: &str) -> bool {
    scheme.starts_with(|first: char| first.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// The value of a `Host` header line. Field names are case-insensitive
/// (RFC 9110 §5.1) and no whitespace may precede the colon (RFC 9112 §5), so
/// comparing the whole name rejects both a folded continuation line and an
/// HTTP/2 `:authority` pseudo-header rather than reading either as a host.
fn host_field_value(line: &str) -> Option<String> {
    let (name, value) = line.split_once(':')?;
    if !name.eq_ignore_ascii_case("host") {
        return None;
    }
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod request_head_tests {
    use super::*;

    #[test]
    fn absolute_form_target_wins_and_a_carried_url_is_not_the_target() {
        assert_eq!(
            request_head_host("GET https://api.example.com/x HTTP/1.1\r\nHost: other.test\r\n"),
            Some("https://api.example.com/x".to_string())
        );
        assert_eq!(absolute_form_target("GET /r?next=https://out.test/ HTTP/1.1"), None);
        assert_eq!(
            request_head_host("GET /r?next=https://out.test/ HTTP/1.1\r\nHost: api.example.com\r\n"),
            Some("api.example.com".to_string())
        );
        assert_eq!(absolute_form_target("OPTIONS * HTTP/1.1"), None);
        assert_eq!(absolute_form_target("GET"), None);
    }

    #[test]
    fn only_a_host_field_in_the_head_names_the_host() {
        let referer_first = "POST /login HTTP/1.1\r\n\
             Referer: https://cdn.thirdparty.test/sso\r\n\
             HOST: api.example.com\r\n\r\n";
        assert_eq!(
            request_head_host(referer_first),
            Some("api.example.com".to_string())
        );
        // The body is not part of the head: a URL in it names no target.
        assert_eq!(
            request_head_host("POST /hook HTTP/1.1\r\n\r\n{\"url\":\"https://out.test/\"}"),
            None
        );
        // `:authority` is not a `Host` field, and neither is a folded line.
        assert_eq!(
            request_head_host("GET /x HTTP/2\r\n:authority: api.example.com\r\n"),
            None
        );
        assert_eq!(request_head_host("GET /x HTTP/1.1\r\n  Host: api.example.com\r\n"), None);
        assert_eq!(request_head_host("GET /x HTTP/1.1\r\nHost:   \r\n"), None);
    }

    #[test]
    fn a_recorded_url_is_read_only_when_it_carries_a_scheme() {
        assert_eq!(
            recorded_target_url(" https://api.example.com/login "),
            Some("https://api.example.com/login".to_string())
        );
        assert_eq!(recorded_target_url("src/app.rs"), None);
        assert_eq!(recorded_target_url(""), None);
        assert!(is_uri_scheme("http"));
        assert!(!is_uri_scheme("/r?next=https"));
    }
}
