use anyhow::{Context, Result};
use globset::Glob;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

/// Operator-controlled bug-bounty scope file loaded from
/// `<workspace>/.kuzushi/scope.toml`. Contains an in-scope allow list
/// and an out-of-scope deny list. Recon, Burp/HAR import, and any tool
/// that takes a host or URL argument runs every target through
/// [`ProgramScope::verdict`] before dispatch. Out-of-scope assets are
/// refused with an actionable message; when an in-scope allow list is present,
/// unmatched assets are also refused.
///
/// File schema:
/// ```toml
/// [in_scope]
/// hosts = ["*.example.com", "api.test"]
/// cidrs = ["10.0.0.0/8"]
///
/// [out_of_scope]
/// hosts = ["admin.example.com"]
/// cidrs = ["10.99.0.0/16"]
/// ```
#[derive(Debug, Default, Clone)]
pub struct ProgramScope {
    in_scope: Vec<HostPattern>,
    out_of_scope: Vec<HostPattern>,
}

/// One entry in a scope allow/deny list. Either a host glob
/// (e.g. `*.example.com`) compiled via `globset`, or a CIDR range
/// parsed via `ipnet`.
#[derive(Debug, Clone)]
pub enum HostPattern {
    HostGlob(Glob),
    Cidr(IpNet),
}

/// Outcome of validating a candidate target against the active scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeVerdict {
    /// Target matches an in-scope pattern and no out-of-scope pattern.
    InScope,
    /// Target matches an out-of-scope pattern — dispatch must refuse.
    OutOfScope,
    /// Target matches neither list and there is no allow list. Callers may warn.
    Unknown,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramScopeFile {
    #[serde(default)]
    pub in_scope: ProgramScopeList,
    #[serde(default)]
    pub out_of_scope: ProgramScopeList,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramScopeList {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
}

impl ProgramScope {
    pub fn from_file(parsed: &ProgramScopeFile) -> Result<Self> {
        Ok(Self {
            in_scope: compile_patterns(&parsed.in_scope)?,
            out_of_scope: compile_patterns(&parsed.out_of_scope)?,
        })
    }

    pub fn parse(toml_text: &str) -> Result<Self> {
        let parsed: ProgramScopeFile =
            toml::from_str(toml_text).context("Could not parse scope.toml")?;
        Self::from_file(&parsed)
    }

    pub fn is_empty(&self) -> bool {
        self.in_scope.is_empty() && self.out_of_scope.is_empty()
    }

    /// `false` when the host is explicitly out-of-scope, or when an allow list
    /// exists and the host does not match it. Used by per-entry import gates
    /// (M2 §2.2 / §2.3) so each amass/httpx/nuclei/nmap-xml/HAR/Burp
    /// entry is checked individually — `recon:import` does not carry
    /// a top-level target field, so the dispatch-level scope guard is
    /// not sufficient.
    pub fn host_allowed(&self, target: &str) -> bool {
        self.verdict(target) != ScopeVerdict::OutOfScope
    }

    /// Validate a candidate target — host, IP, or URL — against the active
    /// scope. Out-of-scope wins over in-scope so deny rules dominate. Returns
    /// [`ScopeVerdict::Unknown`] only when no allow list exists and the target
    /// matches nothing.
    pub fn verdict(&self, target: &str) -> ScopeVerdict {
        let host = extract_host(target);
        if matches_any(&self.out_of_scope, &host) {
            return ScopeVerdict::OutOfScope;
        }
        if matches_any(&self.in_scope, &host) {
            return ScopeVerdict::InScope;
        }
        unmatched_scope_verdict(!self.in_scope.is_empty())
    }
}

fn unmatched_scope_verdict(has_allow_list: bool) -> ScopeVerdict {
    if has_allow_list {
        ScopeVerdict::OutOfScope
    } else {
        ScopeVerdict::Unknown
    }
}

fn compile_patterns(list: &ProgramScopeList) -> Result<Vec<HostPattern>> {
    let mut compiled = Vec::with_capacity(list.hosts.len() + list.cidrs.len());
    for raw in &list.hosts {
        // Both sides of the comparison are normalized, so a glob written with
        // uppercase letters or a root dot still denies the asset it names.
        // Character classes are normalized too: `[A-Z]` becomes `[a-z]`, which
        // matches the same hosts once the candidate is lowercased.
        let glob = Glob::new(&normalize_host(raw))
            .with_context(|| format!("invalid host glob in scope.toml: {raw}"))?;
        compiled.push(HostPattern::HostGlob(glob));
    }
    for raw in &list.cidrs {
        let cidr =
            IpNet::from_str(raw).with_context(|| format!("invalid cidr in scope.toml: {raw}"))?;
        compiled.push(HostPattern::Cidr(cidr));
    }
    Ok(compiled)
}

fn matches_any(patterns: &[HostPattern], host: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| matches_pattern(pattern, host))
}

fn matches_pattern(pattern: &HostPattern, host: &str) -> bool {
    match pattern {
        HostPattern::HostGlob(glob) => glob.compile_matcher().is_match(host),
        HostPattern::Cidr(cidr) => cidr_contains_host(cidr, host),
    }
}

/// `true` when a candidate host is an IP literal inside the rule's range.
/// A candidate is tested in both of the families it can name: `::ffff:10.0.0.1`
/// is the IPv4-mapped form of `10.0.0.1` (RFC 4291 §2.5.5.2), so a client that
/// connects to it reaches the IPv4 host and an IPv4 rule has to cover it.
/// `ipnet` compares families strictly, so without the mapped form a deny rule
/// written `10.99.0.0/16` would let `[::ffff:10.99.0.1]:443` through.
/// Both forms are tried, never one instead of the other, so a rule already
/// written in the mapped IPv6 range keeps matching the addresses it named.
fn cidr_contains_host(cidr: &IpNet, host: &str) -> bool {
    let Ok(addr) = IpAddr::from_str(host) else {
        return false;
    };
    cidr.contains(&addr) || mapped_ipv4(addr).is_some_and(|v4| cidr.contains(&v4))
}

/// The IPv4 address an IPv4-mapped IPv6 literal names, if it is one. The
/// deprecated IPv4-compatible form (`::10.0.0.1`) is deliberately excluded:
/// RFC 4291 §2.5.5.1 retired it and current stacks do not route it to the
/// embedded IPv4 host, so treating it as that host would widen a rule past
/// what an operator's file says.
fn mapped_ipv4(addr: IpAddr) -> Option<IpAddr> {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4),
        IpAddr::V4(_) => None,
    }
}

/// Pull the host component out of a free-form target string. Accepts
/// raw hosts, IP literals, `host:port`, and URLs with schemes. Falls
/// back to the trimmed input so unknown formats still get a chance to
/// match host globs. The result is normalized by [`normalize_host`] so a
/// deny rule cannot be evaded by changing the case of a hostname.
fn extract_host(target: &str) -> String {
    let trimmed = target.trim();
    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    // The authority ends at the first path/query/fragment delimiter, and the
    // userinfo strip must stay inside it: an `@` later in the URL
    // (`https://evil.test/@in-scope.host`) must not spoof the host.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_and_port = authority
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(authority);
    normalize_host(strip_port(host_and_port))
}

/// Put a hostname into the one form both scope patterns and candidate targets
/// are compared in: DNS is case-insensitive (RFC 4343) and the root label is
/// optional, so `ADMIN.Example.com.` and `admin.example.com` name one asset.
/// ASCII-only folding keeps IDN labels from being widened by Unicode case
/// folding. Harmless for IP literals: addresses carry no uppercase ASCII
/// letters beyond hex digits, which parse either way.
fn normalize_host(host: &str) -> String {
    trim_root_dot(host.trim()).to_ascii_lowercase()
}

/// Drop the optional DNS root label. A scope glob may spell that final dot as
/// an escaped `\.`; globset treats `.` as an ordinary character, so the escape
/// is redundant and both spellings name the same host. The escape has to leave
/// with its dot — a lone trailing `\` is a `DanglingEscape` that globset
/// refuses to compile, which would fail the whole scope file to load. Candidate
/// hosts carry no escapes, so for them this is a plain trailing-dot trim.
fn trim_root_dot(host: &str) -> &str {
    let mut rest = host;
    while let Some(head) = rest.strip_suffix('.') {
        rest = match escapes_the_root_dot(head) {
            true => &head[..head.len() - 1],
            false => head,
        };
    }
    rest
}

/// `true` when the text before a root dot ends in a backslash that escapes it.
/// An odd run of backslashes escapes the dot; an even run is literal
/// backslashes that the dot merely follows.
fn escapes_the_root_dot(head: &str) -> bool {
    (head.len() - head.trim_end_matches('\\').len()) % 2 == 1
}

fn strip_port(host: &str) -> &str {
    // Brackets denote IPv6 literals — `[::1]:8080` becomes `::1`.
    if let Some(bracket_end) = host.strip_prefix('[').and_then(|rest| rest.find(']')) {
        return &host[1..1 + bracket_end];
    }
    // A bare IPv6 literal is all colons and has no port to strip; splitting it
    // would leave a fragment that never matches a CIDR rule.
    if IpAddr::from_str(host).is_ok() {
        return host;
    }
    host.rsplit_once(':').map(|(host, _)| host).unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(toml_text: &str) -> ProgramScope {
        ProgramScope::parse(toml_text).expect("scope must parse")
    }

    #[test]
    fn empty_scope_returns_unknown_for_everything() {
        let scope = ProgramScope::default();
        assert!(scope.is_empty());
        assert_eq!(scope.verdict("example.com"), ScopeVerdict::Unknown);
        assert_eq!(scope.verdict("10.0.0.1"), ScopeVerdict::Unknown);
    }

    #[test]
    fn host_glob_matches_in_scope_subdomain() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("api.example.com"), ScopeVerdict::InScope);
        assert_eq!(scope.verdict("evil.com"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn deny_list_only_scope_allows_unknown_hosts() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("api.example.com"), ScopeVerdict::Unknown);
    }

    #[test]
    fn out_of_scope_overrides_in_scope() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("api.example.com"), ScopeVerdict::InScope);
    }

    #[test]
    fn cidr_matches_in_scope_address() {
        let scope = scope(
            r#"
            [in_scope]
            cidrs = ["10.0.0.0/8"]
            "#,
        );
        assert_eq!(scope.verdict("10.42.7.1"), ScopeVerdict::InScope);
        assert_eq!(scope.verdict("11.0.0.1"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn url_inputs_are_reduced_to_host_for_matching() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        assert_eq!(
            scope.verdict("https://api.example.com/path?q=1"),
            ScopeVerdict::InScope
        );
        assert_eq!(
            scope.verdict("http://user:pw@api.example.com:8443/"),
            ScopeVerdict::InScope
        );
    }

    #[test]
    fn at_sign_in_path_query_or_fragment_cannot_spoof_the_host() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        assert_eq!(
            scope.verdict("https://evil.test/@api.example.com"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(
            scope.verdict("https://evil.test/?next=user@api.example.com"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(
            scope.verdict("https://evil.test/#user@api.example.com"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn host_with_port_strips_port_before_matching() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["api.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("api.example.com:8080"), ScopeVerdict::InScope);
    }

    #[test]
    fn ipv6_literal_strips_brackets_and_port() {
        let scope = scope(
            r#"
            [in_scope]
            cidrs = ["::1/128"]
            "#,
        );
        assert_eq!(scope.verdict("[::1]:8080"), ScopeVerdict::InScope);
    }

    #[test]
    fn bare_ipv6_literal_is_matched_against_cidr_rules() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["2001:db8::/32"]
            "#,
        );
        assert_eq!(scope.verdict("2001:db8::1"), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("https://[2001:db8::1]:8443/"),
            ScopeVerdict::OutOfScope
        );
        assert_eq!(scope.verdict("2001:dead::1"), ScopeVerdict::Unknown);
    }

    #[test]
    fn ipv4_mapped_ipv6_literal_does_not_evade_a_deny_cidr() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["10.99.0.0/16"]
            "#,
        );
        assert_eq!(scope.verdict("10.99.0.1"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("::ffff:10.99.0.1"), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("https://[::ffff:10.99.0.1]:8443/panel"),
            ScopeVerdict::OutOfScope
        );
        // Uppercase hex names the same address, and the host is normalized
        // before it is parsed.
        assert_eq!(scope.verdict("::FFFF:10.99.0.1"), ScopeVerdict::OutOfScope);
        assert_eq!(scope.verdict("::ffff:10.98.0.1"), ScopeVerdict::Unknown);
    }

    #[test]
    fn ipv4_mapped_ipv6_literal_matches_an_allow_cidr() {
        let scope = scope(
            r#"
            [in_scope]
            cidrs = ["10.0.0.0/8"]
            "#,
        );
        assert_eq!(scope.verdict("::ffff:10.42.7.1"), ScopeVerdict::InScope);
        assert_eq!(scope.verdict("::ffff:11.0.0.1"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn a_cidr_rule_written_in_the_mapped_range_still_matches() {
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["::ffff:10.99.0.0/112"]
            "#,
        );
        assert_eq!(scope.verdict("::ffff:10.99.0.1"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn a_non_mapped_ipv6_literal_is_not_read_as_an_ipv4_address() {
        // `::10.0.0.1` is the retired IPv4-compatible form and `::1` embeds no
        // IPv4 host at all. Neither may borrow an IPv4 rule's verdict.
        let scope = scope(
            r#"
            [out_of_scope]
            cidrs = ["10.0.0.0/8"]
            "#,
        );
        assert_eq!(scope.verdict("::10.0.0.1"), ScopeVerdict::Unknown);
        assert_eq!(scope.verdict("::1"), ScopeVerdict::Unknown);
    }

    #[test]
    fn host_case_does_not_evade_a_deny_rule() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("ADMIN.example.com"), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("https://Admin.Example.COM/panel"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn deny_rule_written_in_uppercase_still_matches() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["Admin.Example.COM"]
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com"), ScopeVerdict::OutOfScope);
    }

    #[test]
    fn trailing_root_dot_does_not_evade_a_deny_rule() {
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ["admin.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com."), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("https://admin.example.com.:8443/"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn case_and_root_dot_normalize_allow_list_matches_too() {
        let scope = scope(
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        );
        assert_eq!(scope.verdict("API.Example.com."), ScopeVerdict::InScope);
    }

    #[test]
    fn a_rule_that_escapes_its_root_dot_still_loads_and_denies_the_host() {
        // globset rejects a dangling `\`, so dropping the dot without its
        // redundant escape would fail the whole scope file to load.
        let scope = scope(
            r#"
            [out_of_scope]
            hosts = ['admin.example.com\.']
            "#,
        );
        assert_eq!(scope.verdict("admin.example.com"), ScopeVerdict::OutOfScope);
        assert_eq!(
            scope.verdict("ADMIN.example.com."),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn trim_root_dot_removes_root_labels_without_corrupting_escapes() {
        assert_eq!(trim_root_dot("admin.example.com"), "admin.example.com");
        assert_eq!(trim_root_dot("admin.example.com."), "admin.example.com");
        assert_eq!(trim_root_dot("admin.example.com.."), "admin.example.com");
        // An odd run of backslashes escapes the dot: both leave together.
        assert_eq!(trim_root_dot(r"admin.example.com\."), "admin.example.com");
        // An even run is literal backslashes the dot merely follows.
        assert_eq!(trim_root_dot(r"admin.example.com\\."), r"admin.example.com\\");
        assert_eq!(trim_root_dot("."), "");
    }

    #[test]
    fn malformed_cidr_fails_to_load() {
        let err = ProgramScope::parse(
            r#"
            [in_scope]
            cidrs = ["not-a-cidr"]
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("invalid cidr"));
    }
}
