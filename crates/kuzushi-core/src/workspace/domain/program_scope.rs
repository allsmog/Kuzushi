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
/// [`ProgramScope::verdict`] before dispatch so out-of-scope assets are
/// refused with an actionable message.
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
    /// Target matches neither list. Callers warn but do not refuse.
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

    /// `false` when the host is explicitly out-of-scope. InScope and
    /// Unknown both return `true`. Used by per-entry import gates
    /// (M2 §2.2 / §2.3) so each amass/httpx/nuclei/nmap-xml/HAR/Burp
    /// entry is checked individually — `recon:import` does not carry
    /// a top-level target field, so the dispatch-level scope guard is
    /// not sufficient.
    pub fn host_allowed(&self, target: &str) -> bool {
        self.verdict(target) != ScopeVerdict::OutOfScope
    }

    /// Validate a candidate target — host, IP, or URL — against the
    /// active scope. Out-of-scope wins over in-scope so deny rules
    /// dominate. Returns [`ScopeVerdict::Unknown`] when the scope is
    /// empty or the target matches nothing.
    pub fn verdict(&self, target: &str) -> ScopeVerdict {
        let host = extract_host(target);
        if self.is_empty() {
            return ScopeVerdict::Unknown;
        }
        if matches_any(&self.out_of_scope, &host) {
            return ScopeVerdict::OutOfScope;
        }
        if matches_any(&self.in_scope, &host) {
            return ScopeVerdict::InScope;
        }
        ScopeVerdict::Unknown
    }
}

fn compile_patterns(list: &ProgramScopeList) -> Result<Vec<HostPattern>> {
    let mut compiled = Vec::with_capacity(list.hosts.len() + list.cidrs.len());
    for raw in &list.hosts {
        let glob = Glob::new(raw)
            .with_context(|| format!("invalid host glob in scope.toml: {raw}"))?;
        compiled.push(HostPattern::HostGlob(glob));
    }
    for raw in &list.cidrs {
        let cidr = IpNet::from_str(raw)
            .with_context(|| format!("invalid cidr in scope.toml: {raw}"))?;
        compiled.push(HostPattern::Cidr(cidr));
    }
    Ok(compiled)
}

fn matches_any(patterns: &[HostPattern], host: &str) -> bool {
    patterns.iter().any(|pattern| matches_pattern(pattern, host))
}

fn matches_pattern(pattern: &HostPattern, host: &str) -> bool {
    match pattern {
        HostPattern::HostGlob(glob) => glob.compile_matcher().is_match(host),
        HostPattern::Cidr(cidr) => match IpAddr::from_str(host) {
            Ok(addr) => cidr.contains(&addr),
            Err(_) => false,
        },
    }
}

/// Pull the host component out of a free-form target string. Accepts
/// raw hosts, IP literals, `host:port`, and URLs with schemes. Falls
/// back to the trimmed input so unknown formats still get a chance to
/// match host globs.
fn extract_host(target: &str) -> String {
    let trimmed = target.trim();
    let after_scheme = trimmed.split_once("://").map(|(_, rest)| rest).unwrap_or(trimmed);
    let after_userinfo = after_scheme
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(after_scheme);
    let host_and_rest = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);
    strip_port(host_and_rest).to_string()
}

fn strip_port(host: &str) -> &str {
    // Brackets denote IPv6 literals — `[::1]:8080` becomes `::1`.
    if let Some(bracket_end) = host.strip_prefix('[').and_then(|rest| rest.find(']')) {
        return &host[1..1 + bracket_end];
    }
    host.rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(host)
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
        assert_eq!(scope.verdict("evil.com"), ScopeVerdict::Unknown);
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
        assert_eq!(scope.verdict("11.0.0.1"), ScopeVerdict::Unknown);
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
