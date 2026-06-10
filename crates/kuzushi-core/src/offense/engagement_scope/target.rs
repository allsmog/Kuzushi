//! The thing a play wants to operate against: an IP or a hostname.

use std::fmt;
use std::net::IpAddr;

/// A resolved target host. A play turns its target string (`10.0.0.5`,
/// `box.htb`, `app.staging.example.com`) into one of these before asking the
/// scope gate. Hostnames are not resolved here — scope matching is on the
/// declared identity, not on whatever DNS happens to return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeTarget {
    Ip(IpAddr),
    Host(String),
}

impl ScopeTarget {
    /// Parse a target host. A literal IP becomes [`ScopeTarget::Ip`];
    /// anything else is treated as a (lowercased) hostname.
    pub fn parse(raw: &str) -> Self {
        let trimmed = raw.trim().trim_end_matches('.');
        match trimmed.parse::<IpAddr>() {
            Ok(ip) => ScopeTarget::Ip(ip),
            Err(_) => ScopeTarget::Host(trimmed.to_ascii_lowercase()),
        }
    }
}

impl fmt::Display for ScopeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeTarget::Ip(ip) => write!(f, "{ip}"),
            ScopeTarget::Host(host) => write!(f, "{host}"),
        }
    }
}
