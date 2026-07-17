//! One allowlist / exclusion entry: an exact IP, a CIDR range, or a hostname.

use super::ScopeTarget;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A scope entry, declared as a string: `10.0.0.5`, `10.0.0.0/24`,
/// `2001:db8::/32`, `box.htb`, or `*.staging.example.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEntry {
    Ip(IpAddr),
    Cidr {
        base: IpAddr,
        prefix: u8,
    },
    /// Hostname; a bare host matches itself and its subdomains, a `*.suffix`
    /// host matches subdomains only.
    Host(String),
}

impl ScopeEntry {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let value = raw.trim();
        if value.is_empty() {
            return Err("scope entry is empty".to_string());
        }
        if let Some((addr, prefix)) = value.split_once('/') {
            return parse_cidr(addr.trim(), prefix.trim());
        }
        match value.parse::<IpAddr>() {
            Ok(ip) => Ok(ScopeEntry::Ip(ip)),
            Err(_) => Ok(ScopeEntry::Host(
                value.trim_end_matches('.').to_ascii_lowercase(),
            )),
        }
    }

    pub fn matches(&self, target: &ScopeTarget) -> bool {
        match (self, target) {
            (ScopeEntry::Ip(entry), ScopeTarget::Ip(addr)) => entry == addr,
            (ScopeEntry::Cidr { base, prefix }, ScopeTarget::Ip(addr)) => {
                cidr_contains(*base, *prefix, *addr)
            }
            (ScopeEntry::Host(entry), ScopeTarget::Host(host)) => host_matches(entry, host),
            _ => false,
        }
    }

    fn to_token(&self) -> String {
        match self {
            ScopeEntry::Ip(ip) => ip.to_string(),
            ScopeEntry::Cidr { base, prefix } => format!("{base}/{prefix}"),
            ScopeEntry::Host(host) => host.clone(),
        }
    }
}

fn parse_cidr(addr: &str, prefix: &str) -> Result<ScopeEntry, String> {
    let base: IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid CIDR address {addr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("invalid CIDR prefix {prefix:?}"))?;
    let max = if base.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("CIDR prefix /{prefix} exceeds /{max}"));
    }
    Ok(ScopeEntry::Cidr { base, prefix })
}

/// A bare host (`example.com`) matches itself and any subdomain. A wildcard
/// host (`*.example.com`) matches subdomains only.
fn host_matches(entry: &str, host: &str) -> bool {
    if let Some(suffix) = entry.strip_prefix("*.") {
        return host_has_suffix(host, suffix);
    }
    host == entry || host_has_suffix(host, entry)
}

fn host_has_suffix(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

fn cidr_contains(base: IpAddr, prefix: u8, addr: IpAddr) -> bool {
    match (base, addr) {
        (IpAddr::V4(base), IpAddr::V4(addr)) => v4_in_cidr(base, prefix, addr),
        (IpAddr::V6(base), IpAddr::V6(addr)) => v6_in_cidr(base, prefix, addr),
        _ => false,
    }
}

fn v4_in_cidr(base: Ipv4Addr, prefix: u8, addr: Ipv4Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    (u32::from(addr) & mask) == (u32::from(base) & mask)
}

fn v6_in_cidr(base: Ipv6Addr, prefix: u8, addr: Ipv6Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - u32::from(prefix));
    (u128::from(addr) & mask) == (u128::from(base) & mask)
}

impl Serialize for ScopeEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_token())
    }
}

impl<'de> Deserialize<'de> for ScopeEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        ScopeEntry::parse(&raw).map_err(serde::de::Error::custom)
    }
}
