use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NmapParseResult {
    pub(crate) hosts: Vec<NmapHost>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NmapHost {
    pub(crate) address: String,
    pub(crate) hostname: Option<String>,
    pub(crate) services: Vec<NmapService>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NmapService {
    pub(crate) port: u16,
    pub(crate) proto: String,
    pub(crate) state: String,
    pub(crate) name: Option<String>,
    pub(crate) banner: Option<String>,
}

pub(crate) fn parse_nmap_grepable(stdout: &str) -> Result<NmapParseResult> {
    let mut hosts = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with("Host:") || !line.contains("Ports:") {
            continue;
        }
        let after_host = line.trim_start_matches("Host:").trim();
        let (host_part, rest) = after_host
            .split_once("Ports:")
            .context("recon:nmap could not parse nmap grepable host line")?;
        let address = host_part
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if address.is_empty() {
            continue;
        }
        let hostname = host_part
            .split_once('(')
            .and_then(|(_, tail)| tail.split_once(')').map(|(name, _)| name.trim()))
            .filter(|name| !name.is_empty())
            .map(ToString::to_string);
        let ports_part = rest.split('\t').next().unwrap_or(rest);
        let mut services = Vec::new();
        for raw_service in ports_part.split(',') {
            let fields = raw_service.trim().split('/').collect::<Vec<_>>();
            if fields.len() < 3 {
                continue;
            }
            if fields.get(1).map(|value| value.trim()) != Some("open") {
                continue;
            }
            let Some(port) = fields
                .first()
                .and_then(|value| value.trim().parse::<u16>().ok())
            else {
                continue;
            };
            let proto = fields
                .get(2)
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or("tcp")
                .to_string();
            let name = fields
                .get(4)
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);
            let banner = fields
                .get(6)
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(ToString::to_string);
            services.push(NmapService {
                port,
                proto,
                state: "open".to_string(),
                name,
                banner,
            });
        }
        hosts.push(NmapHost {
            address,
            hostname,
            services,
        });
    }
    Ok(NmapParseResult { hosts })
}

pub(crate) fn parse_crtsh_subdomains(stdout: &str, domain: &str) -> Result<Vec<String>> {
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value: Value = serde_json::from_str(stdout)
        .context("recon:subdomain could not parse crt.sh JSON output")?;
    let mut domains = BTreeSet::new();
    for item in value.as_array().into_iter().flatten() {
        if let Some(name_value) = item.get("name_value").and_then(Value::as_str) {
            for candidate in name_value.lines() {
                if let Some(host) = normalize_subdomain(candidate, domain) {
                    domains.insert(host);
                }
            }
        }
    }
    Ok(domains.into_iter().collect())
}
