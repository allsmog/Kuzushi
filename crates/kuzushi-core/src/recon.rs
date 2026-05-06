use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::modules::ToolExecutionContext;
use crate::scan::ScanCancellation;
use crate::workspace::WorkspaceTarget;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReconHost {
    pub id: String,
    pub workspace_id: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReconService {
    pub id: String,
    pub host_id: String,
    pub port: u16,
    pub proto: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReconNote {
    pub id: String,
    pub workspace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    pub ntype: String,
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ReconPersisted {
    workspace_id: String,
    db: String,
    host_count: usize,
    service_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ReconReport {
    tool: String,
    target: String,
    hosts: Vec<ReconHost>,
    services: Vec<ReconService>,
    notes: Vec<ReconNote>,
    persisted: ReconPersisted,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subdomains: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    fingerprint: BTreeMap<String, Value>,
}

impl ReconReport {
    fn output(&self) -> String {
        match self.tool.as_str() {
            "recon:nmap" => format!(
                "recon:nmap discovered {} host{} and {} open service{} for {}",
                self.hosts.len(),
                plural(self.hosts.len()),
                self.services.len(),
                plural(self.services.len()),
                self.target
            ),
            "recon:subdomain" => format!(
                "recon:subdomain discovered {} subdomain{} for {}",
                self.subdomains.len(),
                plural(self.subdomains.len()),
                self.target
            ),
            "recon:http-fingerprint" => {
                let service = self
                    .services
                    .first()
                    .map(|service| {
                        format!(
                            "{}:{}",
                            service.name.as_deref().unwrap_or("http"),
                            service.port
                        )
                    })
                    .unwrap_or_else(|| "http".to_string());
                format!(
                    "recon:http-fingerprint registered {} as {service}",
                    self.target
                )
            }
            _ => format!("{} completed for {}", self.tool, self.target),
        }
    }

    fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
        })
    }
}

pub fn execute_recon_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    match name {
        "recon:nmap" => {
            Ok(run_recon_nmap(&input, ctx, &ScanCancellation::default())?.to_tool_json())
        }
        "recon:subdomain" => {
            Ok(run_recon_subdomain(&input, ctx, &ScanCancellation::default())?.to_tool_json())
        }
        "recon:http-fingerprint" => {
            Ok(
                run_recon_http_fingerprint(&input, ctx, &ScanCancellation::default())?
                    .to_tool_json(),
            )
        }
        other => anyhow::bail!("unknown recon tool {other:?}"),
    }
}

fn run_recon_nmap(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:nmap needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let options = NmapInput::from_tool_input(input)?;
    let scan = ReconNmapScanner::from_input(&options);
    let parsed = scan.scan(cancel)?;
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;

    let mut hosts = Vec::new();
    let mut services = Vec::new();
    for discovered_host in parsed.hosts {
        let host = store.upsert_host(
            &workspace_id,
            &discovered_host.address,
            discovered_host.hostname.as_deref(),
            "alive",
            json!({
                "discoveredBy": "recon:nmap",
                "discoveredAt": now_isoish(),
                "target": options.target,
                "ports": options.ports,
            }),
        )?;
        for discovered_service in discovered_host.services {
            let service = store.upsert_service(
                &host.id,
                discovered_service.port,
                &discovered_service.proto,
                discovered_service.name.as_deref(),
                discovered_service.banner.as_deref(),
                &discovered_service.state,
                json!({
                    "discoveredBy": "recon:nmap",
                    "target": options.target,
                    "ports": options.ports,
                }),
            )?;
            services.push(service);
        }
        hosts.push(host);
    }

    let note = store.create_note(
        &workspace_id,
        None,
        None,
        "recon:nmap",
        json!({
            "target": options.target,
            "ports": options.ports,
            "hosts": hosts.len(),
            "services": services.len(),
        }),
    )?;

    Ok(ReconReport {
        tool: "recon:nmap".to_string(),
        target: options.target,
        hosts,
        services,
        notes: vec![note],
        persisted: ReconPersisted {
            workspace_id,
            db: workspace.findings_db_path().display().to_string(),
            host_count: store.count_hosts()?,
            service_count: store.count_services()?,
        },
        subdomains: Vec::new(),
        fingerprint: BTreeMap::new(),
    })
}

fn run_recon_subdomain(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:subdomain needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let options = SubdomainInput::from_tool_input(input)?;
    let enumerator = ReconSubdomainEnumerator::from_input(&options);
    let subdomains = enumerator.enumerate(cancel)?;
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;

    let mut hosts = Vec::new();
    for subdomain in &subdomains {
        hosts.push(store.upsert_host(
            &workspace_id,
            subdomain,
            Some(subdomain),
            "alive",
            json!({
                "discoveredBy": "recon:subdomain",
                "discoveredAt": now_isoish(),
                "domain": options.domain,
                "source": options.source.as_str(),
            }),
        )?);
    }
    let note = store.create_note(
        &workspace_id,
        None,
        None,
        "recon:subdomain",
        json!({
            "domain": options.domain,
            "source": options.source.as_str(),
            "count": subdomains.len(),
            "subdomains": subdomains,
        }),
    )?;

    Ok(ReconReport {
        tool: "recon:subdomain".to_string(),
        target: options.domain,
        hosts,
        services: Vec::new(),
        notes: vec![note],
        persisted: ReconPersisted {
            workspace_id,
            db: workspace.findings_db_path().display().to_string(),
            host_count: store.count_hosts()?,
            service_count: store.count_services()?,
        },
        subdomains,
        fingerprint: BTreeMap::new(),
    })
}

fn run_recon_http_fingerprint(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    cancel: &ScanCancellation,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:http-fingerprint needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let options = HttpFingerprintInput::from_tool_input(input)?;
    let fingerprinter = ReconHttpFingerprinter::from_input(&options);
    let fingerprint = fingerprinter.fingerprint(cancel)?;
    let endpoint = split_host_port(&options.target);
    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;
    let host = store.upsert_host(
        &workspace_id,
        &endpoint.host,
        Some(&endpoint.host),
        "alive",
        json!({
            "discoveredBy": "recon:http-fingerprint",
            "discoveredAt": now_isoish(),
        }),
    )?;
    let service = store.upsert_service(
        &host.id,
        endpoint.port,
        "tcp",
        Some(if endpoint.port == 443 {
            "https"
        } else {
            "http"
        }),
        fingerprint.server.as_deref(),
        "open",
        json!({
            "discoveredBy": "recon:http-fingerprint",
            "status": fingerprint.status,
            "headers": fingerprint.headers,
            "technologies": fingerprint.technologies,
            "title": fingerprint.title,
        }),
    )?;
    let mut fingerprint_data = BTreeMap::new();
    fingerprint_data.insert("status".to_string(), json!(fingerprint.status));
    fingerprint_data.insert("headers".to_string(), json!(fingerprint.headers));
    fingerprint_data.insert("technologies".to_string(), json!(fingerprint.technologies));
    if let Some(server) = &fingerprint.server {
        fingerprint_data.insert("server".to_string(), json!(server));
    }
    if let Some(title) = &fingerprint.title {
        fingerprint_data.insert("title".to_string(), json!(title));
    }
    let note = store.create_note(
        &workspace_id,
        Some(&host.id),
        Some(&service.id),
        "recon:http-fingerprint",
        json!({
            "target": options.target,
            "status": fingerprint.status,
            "server": fingerprint.server,
            "title": fingerprint.title,
            "technologies": fingerprint.technologies,
        }),
    )?;

    Ok(ReconReport {
        tool: "recon:http-fingerprint".to_string(),
        target: options.target,
        hosts: vec![host],
        services: vec![service],
        notes: vec![note],
        persisted: ReconPersisted {
            workspace_id,
            db: workspace.findings_db_path().display().to_string(),
            host_count: store.count_hosts()?,
            service_count: store.count_services()?,
        },
        subdomains: Vec::new(),
        fingerprint: fingerprint_data,
    })
}

#[derive(Debug, Clone)]
struct NmapInput {
    target: String,
    ports: String,
    binary: String,
}

impl NmapInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        let target = required_string(input, "target", "recon:nmap requires a target.")?;
        Ok(Self {
            target,
            ports: optional_string(input, &["ports"])?.unwrap_or_else(|| "top100".to_string()),
            binary: optional_string(input, &["binary", "nmapBinary", "scannerBin"])?
                .unwrap_or_else(|| "nmap".to_string()),
        })
    }
}

#[derive(Debug, Clone)]
struct ReconNmapScanner {
    target: String,
    ports: String,
    binary: String,
}

impl ReconNmapScanner {
    fn from_input(input: &NmapInput) -> Self {
        Self {
            target: input.target.clone(),
            ports: input.ports.clone(),
            binary: input.binary.clone(),
        }
    }

    fn scan(&self, cancel: &ScanCancellation) -> Result<NmapParseResult> {
        let mut args = vec!["-oG".to_string(), "-".to_string()];
        match self.ports.trim() {
            "" => {}
            "top100" => {
                args.push("--top-ports".to_string());
                args.push("100".to_string());
            }
            "top1000" => {
                args.push("--top-ports".to_string());
                args.push("1000".to_string());
            }
            ports => {
                args.push("-p".to_string());
                args.push(ports.to_string());
            }
        }
        args.push(self.target.clone());

        let output = run_subprocess(
            "recon:nmap",
            &self.binary,
            &args,
            None,
            cancel,
            "Install nmap first (`brew install nmap`, `apt install nmap`) or pass {\"binary\":\"/path/to/nmap\"}.",
        )?;
        let stdout =
            String::from_utf8(output.stdout).context("recon:nmap emitted non-UTF8 output")?;
        parse_nmap_grepable(&stdout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubdomainSource {
    Crtsh,
    Wayback,
    Both,
}

impl SubdomainSource {
    fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "crtsh" => Ok(Self::Crtsh),
            "wayback" => Ok(Self::Wayback),
            "both" | "" => Ok(Self::Both),
            other => anyhow::bail!(
                "recon:subdomain source must be one of crtsh, wayback, or both; got {other:?}"
            ),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Crtsh => "crtsh",
            Self::Wayback => "wayback",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone)]
struct SubdomainInput {
    domain: String,
    source: SubdomainSource,
    binary: String,
    timeout_seconds: u64,
}

impl SubdomainInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            domain: required_string(input, "domain", "recon:subdomain requires a domain.")?,
            source: SubdomainSource::parse(
                optional_string(input, &["source"])?
                    .unwrap_or_else(|| "both".to_string())
                    .as_str(),
            )?,
            binary: optional_string(input, &["binary", "curlBinary", "scannerBin"])?
                .unwrap_or_else(|| "curl".to_string()),
            timeout_seconds: optional_u64(input, &["timeoutSeconds", "timeout_seconds"])?
                .unwrap_or(20),
        })
    }
}

#[derive(Debug, Clone)]
struct ReconSubdomainEnumerator {
    domain: String,
    source: SubdomainSource,
    binary: String,
    timeout_seconds: u64,
}

impl ReconSubdomainEnumerator {
    fn from_input(input: &SubdomainInput) -> Self {
        Self {
            domain: input.domain.clone(),
            source: input.source,
            binary: input.binary.clone(),
            timeout_seconds: input.timeout_seconds,
        }
    }

    fn enumerate(&self, cancel: &ScanCancellation) -> Result<Vec<String>> {
        let mut subdomains = BTreeSet::new();
        if matches!(self.source, SubdomainSource::Crtsh | SubdomainSource::Both) {
            for value in self.fetch_crtsh(cancel)? {
                subdomains.insert(value);
            }
        }
        if matches!(
            self.source,
            SubdomainSource::Wayback | SubdomainSource::Both
        ) {
            for value in self.fetch_wayback(cancel)? {
                subdomains.insert(value);
            }
        }
        Ok(subdomains.into_iter().collect())
    }

    fn fetch_crtsh(&self, cancel: &ScanCancellation) -> Result<Vec<String>> {
        let url = format!("https://crt.sh/?q=%25.{}&output=json", self.domain);
        let stdout = self.run_curl(&url, cancel)?;
        parse_crtsh_subdomains(&stdout, &self.domain)
    }

    fn fetch_wayback(&self, cancel: &ScanCancellation) -> Result<Vec<String>> {
        let url = format!(
            "https://web.archive.org/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey",
            self.domain
        );
        let stdout = self.run_curl(&url, cancel)?;
        parse_wayback_subdomains(&stdout, &self.domain)
    }

    fn run_curl(&self, url: &str, cancel: &ScanCancellation) -> Result<String> {
        let args = vec![
            "-fsSL".to_string(),
            "--max-time".to_string(),
            self.timeout_seconds.to_string(),
            url.to_string(),
        ];
        let output = run_subprocess(
            "recon:subdomain",
            &self.binary,
            &args,
            None,
            cancel,
            "Install curl or pass {\"binary\":\"/path/to/curl\"}.",
        )?;
        String::from_utf8(output.stdout).context("recon:subdomain source emitted non-UTF8 output")
    }
}

#[derive(Debug, Clone)]
struct HttpFingerprintInput {
    target: String,
    binary: String,
    timeout_seconds: u64,
}

impl HttpFingerprintInput {
    fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            target: required_string(input, "target", "recon:http-fingerprint requires a target.")?,
            binary: optional_string(input, &["binary", "curlBinary", "scannerBin"])?
                .unwrap_or_else(|| "curl".to_string()),
            timeout_seconds: optional_u64(input, &["timeoutSeconds", "timeout_seconds"])?
                .unwrap_or(10),
        })
    }
}

#[derive(Debug, Clone)]
struct ReconHttpFingerprinter {
    target: String,
    binary: String,
    timeout_seconds: u64,
}

impl ReconHttpFingerprinter {
    fn from_input(input: &HttpFingerprintInput) -> Self {
        Self {
            target: input.target.clone(),
            binary: input.binary.clone(),
            timeout_seconds: input.timeout_seconds,
        }
    }

    fn fingerprint(&self, cancel: &ScanCancellation) -> Result<HttpFingerprint> {
        let target = ensure_http_scheme(&self.target);
        let args = vec![
            "-i".to_string(),
            "-L".to_string(),
            "-sS".to_string(),
            "--max-time".to_string(),
            self.timeout_seconds.to_string(),
            target,
        ];
        let output = run_subprocess(
            "recon:http-fingerprint",
            &self.binary,
            &args,
            None,
            cancel,
            "Install curl or pass {\"binary\":\"/path/to/curl\"}.",
        )?;
        let stdout = String::from_utf8(output.stdout)
            .context("recon:http-fingerprint emitted non-UTF8 output")?;
        parse_http_fingerprint(&stdout)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NmapParseResult {
    hosts: Vec<NmapHost>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NmapHost {
    address: String,
    hostname: Option<String>,
    services: Vec<NmapService>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NmapService {
    port: u16,
    proto: String,
    state: String,
    name: Option<String>,
    banner: Option<String>,
}

fn parse_nmap_grepable(stdout: &str) -> Result<NmapParseResult> {
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

fn parse_crtsh_subdomains(stdout: &str, domain: &str) -> Result<Vec<String>> {
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

fn parse_wayback_subdomains(stdout: &str, domain: &str) -> Result<Vec<String>> {
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut domains = BTreeSet::new();
    if let Ok(value) = serde_json::from_str::<Value>(stdout) {
        if let Some(rows) = value.as_array() {
            for row in rows {
                if let Some(url) = row.as_str().or_else(|| {
                    row.as_array()
                        .and_then(|values| values.first())
                        .and_then(Value::as_str)
                }) {
                    if url.eq_ignore_ascii_case("original") {
                        continue;
                    }
                    if let Some(host) =
                        host_from_url(url).and_then(|host| normalize_subdomain(&host, domain))
                    {
                        domains.insert(host);
                    }
                }
            }
            return Ok(domains.into_iter().collect());
        }
    }

    for line in stdout.lines() {
        if let Some(host) = host_from_url(line).and_then(|host| normalize_subdomain(&host, domain))
        {
            domains.insert(host);
        }
    }
    Ok(domains.into_iter().collect())
}

#[derive(Debug, Clone, PartialEq)]
struct HttpFingerprint {
    status: Option<u16>,
    headers: BTreeMap<String, String>,
    server: Option<String>,
    title: Option<String>,
    technologies: Vec<String>,
}

fn parse_http_fingerprint(stdout: &str) -> Result<HttpFingerprint> {
    let (headers_raw, body) = split_last_http_response(stdout);
    let mut status = None;
    let mut headers = BTreeMap::new();
    for line in headers_raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("HTTP/") {
            status = trimmed
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u16>().ok());
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if !key.is_empty() {
                headers.insert(key, value);
            }
        }
    }
    let server = headers.get("server").cloned();
    let title = extract_html_title(body);
    let technologies = infer_http_technologies(&headers, body);
    Ok(HttpFingerprint {
        status,
        headers,
        server,
        title,
        technologies,
    })
}

fn split_last_http_response(stdout: &str) -> (&str, &str) {
    let marker = "\r\n\r\n";
    let normalized_marker = "\n\n";
    if let Some((headers, body)) = stdout.rsplit_once(marker) {
        return (last_http_header_block(headers), body);
    }
    if let Some((headers, body)) = stdout.rsplit_once(normalized_marker) {
        return (last_http_header_block(headers), body);
    }
    (stdout, "")
}

fn last_http_header_block(headers: &str) -> &str {
    headers
        .rsplit("\r\n\r\n")
        .next()
        .unwrap_or(headers)
        .rsplit("\n\n")
        .next()
        .unwrap_or(headers)
}

fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title>")?;
    let end = lower[start + 7..].find("</title>")? + start + 7;
    Some(body[start + 7..end].trim().to_string()).filter(|title| !title.is_empty())
}

fn infer_http_technologies(headers: &BTreeMap<String, String>, body: &str) -> Vec<String> {
    let mut tech = BTreeSet::new();
    if let Some(server) = headers.get("server") {
        let lower = server.to_ascii_lowercase();
        for (needle, label) in [
            ("nginx", "nginx"),
            ("apache", "apache"),
            ("cloudflare", "cloudflare"),
            ("express", "express"),
        ] {
            if lower.contains(needle) {
                tech.insert(label.to_string());
            }
        }
    }
    if let Some(powered_by) = headers.get("x-powered-by") {
        tech.insert(powered_by.trim().to_string());
    }
    let body_lower = body.to_ascii_lowercase();
    for (needle, label) in [
        ("wp-content", "wordpress"),
        ("_next/static", "next.js"),
        ("data-reactroot", "react"),
        ("<meta name=\"generator\" content=\"hugo", "hugo"),
    ] {
        if body_lower.contains(needle) {
            tech.insert(label.to_string());
        }
    }
    tech.into_iter().collect()
}

pub struct ReconWorkspaceStore {
    conn: Connection,
    db_path: String,
}

impl ReconWorkspaceStore {
    pub fn open(workspace: &WorkspaceTarget) -> Result<Self> {
        workspace.ensure_state_dir()?;
        let db_path = workspace.findings_db_path();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        let conn = Connection::open(&db_path)
            .with_context(|| format!("Could not open {}", db_path.display()))?;
        let store = Self {
            conn,
            db_path: db_path.display().to_string(),
        };
        store.init()?;
        Ok(store)
    }

    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            pragma foreign_keys = on;

            create table if not exists workspaces (
              id text primary key,
              name text not null unique,
              targets_json text not null default '[]',
              created_at text not null,
              last_accessed_at text not null,
              metadata_json text not null default '{}',
              updated_at text not null default (datetime('now'))
            );

            create table if not exists hosts (
              id text primary key,
              workspace_id text not null references workspaces(id) on delete cascade,
              address text not null,
              hostname text,
              os_name text,
              os_flavor text,
              os_version text,
              arch text,
              purpose text,
              state text not null default 'alive' check (state in ('alive','down','unknown')),
              comm text,
              metadata_json text not null default '{}',
              created_at text not null default (datetime('now')),
              updated_at text not null default (datetime('now')),
              unique(workspace_id, address)
            );
            create index if not exists idx_hosts_workspace on hosts(workspace_id);

            create table if not exists services (
              id text primary key,
              host_id text not null references hosts(id) on delete cascade,
              port integer not null check (port >= 0 and port <= 65535),
              proto text not null default 'tcp' check (proto in ('tcp','udp','icmp','sctp')),
              name text,
              banner text,
              state text not null default 'open' check (state in ('open','closed','filtered','unknown')),
              info_json text not null default '{}',
              created_at text not null default (datetime('now')),
              updated_at text not null default (datetime('now')),
              unique(host_id, port, proto)
            );
            create index if not exists idx_services_host on services(host_id);

            create table if not exists notes (
              id text primary key,
              workspace_id text not null references workspaces(id) on delete cascade,
              host_id text references hosts(id) on delete set null,
              service_id text references services(id) on delete set null,
              ntype text not null,
              data_json text not null default '{}',
              created_at text not null default (datetime('now'))
            );
            create index if not exists idx_notes_workspace on notes(workspace_id);
            "#,
        )?;
        Ok(())
    }

    pub fn ensure_default_workspace(&mut self, target: &Path) -> Result<String> {
        if let Some(id) = self
            .conn
            .query_row(
                "select id from workspaces where name = ?1",
                params!["default"],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            self.conn.execute(
                "update workspaces set last_accessed_at = ?2, updated_at = datetime('now') where id = ?1",
                params![id, now_isoish()],
            )?;
            return Ok(id);
        }
        let id = Uuid::new_v4().to_string();
        let now = now_isoish();
        self.conn.execute(
            r#"
            insert into workspaces(id, name, targets_json, created_at, last_accessed_at, metadata_json)
            values (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                id,
                "default",
                json!([target.display().to_string()]).to_string(),
                now,
                now,
                "{}",
            ],
        )?;
        Ok(id)
    }

    pub fn upsert_host(
        &self,
        workspace_id: &str,
        address: &str,
        hostname: Option<&str>,
        state: &str,
        metadata: Value,
    ) -> Result<ReconHost> {
        let id = self
            .conn
            .query_row(
                "select id from hosts where workspace_id = ?1 and address = ?2",
                params![workspace_id, address],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        self.conn.execute(
            r#"
            insert into hosts(id, workspace_id, address, hostname, state, metadata_json)
            values (?1, ?2, ?3, ?4, ?5, ?6)
            on conflict(workspace_id, address) do update set
              hostname = excluded.hostname,
              state = excluded.state,
              metadata_json = excluded.metadata_json,
              updated_at = datetime('now')
            "#,
            params![
                id,
                workspace_id,
                address,
                hostname,
                state,
                metadata.to_string()
            ],
        )?;
        self.get_host(&id)
    }

    pub fn upsert_service(
        &self,
        host_id: &str,
        port: u16,
        proto: &str,
        name: Option<&str>,
        banner: Option<&str>,
        state: &str,
        info: Value,
    ) -> Result<ReconService> {
        let id = self
            .conn
            .query_row(
                "select id from services where host_id = ?1 and port = ?2 and proto = ?3",
                params![host_id, port as i64, proto],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        self.conn.execute(
            r#"
            insert into services(id, host_id, port, proto, name, banner, state, info_json)
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            on conflict(host_id, port, proto) do update set
              name = excluded.name,
              banner = excluded.banner,
              state = excluded.state,
              info_json = excluded.info_json,
              updated_at = datetime('now')
            "#,
            params![
                id,
                host_id,
                port as i64,
                proto,
                name,
                banner,
                state,
                info.to_string()
            ],
        )?;
        self.get_service(&id)
    }

    pub fn create_note(
        &self,
        workspace_id: &str,
        host_id: Option<&str>,
        service_id: Option<&str>,
        ntype: &str,
        data: Value,
    ) -> Result<ReconNote> {
        let id = Uuid::new_v4().to_string();
        self.conn.execute(
            r#"
            insert into notes(id, workspace_id, host_id, service_id, ntype, data_json)
            values (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                id,
                workspace_id,
                host_id,
                service_id,
                ntype,
                data.to_string()
            ],
        )?;
        self.get_note(&id)
    }

    pub fn list_hosts(&self, workspace_id: &str) -> Result<Vec<ReconHost>> {
        let mut stmt = self.conn.prepare(
            "select id, workspace_id, address, hostname, state from hosts where workspace_id = ?1 order by address",
        )?;
        let rows = stmt.query_map(params![workspace_id], row_to_host)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_services_for_host(&self, host_id: &str) -> Result<Vec<ReconService>> {
        let mut stmt = self.conn.prepare(
            "select id, host_id, port, proto, name, banner, state from services where host_id = ?1 order by port",
        )?;
        let rows = stmt.query_map(params![host_id], row_to_service)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn list_notes(&self, workspace_id: &str, ntype: Option<&str>) -> Result<Vec<ReconNote>> {
        let sql = if ntype.is_some() {
            "select id, workspace_id, host_id, service_id, ntype, data_json from notes where workspace_id = ?1 and ntype = ?2 order by created_at desc"
        } else {
            "select id, workspace_id, host_id, service_id, ntype, data_json from notes where workspace_id = ?1 order by created_at desc"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = if let Some(ntype) = ntype {
            stmt.query_map(params![workspace_id, ntype], row_to_note)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            stmt.query_map(params![workspace_id], row_to_note)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(rows)
    }

    fn get_host(&self, id: &str) -> Result<ReconHost> {
        self.conn
            .query_row(
                "select id, workspace_id, address, hostname, state from hosts where id = ?1",
                params![id],
                row_to_host,
            )
            .with_context(|| format!("recon could not load persisted host {id}"))
    }

    fn get_service(&self, id: &str) -> Result<ReconService> {
        self.conn
            .query_row(
                "select id, host_id, port, proto, name, banner, state from services where id = ?1",
                params![id],
                row_to_service,
            )
            .with_context(|| format!("recon could not load persisted service {id}"))
    }

    fn get_note(&self, id: &str) -> Result<ReconNote> {
        self.conn
            .query_row(
                "select id, workspace_id, host_id, service_id, ntype, data_json from notes where id = ?1",
                params![id],
                row_to_note,
            )
            .with_context(|| format!("recon could not load persisted note {id}"))
    }

    fn count_hosts(&self) -> Result<usize> {
        let count = self
            .conn
            .query_row("select count(*) from hosts", [], |row| row.get::<_, i64>(0))?;
        Ok(count as usize)
    }

    fn count_services(&self) -> Result<usize> {
        let count = self
            .conn
            .query_row("select count(*) from services", [], |row| {
                row.get::<_, i64>(0)
            })?;
        Ok(count as usize)
    }
}

fn row_to_host(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconHost> {
    Ok(ReconHost {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        address: row.get(2)?,
        hostname: row.get(3)?,
        state: row.get(4)?,
    })
}

fn row_to_service(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconService> {
    let port: i64 = row.get(2)?;
    Ok(ReconService {
        id: row.get(0)?,
        host_id: row.get(1)?,
        port: port as u16,
        proto: row.get(3)?,
        name: row.get(4)?,
        banner: row.get(5)?,
        state: row.get(6)?,
    })
}

fn row_to_note(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconNote> {
    let data_raw: String = row.get(5)?;
    Ok(ReconNote {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        host_id: row.get(2)?,
        service_id: row.get(3)?,
        ntype: row.get(4)?,
        data: serde_json::from_str(&data_raw).unwrap_or(Value::Null),
    })
}

#[derive(Debug)]
struct ProcessOutput {
    stdout: Vec<u8>,
}

fn run_subprocess(
    tool_name: &str,
    binary: &str,
    args: &[String],
    cwd: Option<&Path>,
    cancel: &ScanCancellation,
    install_hint: &str,
) -> Result<ProcessOutput> {
    if cancel.is_cancelled() {
        anyhow::bail!("{tool_name} cancelled");
    }

    let mut command = Command::new(binary);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "{tool_name}: could not find subprocess binary {:?}. {install_hint}",
                binary
            )
        } else {
            anyhow::anyhow!("{tool_name}: could not start {:?}: {error}", binary)
        }
    })?;
    let process_group_id = child_process_group_id(&child);
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("Could not capture {tool_name} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("Could not capture {tool_name} stderr"))?;
    let stdout_reader = thread::spawn(move || read_pipe(stdout));
    let stderr_reader = thread::spawn(move || read_pipe(stderr));

    let status = wait_for_process(tool_name, &mut child, process_group_id, cancel)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{tool_name} stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{tool_name} stderr reader panicked"))??;

    let Some(status) = status else {
        anyhow::bail!("{tool_name} cancelled");
    };
    if !status.success() {
        let details = String::from_utf8_lossy(if stderr.is_empty() { &stdout } else { &stderr });
        anyhow::bail!(
            "{tool_name}: subprocess {:?} failed with status {}: {}",
            binary,
            status,
            details.trim()
        );
    }
    Ok(ProcessOutput { stdout })
}

fn wait_for_process(
    tool_name: &str,
    child: &mut Child,
    process_group_id: Option<u32>,
    cancel: &ScanCancellation,
) -> Result<Option<ExitStatus>> {
    loop {
        if cancel.is_cancelled() {
            kill_child(child, process_group_id);
            let _ = child.wait();
            return Ok(None);
        }
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("{tool_name}: could not poll subprocess"))?
        {
            return Ok(Some(status));
        }
        thread::sleep(Duration::from_millis(75));
    }
}

fn kill_child(child: &mut Child, process_group_id: Option<u32>) {
    #[cfg(unix)]
    {
        if let Some(process_group_id) = process_group_id {
            unsafe {
                libc::killpg(process_group_id as libc::pid_t, libc::SIGKILL);
            }
            return;
        }
    }
    let _ = child.kill();
}

fn child_process_group_id(child: &Child) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(child.id())
    }

    #[cfg(not(unix))]
    {
        let _ = child;
        None
    }
}

fn read_pipe(mut pipe: impl Read) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    pipe.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn required_string(input: &Value, key: &str, message: &str) -> Result<String> {
    input
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!(message.to_string()))
}

fn optional_string(input: &Value, keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::String(value) => {
                    Ok(Some(value.trim().to_string()).filter(|value| !value.is_empty()))
                }
                Value::Null => Ok(None),
                _ => anyhow::bail!("{key} must be a string"),
            };
        }
    }
    Ok(None)
}

fn optional_u64(input: &Value, keys: &[&str]) -> Result<Option<u64>> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            return match value {
                Value::Number(number) => number
                    .as_u64()
                    .map(Some)
                    .with_context(|| format!("{key} must be a non-negative integer")),
                Value::String(value) => value
                    .parse::<u64>()
                    .map(Some)
                    .with_context(|| format!("{key} must be a non-negative integer")),
                Value::Null => Ok(None),
                _ => anyhow::bail!("{key} must be a non-negative integer"),
            };
        }
    }
    Ok(None)
}

fn normalize_subdomain(candidate: &str, domain: &str) -> Option<String> {
    let host = candidate
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("*.")
        .to_ascii_lowercase();
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if host == domain || !host.ends_with(&format!(".{domain}")) {
        return None;
    }
    Some(host)
}

fn host_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .trim()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| url.trim());
    let without_credentials = without_scheme
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(without_scheme);
    let host_port = without_credentials
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host = host_port.split(':').next().unwrap_or_default().trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    host: String,
    port: u16,
}

fn split_host_port(target: &str) -> Endpoint {
    let default_port = if target.starts_with("https://") {
        443
    } else {
        80
    };
    let without_scheme = target
        .trim()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_else(|| target.trim());
    let host_port = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let (host, port) = if let Some((host, port)) = host_port.rsplit_once(':') {
        let parsed = port.parse::<u16>().ok().unwrap_or(default_port);
        (host.to_string(), parsed)
    } else {
        (host_port.to_string(), default_port)
    };
    Endpoint { host, port }
}

fn ensure_http_scheme(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("http://{target}")
    }
}

fn now_isoish() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("{seconds}")
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::thread;
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::*;
    use crate::config::V2Config;
    use crate::modules::ToolExecutionContext;

    fn context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            spend: None,
            executor: None,
        }
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, content: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, content).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn parses_nmap_grepable_output() {
        let parsed = parse_nmap_grepable(
            "Host: 192.0.2.10 (web.example) Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx TLS/\n",
        )
        .unwrap();

        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.hosts[0].address, "192.0.2.10");
        assert_eq!(parsed.hosts[0].hostname.as_deref(), Some("web.example"));
        assert_eq!(parsed.hosts[0].services.len(), 2);
        assert_eq!(parsed.hosts[0].services[0].port, 80);
        assert_eq!(parsed.hosts[0].services[0].name.as_deref(), Some("http"));
    }

    #[test]
    fn parses_subdomain_sources() {
        let crtsh = parse_crtsh_subdomains(
            r#"[{"name_value":"www.example.com\n*.api.example.com\nexample.com"}]"#,
            "example.com",
        )
        .unwrap();
        assert_eq!(crtsh, vec!["api.example.com", "www.example.com"]);

        let wayback = parse_wayback_subdomains(
            r#"[["original"],["https://shop.example.com/a"],["https://www.example.com/b"]]"#,
            "example.com",
        )
        .unwrap();
        assert_eq!(wayback, vec!["shop.example.com", "www.example.com"]);
    }

    #[test]
    fn parses_http_fingerprint_headers_and_body() {
        let parsed = parse_http_fingerprint(
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: Express\r\n\r\n<html><title>Acme</title><script src=\"/_next/static/app.js\"></script></html>",
        )
        .unwrap();

        assert_eq!(parsed.status, Some(200));
        assert_eq!(parsed.server.as_deref(), Some("nginx"));
        assert_eq!(parsed.title.as_deref(), Some("Acme"));
        assert!(parsed.technologies.contains(&"nginx".to_string()));
        assert!(parsed.technologies.contains(&"Express".to_string()));
        assert!(parsed.technologies.contains(&"next.js".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn nmap_executor_invokes_subprocess_and_persists_workspace_rows() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("nmap");
        write_executable(
            &binary,
            r#"#!/bin/sh
cat <<'OUT'
Host: 192.0.2.10 (web.example) Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx TLS/
OUT
"#,
        );
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let result = execute_recon_tool(
            "recon:nmap",
            json!({"target":"192.0.2.10","ports":"80,443","binary":binary.display().to_string()}),
            &ctx,
        )
        .unwrap();

        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/hosts/0/address")
                .and_then(Value::as_str),
            Some("192.0.2.10")
        );
        assert_eq!(
            result
                .pointer("/data/services/1/port")
                .and_then(Value::as_u64),
            Some(443)
        );
        let mut store = ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        assert_eq!(store.list_hosts(&workspace_id).unwrap().len(), 1);
        assert_eq!(
            store
                .list_services_for_host(
                    result
                        .pointer("/data/hosts/0/id")
                        .and_then(Value::as_str)
                        .unwrap()
                )
                .unwrap()
                .len(),
            2
        );
    }

    #[cfg(unix)]
    #[test]
    fn subdomain_executor_invokes_curl_and_persists_hosts() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("curl");
        write_executable(
            &binary,
            r#"#!/bin/sh
cat <<'JSON'
[{"name_value":"www.example.com\napi.example.com"}]
JSON
"#,
        );
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let result = execute_recon_tool(
            "recon:subdomain",
            json!({"domain":"example.com","source":"crtsh","binary":binary.display().to_string()}),
            &ctx,
        )
        .unwrap();

        assert_eq!(
            result.pointer("/data/subdomains/0").and_then(Value::as_str),
            Some("api.example.com")
        );
        assert_eq!(
            result
                .pointer("/data/hosts")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            result
                .pointer("/data/notes/0/ntype")
                .and_then(Value::as_str),
            Some("recon:subdomain")
        );
    }

    #[cfg(unix)]
    #[test]
    fn http_fingerprint_executor_invokes_curl_and_persists_service() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("curl");
        write_executable(
            &binary,
            r#"#!/bin/sh
cat <<'HTTP'
HTTP/1.1 200 OK
Server: nginx
X-Powered-By: Express

<html><title>Acme</title></html>
HTTP
"#,
        );
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let result = execute_recon_tool(
            "recon:http-fingerprint",
            json!({"target":"https://www.example.com","binary":binary.display().to_string()}),
            &ctx,
        )
        .unwrap();

        assert_eq!(
            result
                .pointer("/data/hosts/0/address")
                .and_then(Value::as_str),
            Some("www.example.com")
        );
        assert_eq!(
            result
                .pointer("/data/services/0/port")
                .and_then(Value::as_u64),
            Some(443)
        );
        assert_eq!(
            result
                .pointer("/data/fingerprint/server")
                .and_then(Value::as_str),
            Some("nginx")
        );
    }

    #[test]
    fn missing_nmap_binary_error_is_actionable() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let error = execute_recon_tool(
            "recon:nmap",
            json!({"target":"192.0.2.10","binary":temp.path().join("missing-nmap").display().to_string()}),
            &ctx,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("could not find subprocess binary"));
        assert!(error.contains("Install nmap"));
    }

    #[test]
    fn missing_subdomain_binary_error_is_actionable() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);
        let error = execute_recon_tool(
            "recon:subdomain",
            json!({"domain":"example.com","source":"crtsh","binary":temp.path().join("missing-curl").display().to_string()}),
            &ctx,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("could not find subprocess binary"));
        assert!(error.contains("Install curl"));
    }

    #[test]
    fn missing_workspace_error_is_actionable() {
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: None,
            findings_store: None,
            spend: None,
            executor: None,
        };
        let error = execute_recon_tool(
            "recon:http-fingerprint",
            json!({"target":"example.com"}),
            &ctx,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("active workspace"));
    }

    #[cfg(unix)]
    #[test]
    fn cancels_running_nmap_process() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("slow-nmap");
        write_executable(
            &binary,
            "#!/bin/sh\nsleep 5\nprintf 'Host: 192.0.2.10 () Ports: 80/open/tcp//http///\\n'\n",
        );
        let scanner = ReconNmapScanner {
            target: "192.0.2.10".to_string(),
            ports: "80".to_string(),
            binary: binary.display().to_string(),
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let started_at = Instant::now();
        let worker = thread::spawn(move || scanner.scan(&worker_cancellation));
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let error = worker.join().unwrap().unwrap_err().to_string();

        assert!(error.contains("cancelled"));
        assert!(started_at.elapsed() < Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[test]
    fn cancels_running_http_fingerprint_process() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("slow-curl");
        write_executable(
            &binary,
            "#!/bin/sh\nsleep 5\nprintf 'HTTP/1.1 200 OK\\n\\n'\n",
        );
        let fingerprinter = ReconHttpFingerprinter {
            target: "http://example.com".to_string(),
            binary: binary.display().to_string(),
            timeout_seconds: 10,
        };
        let cancellation = ScanCancellation::default();
        let worker_cancellation = cancellation.clone();
        let started_at = Instant::now();
        let worker = thread::spawn(move || fingerprinter.fingerprint(&worker_cancellation));
        thread::sleep(Duration::from_millis(200));
        cancellation.cancel();
        let error = worker.join().unwrap().unwrap_err().to_string();

        assert!(error.contains("cancelled"));
        assert!(started_at.elapsed() < Duration::from_secs(3));
    }
}
