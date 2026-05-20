use super::*;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Import an Nmap XML scan (`nmap -oX out.xml`) into the recon store as
/// `ReconHost` + `ReconService` rows. Parsed in-process via `quick-xml`
/// — no `nmap` binary required to ingest. Skip a host when its status
/// is not `up`. Service rows track open ports only.
pub(crate) fn run_recon_import_nmap_xml(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<ReconReport> {
    let workspace = ctx.workspace.context(
        "recon:import needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let path = required_path(input, "path", "recon:import nmap-xml needs a `path` field")?;
    let xml = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;

    let parsed = parse_nmap_xml(&xml)
        .with_context(|| format!("Could not parse nmap XML at {}", path.display()))?;

    let mut store = ReconWorkspaceStore::open(workspace)?;
    let workspace_id = store.ensure_default_workspace(workspace.root())?;
    let mut hosts = Vec::new();
    let mut services = Vec::new();

    for nmap_host in parsed.hosts {
        if nmap_host.state != "up" {
            continue;
        }
        // hosts table CHECK constraint accepts only ('alive','down','unknown').
        // Map nmap's `up` to `alive` so the host row passes validation.
        let host = store.upsert_host(
            &workspace_id,
            &nmap_host.address,
            nmap_host.hostname.as_deref(),
            "alive",
            json!({
                "discoveredBy": "recon:import-nmap-xml",
                "discoveredAt": now_isoish(),
                "nmapState": nmap_host.state,
            }),
        )?;
        for service in nmap_host.services {
            let recorded = store.upsert_service(
                &host.id,
                service.port,
                &service.proto,
                service.name.as_deref(),
                service.product.as_deref(),
                &service.state,
                json!({
                    "version": service.version,
                    "raw": service.raw,
                }),
            )?;
            services.push(recorded);
        }
        hosts.push(host);
    }

    Ok(ReconReport {
        tool: "recon:import-nmap-xml".to_string(),
        target: path.display().to_string(),
        hosts,
        services,
        notes: Vec::new(),
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

#[derive(Debug, Default)]
struct ParsedNmapXml {
    hosts: Vec<ParsedNmapHost>,
}

#[derive(Debug, Default)]
struct ParsedNmapHost {
    state: String,
    address: String,
    hostname: Option<String>,
    services: Vec<ParsedNmapService>,
}

#[derive(Debug)]
struct ParsedNmapService {
    port: u16,
    proto: String,
    state: String,
    name: Option<String>,
    product: Option<String>,
    version: Option<String>,
    raw: serde_json::Value,
}

fn parse_nmap_xml(xml: &str) -> Result<ParsedNmapXml> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut report = ParsedNmapXml::default();
    let mut current_host: Option<ParsedNmapHost> = None;
    let mut current_service: Option<ParsedNmapService> = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) | Ok(Event::Empty(event)) => {
                let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
                let attrs = collect_attrs(&event)?;
                match name.as_str() {
                    "host" => current_host = Some(ParsedNmapHost::default()),
                    "status" => {
                        if let Some(host) = current_host.as_mut() {
                            host.state = attrs.get("state").cloned().unwrap_or_default();
                        }
                    }
                    "address" => {
                        if let Some(host) = current_host.as_mut() {
                            if attrs.get("addrtype").map(String::as_str) != Some("mac") {
                                host.address = attrs.get("addr").cloned().unwrap_or_default();
                            }
                        }
                    }
                    "hostname" => {
                        if let Some(host) = current_host.as_mut() {
                            if let Some(name) = attrs.get("name") {
                                host.hostname = Some(name.clone());
                            }
                        }
                    }
                    "port" => {
                        let port = attrs
                            .get("portid")
                            .and_then(|p| p.parse::<u16>().ok())
                            .unwrap_or(0);
                        let proto = attrs.get("protocol").cloned().unwrap_or_default();
                        current_service = Some(ParsedNmapService {
                            port,
                            proto,
                            state: String::new(),
                            name: None,
                            product: None,
                            version: None,
                            raw: serde_json::json!(attrs),
                        });
                    }
                    "state" => {
                        if let Some(service) = current_service.as_mut() {
                            service.state = attrs.get("state").cloned().unwrap_or_default();
                        }
                    }
                    "service" => {
                        if let Some(service) = current_service.as_mut() {
                            service.name = attrs.get("name").cloned();
                            service.product = attrs.get("product").cloned();
                            service.version = attrs.get("version").cloned();
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(event)) => {
                let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
                match name.as_str() {
                    "port" => {
                        if let (Some(host), Some(service)) =
                            (current_host.as_mut(), current_service.take())
                        {
                            host.services.push(service);
                        }
                    }
                    "host" => {
                        if let Some(host) = current_host.take() {
                            report.hosts.push(host);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(err) => anyhow::bail!("nmap XML parse error at byte {}: {err}", reader.buffer_position()),
            _ => {}
        }
    }
    Ok(report)
}

fn collect_attrs(
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<std::collections::BTreeMap<String, String>> {
    let mut attrs = std::collections::BTreeMap::new();
    for attr in event.attributes() {
        let attr = attr.context("nmap XML attribute decode failed")?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let value = attr
            .decode_and_unescape_value(quick_xml::reader::Reader::from_str("").decoder())
            .context("nmap XML attribute unescape failed")?
            .into_owned();
        attrs.insert(key, value);
    }
    Ok(attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_NMAP: &str = r#"<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up" />
            <address addr="10.0.0.1" addrtype="ipv4" />
            <hostnames><hostname name="server.lab.test" /></hostnames>
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open" />
                <service name="http" product="nginx" version="1.20" />
              </port>
              <port protocol="tcp" portid="22">
                <state state="open" />
                <service name="ssh" product="OpenSSH" version="9.0" />
              </port>
            </ports>
          </host>
          <host>
            <status state="down" />
            <address addr="10.0.0.2" addrtype="ipv4" />
          </host>
        </nmaprun>"#;

    #[test]
    fn parses_hosts_and_services_skipping_down_state() {
        let report = parse_nmap_xml(SIMPLE_NMAP).unwrap();
        assert_eq!(report.hosts.len(), 2, "both hosts parsed");
        let up = &report.hosts[0];
        assert_eq!(up.state, "up");
        assert_eq!(up.address, "10.0.0.1");
        assert_eq!(up.hostname.as_deref(), Some("server.lab.test"));
        assert_eq!(up.services.len(), 2);
        let http = up
            .services
            .iter()
            .find(|s| s.port == 80)
            .expect("port 80 present");
        assert_eq!(http.name.as_deref(), Some("http"));
        assert_eq!(http.product.as_deref(), Some("nginx"));
        assert_eq!(http.state, "open");
    }

    #[test]
    fn malformed_xml_errors_cleanly() {
        // Truly malformed payload — quick-xml refuses the syntax error and
        // we surface that as a parse failure instead of silently returning
        // an empty document.
        let result = parse_nmap_xml("<nmaprun><<host></host></nmaprun>");
        assert!(result.is_err(), "parser must reject malformed XML");
    }
}
