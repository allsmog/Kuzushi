//! Pure-data parser for Nmap XML scans (`nmap -oX out.xml`). Lives in
//! its own module so `import_nmap_xml.rs` can stay focused on the
//! persistence side and pass the CRAP-risk per-file gate.

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

#[derive(Debug, Default)]
pub(super) struct ParsedNmapXml {
    pub(super) hosts: Vec<ParsedNmapHost>,
}

#[derive(Debug, Default)]
pub(super) struct ParsedNmapHost {
    pub(super) state: String,
    pub(super) address: String,
    pub(super) hostname: Option<String>,
    pub(super) services: Vec<ParsedNmapService>,
}

#[derive(Debug)]
pub(super) struct ParsedNmapService {
    pub(super) port: u16,
    pub(super) proto: String,
    pub(super) state: String,
    pub(super) name: Option<String>,
    pub(super) product: Option<String>,
    pub(super) version: Option<String>,
    pub(super) raw: serde_json::Value,
}

pub(super) fn parse_nmap_xml(xml: &str) -> Result<ParsedNmapXml> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut state = NmapParseState::default();
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) | Ok(Event::Empty(event)) => {
                let attrs = collect_attrs(&event)?;
                let name = event.name().as_ref().to_string();
                dispatch_nmap_open(name.as_str(), &attrs, &mut state);
            }
            Ok(Event::End(event)) => {
                let name = event.name().as_ref().to_string();
                dispatch_nmap_close(name.as_str(), &mut state);
            }
            Ok(Event::Eof) => break,
            Err(err) => anyhow::bail!(
                "nmap XML parse error at byte {}: {err}",
                reader.buffer_position()
            ),
            _ => {}
        }
    }
    Ok(state.report)
}

#[derive(Default)]
struct NmapParseState {
    report: ParsedNmapXml,
    current_host: Option<ParsedNmapHost>,
    current_service: Option<ParsedNmapService>,
}

fn dispatch_nmap_open(
    name: &str,
    attrs: &std::collections::BTreeMap<String, String>,
    state: &mut NmapParseState,
) {
    match name {
        "host" => state.current_host = Some(ParsedNmapHost::default()),
        "status" => {
            if let Some(host) = state.current_host.as_mut() {
                host.state = attrs.get("state").cloned().unwrap_or_default();
            }
        }
        "address" => set_host_address(&mut state.current_host, attrs),
        "hostname" => set_host_name(&mut state.current_host, attrs),
        "port" => state.current_service = Some(new_service(attrs)),
        "state" => set_service_state(&mut state.current_service, attrs),
        "service" => set_service_metadata(&mut state.current_service, attrs),
        _ => {}
    }
}

fn dispatch_nmap_close(name: &str, state: &mut NmapParseState) {
    match name {
        "port" => {
            if let (Some(host), Some(service)) = (
                state.current_host.as_mut(),
                state.current_service.take(),
            ) {
                host.services.push(service);
            }
        }
        "host" => {
            if let Some(host) = state.current_host.take() {
                state.report.hosts.push(host);
            }
        }
        _ => {}
    }
}

fn set_host_address(
    current_host: &mut Option<ParsedNmapHost>,
    attrs: &std::collections::BTreeMap<String, String>,
) {
    let Some(host) = current_host.as_mut() else {
        return;
    };
    if attrs.get("addrtype").map(String::as_str) == Some("mac") {
        return;
    }
    host.address = attrs.get("addr").cloned().unwrap_or_default();
}

fn set_host_name(
    current_host: &mut Option<ParsedNmapHost>,
    attrs: &std::collections::BTreeMap<String, String>,
) {
    let Some(host) = current_host.as_mut() else {
        return;
    };
    if let Some(name) = attrs.get("name") {
        host.hostname = Some(name.clone());
    }
}

fn new_service(attrs: &std::collections::BTreeMap<String, String>) -> ParsedNmapService {
    ParsedNmapService {
        port: attrs
            .get("portid")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(0),
        proto: attrs.get("protocol").cloned().unwrap_or_default(),
        state: String::new(),
        name: None,
        product: None,
        version: None,
        raw: serde_json::json!(attrs),
    }
}

fn set_service_state(
    current_service: &mut Option<ParsedNmapService>,
    attrs: &std::collections::BTreeMap<String, String>,
) {
    if let Some(service) = current_service.as_mut() {
        service.state = attrs.get("state").cloned().unwrap_or_default();
    }
}

fn set_service_metadata(
    current_service: &mut Option<ParsedNmapService>,
    attrs: &std::collections::BTreeMap<String, String>,
) {
    if let Some(service) = current_service.as_mut() {
        service.name = attrs.get("name").cloned();
        service.product = attrs.get("product").cloned();
        service.version = attrs.get("version").cloned();
    }
}

fn collect_attrs(
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<std::collections::BTreeMap<String, String>> {
    let mut attrs = std::collections::BTreeMap::new();
    for attr in event.attributes() {
        let attr = attr.context("nmap XML attribute decode failed")?;
        let key = attr.key.as_ref().to_string();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
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
                <state state="filtered" />
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
        assert_eq!(http.state, "open");
        let ssh = up
            .services
            .iter()
            .find(|s| s.port == 22)
            .expect("port 22 present");
        assert_eq!(ssh.state, "filtered");
    }

    #[test]
    fn malformed_xml_errors_cleanly() {
        let result = parse_nmap_xml("<nmaprun><<host></host></nmaprun>");
        assert!(result.is_err(), "parser must reject malformed XML");
    }
}
