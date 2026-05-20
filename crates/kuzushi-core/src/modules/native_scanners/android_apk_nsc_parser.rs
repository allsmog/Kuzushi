use super::*;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub(in crate::modules) struct NetworkSecuritySummary {
    pub(in crate::modules) base_cleartext: Option<bool>,
    pub(in crate::modules) debug_cleartext: Option<bool>,
    pub(in crate::modules) domain_configs: Vec<DomainConfig>,
    pub(in crate::modules) trust_anchors_user: bool,
}

#[derive(Debug, Default, Clone)]
pub(in crate::modules) struct DomainConfig {
    pub(in crate::modules) domains: Vec<String>,
    pub(in crate::modules) cleartext_permitted: Option<bool>,
    pub(in crate::modules) trust_anchors_user: bool,
}

pub(in crate::modules) fn parse_network_security_config(
    path: &Path,
) -> Result<NetworkSecuritySummary> {
    let bytes = fs::read(path)
        .map_err(|error| anyhow::anyhow!("could not read {}: {error}", path.display()))?;
    parse_network_security_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid XML in {}: {error}", path.display()))
}

pub(in crate::modules) fn parse_network_security_bytes(
    bytes: &[u8],
) -> Result<NetworkSecuritySummary> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut state = NscParserState::default();
    let mut buffer = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer)? {
            Event::Start(start) => state.on_open(&start)?,
            Event::Empty(start) => {
                state.on_open(&start)?;
                state.on_close(local_name(&start).as_str());
            }
            Event::Text(text) => state.on_text(&text.unescape()?),
            Event::End(end) => state.on_close(&end_local_name(&end)),
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(state.finish())
}

fn end_local_name(element: &quick_xml::events::BytesEnd<'_>) -> String {
    let name = String::from_utf8_lossy(element.name().as_ref()).to_string();
    name.rsplit_once(':').map(|(_, l)| l.to_string()).unwrap_or(name)
}

#[derive(Default)]
struct NscParserState {
    summary: NetworkSecuritySummary,
    in_base: bool,
    in_debug: bool,
    in_domain: Option<DomainConfig>,
    in_domain_element: bool,
    in_trust_anchors: bool,
    last_domain_text: String,
}

impl NscParserState {
    fn on_open(&mut self, element: &BytesStart<'_>) -> Result<()> {
        let local = local_name(element);
        match local.as_str() {
            "base-config" => self.enter_base(element)?,
            "debug-overrides" => self.enter_debug(element)?,
            "domain-config" => self.enter_domain(element)?,
            "domain" => self.enter_domain_text(),
            "trust-anchors" => self.in_trust_anchors = true,
            "certificates" => self.handle_certificates(element)?,
            _ => {}
        }
        Ok(())
    }

    fn enter_base(&mut self, element: &BytesStart<'_>) -> Result<()> {
        self.in_base = true;
        self.summary.base_cleartext = attr_bool(element, "cleartextTrafficPermitted")?;
        Ok(())
    }

    fn enter_debug(&mut self, element: &BytesStart<'_>) -> Result<()> {
        self.in_debug = true;
        self.summary.debug_cleartext = attr_bool(element, "cleartextTrafficPermitted")?;
        Ok(())
    }

    fn enter_domain(&mut self, element: &BytesStart<'_>) -> Result<()> {
        self.in_domain = Some(DomainConfig {
            cleartext_permitted: attr_bool(element, "cleartextTrafficPermitted")?,
            ..DomainConfig::default()
        });
        Ok(())
    }

    fn enter_domain_text(&mut self) {
        self.in_domain_element = true;
        self.last_domain_text.clear();
    }

    fn handle_certificates(&mut self, element: &BytesStart<'_>) -> Result<()> {
        if !self.in_trust_anchors {
            return Ok(());
        }
        if let Some(src) = attr_value(element, "src")? {
            if src == "user" {
                self.mark_trust_user();
            }
        }
        Ok(())
    }

    fn on_close(&mut self, local: &str) {
        match local {
            "base-config" => self.in_base = false,
            "debug-overrides" => self.in_debug = false,
            "domain-config" => self.flush_domain(),
            "domain" => self.flush_domain_text(),
            "trust-anchors" => self.in_trust_anchors = false,
            _ => {}
        }
    }

    fn flush_domain(&mut self) {
        if let Some(domain) = self.in_domain.take() {
            self.summary.domain_configs.push(domain);
        }
    }

    fn on_text(&mut self, text: &str) {
        if self.in_domain_element {
            self.last_domain_text.push_str(text);
        }
    }

    fn flush_domain_text(&mut self) {
        let value = std::mem::take(&mut self.last_domain_text).trim().to_string();
        self.in_domain_element = false;
        if value.is_empty() {
            return;
        }
        if let Some(domain) = self.in_domain.as_mut() {
            domain.domains.push(value);
        }
    }

    fn mark_trust_user(&mut self) {
        self.summary.trust_anchors_user = true;
        if let Some(domain) = self.in_domain.as_mut() {
            domain.trust_anchors_user = true;
        }
    }

    fn finish(self) -> NetworkSecuritySummary {
        self.summary
    }
}

fn local_name(element: &BytesStart<'_>) -> String {
    let name = String::from_utf8_lossy(element.name().as_ref()).to_string();
    name.rsplit_once(':')
        .map(|(_, local)| local.to_string())
        .unwrap_or(name)
}

fn attr_value(element: &BytesStart<'_>, qualified: &str) -> Result<Option<String>> {
    for attr in element.attributes() {
        let attr = attr?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        if key == qualified || strip_ns(&key) == strip_ns(qualified) {
            return Ok(Some(String::from_utf8_lossy(attr.value.as_ref()).to_string()));
        }
    }
    Ok(None)
}

fn strip_ns(name: &str) -> &str {
    name.rsplit_once(':').map(|(_, l)| l).unwrap_or(name)
}

fn attr_bool(element: &BytesStart<'_>, qualified: &str) -> Result<Option<bool>> {
    Ok(attr_value(element, qualified)?.and_then(|value| match value.as_str() {
        "true" | "True" | "TRUE" | "1" => Some(true),
        "false" | "False" | "FALSE" | "0" => Some(false),
        _ => None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">internal.lyft.test</domain>
    </domain-config>
</network-security-config>"#;

    #[test]
    fn parses_base_cleartext_true() {
        let summary = parse_network_security_bytes(SAMPLE.as_bytes()).unwrap();
        assert_eq!(summary.base_cleartext, Some(true));
    }

    #[test]
    fn parses_domain_config_with_text_content() {
        let summary = parse_network_security_bytes(SAMPLE.as_bytes()).unwrap();
        assert_eq!(summary.domain_configs.len(), 1);
        assert_eq!(summary.domain_configs[0].domains, vec!["internal.lyft.test"]);
    }

    #[test]
    fn detects_user_ca_trust_anchor() {
        let summary = parse_network_security_bytes(SAMPLE.as_bytes()).unwrap();
        assert!(summary.trust_anchors_user);
    }

    #[test]
    fn reads_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nsc.xml");
        fs::write(&path, SAMPLE).unwrap();
        let summary = parse_network_security_config(&path).unwrap();
        assert_eq!(summary.domain_configs.len(), 1);
    }
}
