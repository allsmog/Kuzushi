use crate::findings::{Finding, FindingEvidence, FindingStore, Severity};
use crate::workspace::{load_program_scope, ProgramScope, WorkspaceTarget};
use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::path::Path;
use uuid::Uuid;

/// Outcome of one Burp XML import call.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BurpImportSummary {
    pub run_id: String,
    pub imported: usize,
    pub skipped_out_of_scope: usize,
    pub source_path: String,
}

/// Parse a Burp Suite Site Map / Proxy History XML export and persist
/// each `<item>` as a `Finding` whose evidence carries the raw
/// request and response bodies. Burp encodes request/response bodies as
/// base64 when `base64="true"`. Unknown encodings yield the literal
/// text. Out-of-scope items are skipped silently.
pub fn import_burp_xml(workspace: &WorkspaceTarget, path: &Path) -> Result<BurpImportSummary> {
    let xml = std::fs::read_to_string(path)
        .with_context(|| format!("Could not read Burp XML file {}", path.display()))?;
    let items = parse_burp_items(&xml)
        .with_context(|| format!("Could not parse Burp XML at {}", path.display()))?;

    let scope = load_program_scope(workspace).context("Could not load scope.toml")?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let run_id = format!("burp-{}", Uuid::new_v4());
    store.insert_scan_run(&run_id, workspace.root(), "completed")?;

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for item in items {
        persist_burp_item(
            &store,
            &run_id,
            scope.as_ref(),
            &item,
            &mut imported,
            &mut skipped,
        )?;
    }

    Ok(BurpImportSummary {
        run_id,
        imported,
        skipped_out_of_scope: skipped,
        source_path: path.display().to_string(),
    })
}

fn persist_burp_item(
    store: &FindingStore,
    run_id: &str,
    scope: Option<&ProgramScope>,
    item: &BurpItem,
    imported: &mut usize,
    skipped: &mut usize,
) -> Result<()> {
    if item.url.is_empty() {
        return Ok(());
    }
    if let Some(scope) = scope {
        if !scope.host_allowed(&item.url) {
            *skipped += 1;
            return Ok(());
        }
    }
    let finding = build_burp_finding(item);
    store.insert_finding(run_id, &finding)?;
    *imported += 1;
    Ok(())
}

#[derive(Debug, Default, Clone)]
struct BurpItem {
    url: String,
    method: String,
    status: String,
    request: String,
    response: String,
}

#[derive(Default)]
struct CurrentField {
    base64: bool,
    text: String,
}

fn parse_burp_items(xml: &str) -> Result<Vec<BurpItem>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut state = BurpParseState::default();
    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => handle_burp_open(&event, &mut state)?,
            Ok(Event::Text(event)) => state
                .current_field
                .text
                .push_str(&event.unescape().context("Burp XML text decode failed")?),
            Ok(Event::CData(event)) => state
                .current_field
                .text
                .push_str(&String::from_utf8_lossy(event.as_ref())),
            Ok(Event::End(event)) => handle_burp_close(&event, &mut state),
            Ok(Event::Eof) => break,
            Err(err) => anyhow::bail!(
                "Burp XML parse error at byte {}: {err}",
                reader.buffer_position()
            ),
            _ => {}
        }
    }
    Ok(state.items)
}

#[derive(Default)]
struct BurpParseState {
    items: Vec<BurpItem>,
    current_item: Option<BurpItem>,
    current_field: CurrentField,
}

fn handle_burp_open(
    event: &quick_xml::events::BytesStart<'_>,
    state: &mut BurpParseState,
) -> Result<()> {
    let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
    if name == "item" {
        state.current_item = Some(BurpItem::default());
        return Ok(());
    }
    let base64 = attribute(event, "base64")? == Some("true".to_string());
    state.current_field = CurrentField {
        base64,
        text: String::new(),
    };
    Ok(())
}

fn handle_burp_close(event: &quick_xml::events::BytesEnd<'_>, state: &mut BurpParseState) {
    let name = String::from_utf8_lossy(event.name().as_ref()).to_string();
    if name == "item" {
        if let Some(item) = state.current_item.take() {
            state.items.push(item);
        }
        return;
    }
    let Some(item) = state.current_item.as_mut() else {
        state.current_field = CurrentField::default();
        return;
    };
    let field_text = std::mem::take(&mut state.current_field.text);
    let decoded = decode_burp_text(&field_text, state.current_field.base64);
    assign_burp_field(item, &name, decoded);
    state.current_field = CurrentField::default();
}

fn assign_burp_field(item: &mut BurpItem, name: &str, decoded: String) {
    match name {
        "url" => item.url = decoded.trim().to_string(),
        "method" => item.method = decoded.trim().to_string(),
        "status" => item.status = decoded.trim().to_string(),
        "request" => item.request = decoded,
        "response" => item.response = decoded,
        _ => {}
    }
}

fn attribute(event: &quick_xml::events::BytesStart<'_>, key: &str) -> Result<Option<String>> {
    for attr in event.attributes() {
        let attr = attr.context("Burp XML attribute decode failed")?;
        if attr.key.as_ref() == key.as_bytes() {
            let value = String::from_utf8_lossy(attr.value.as_ref()).to_string();
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn decode_burp_text(raw: &str, base64: bool) -> String {
    if !base64 {
        return raw.to_string();
    }
    super::burp_base64::decode_base64_string(raw.trim()).unwrap_or_else(|_| raw.to_string())
}

fn build_burp_finding(item: &BurpItem) -> Finding {
    let method = if item.method.is_empty() {
        "?"
    } else {
        item.method.as_str()
    };
    let evidence = FindingEvidence {
        kind: "http-request".to_string(),
        file_path: item.url.clone(),
        line: 0,
        snippet: format!("{method} {url}", url = item.url),
        rationale: "Imported from Burp Suite XML".to_string(),
        confidence: 50,
        request_blob: Some(item.request.clone()).filter(|s| !s.is_empty()),
        response_blob: Some(item.response.clone()).filter(|s| !s.is_empty()),
    };
    let summary = format!("{method} {url} (imported)", url = item.url);
    Finding::new_tool(
        "burp-xml",
        "http-evidence",
        &item.url,
        0,
        None,
        Severity::Info,
        &summary,
    )
    .with_evidence(vec![evidence])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn base64_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let len = chunk.len();
            let b0 = chunk[0] as u32;
            let b1 = if len > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if len > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
            out.push(if len > 1 {
                ALPHABET[((triple >> 6) & 0x3F) as usize] as char
            } else {
                '='
            });
            out.push(if len > 2 {
                ALPHABET[(triple & 0x3F) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    fn fixture_burp_xml(host: &str) -> String {
        let request = base64_encode(b"GET / HTTP/1.1\r\nHost: api.lab.test\r\n\r\n");
        let response = base64_encode(b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}");
        format!(
            r#"<?xml version="1.0"?>
            <items>
              <item>
                <url>https://{host}/path</url>
                <method>GET</method>
                <status>200</status>
                <request base64="true">{request}</request>
                <response base64="true">{response}</response>
              </item>
            </items>"#
        )
    }

    #[test]
    fn imports_burp_xml_items_with_base64_decoded_blobs() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let path = tmp.path().join("burp.xml");
        fs::write(&path, fixture_burp_xml("api.lab.test")).unwrap();

        let summary = import_burp_xml(&workspace, &path).unwrap();

        assert_eq!(summary.imported, 1);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        let evidence = &findings[0].evidence[0];
        assert_eq!(evidence.kind, "http-request");
        let request_blob = evidence.request_blob.as_deref().unwrap();
        assert!(request_blob.contains("Host: api.lab.test"));
        let response_blob = evidence.response_blob.as_deref().unwrap();
        assert!(response_blob.contains("{\"ok\":true}"));
    }

    #[test]
    fn scope_gate_skips_out_of_scope_burp_items() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let scope_dir = tmp.path().join(".kuzushi");
        fs::create_dir_all(&scope_dir).unwrap();
        fs::write(
            scope_dir.join("scope.toml"),
            "[in_scope]\nhosts = [\"*.lab.test\"]\n\
             [out_of_scope]\nhosts = [\"evil.example\"]\n",
        )
        .unwrap();
        let path = tmp.path().join("burp.xml");
        fs::write(&path, fixture_burp_xml("evil.example")).unwrap();

        let summary = import_burp_xml(&workspace, &path).unwrap();
        assert_eq!(summary.imported, 0);
        assert_eq!(summary.skipped_out_of_scope, 1);
    }

    #[test]
    fn malformed_burp_xml_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let path = tmp.path().join("bad.xml");
        fs::write(&path, "<items><<<item></item></items>").unwrap();
        let err = import_burp_xml(&workspace, &path).unwrap_err().to_string();
        assert!(err.contains("Could not parse") || err.contains("parse error"));
    }
}
