use super::capture_payload::{decode_base64_field, disclosure, rationale_with, DecodedField};
use super::CaptureTally;
use crate::findings::{Finding, FindingEvidence, FindingStore, Severity};
use crate::workspace::{load_program_scope, ProgramScope, WorkspaceTarget};
use anyhow::{Context, Result};
use quick_xml::events::{BytesText, Event};
use quick_xml::reader::Reader;
use std::path::Path;
use uuid::Uuid;

/// Outcome of one Burp XML import call. Every `<item>` the file carried is
/// accounted for by exactly one counter, so `imported + skipped_out_of_scope
/// + skipped_unusable` is the item count an operator can check against Burp.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BurpImportSummary {
    pub run_id: String,
    pub imported: usize,
    pub skipped_out_of_scope: usize,
    /// Items carrying no URL. They cannot be scope-checked or addressed, so
    /// they are dropped — but never without saying how many.
    pub skipped_unusable: usize,
    pub source_path: String,
}

/// Parse a Burp Suite Site Map / Proxy History XML export and persist
/// each `<item>` as a `Finding` whose evidence carries the raw
/// request and response bodies. Burp encodes request/response bodies as
/// base64 when `base64="true"`, which is how it carries binary and
/// compressed payloads; a payload that does not survive that decode is
/// disclosed in the evidence rationale rather than passed off as the raw
/// HTTP message. Out-of-scope items are skipped silently.
pub fn import_burp_xml(workspace: &WorkspaceTarget, path: &Path) -> Result<BurpImportSummary> {
    let xml = crate::bounded_file::read_utf8_text(path, 64 * 1024 * 1024)
        .with_context(|| format!("Could not read Burp XML file {}", path.display()))?;
    let items = parse_burp_items(&xml)
        .with_context(|| format!("Could not parse Burp XML at {}", path.display()))?;

    let scope = load_program_scope(workspace).context("Could not load scope.toml")?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let run_id = format!("burp-{}", Uuid::new_v4());
    let tally = store.with_run_lifecycle(&run_id, workspace.root(), || {
        let mut tally = CaptureTally::default();
        for item in items {
            persist_burp_item(&store, &run_id, scope.as_ref(), &item, &mut tally)?;
        }
        Ok((tally, tally.imported))
    })?;

    Ok(BurpImportSummary {
        run_id,
        imported: tally.imported,
        skipped_out_of_scope: tally.skipped_out_of_scope,
        skipped_unusable: tally.skipped_unusable,
        source_path: path.display().to_string(),
    })
}

fn persist_burp_item(
    store: &FindingStore,
    run_id: &str,
    scope: Option<&ProgramScope>,
    item: &BurpItem,
    tally: &mut CaptureTally,
) -> Result<()> {
    if item.url.is_empty() {
        tally.skipped_unusable += 1;
        return Ok(());
    }
    if scope.is_some_and(|scope| !scope.host_allowed(&item.url)) {
        tally.skipped_out_of_scope += 1;
        return Ok(());
    }
    let finding = build_burp_finding(item);
    store.insert_finding(run_id, &finding)?;
    tally.imported += 1;
    Ok(())
}

#[derive(Debug, Default, Clone)]
struct BurpItem {
    url: String,
    method: String,
    status: String,
    request: String,
    response: String,
    /// What the stored request/response blobs are, when they are not exactly
    /// what the capture carried. Empty for a clean item.
    decode_notes: Vec<String>,
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
            Ok(Event::Text(event)) => state.current_field.text.push_str(&decoded_text(&event)?),
            Ok(Event::CData(event)) => state.current_field.text.push_str(event.as_ref()),
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

fn decoded_text(event: &BytesText<'_>) -> Result<String> {
    Ok(quick_xml::escape::unescape(event.as_ref())
        .context("Burp XML text entity decode failed")?
        .into_owned())
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
    let name = event.name().as_ref().to_string();
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
    let name = event.name().as_ref().to_string();
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

fn assign_burp_field(item: &mut BurpItem, name: &str, decoded: DecodedField) {
    match name {
        "url" => item.url = decoded.text.trim().to_string(),
        "method" => item.method = decoded.text.trim().to_string(),
        "status" => item.status = decoded.text.trim().to_string(),
        "request" => assign_burp_blob(&mut item.request, &mut item.decode_notes, "request", decoded),
        "response" => assign_burp_blob(
            &mut item.response,
            &mut item.decode_notes,
            "response",
            decoded,
        ),
        _ => {}
    }
}

fn assign_burp_blob(
    blob: &mut String,
    notes: &mut Vec<String>,
    label: &str,
    decoded: DecodedField,
) {
    notes.extend(disclosure(label, &decoded));
    *blob = decoded.text;
}

fn attribute(event: &quick_xml::events::BytesStart<'_>, key: &str) -> Result<Option<String>> {
    for attr in event.attributes() {
        let attr = attr.context("Burp XML attribute decode failed")?;
        if attr.key.as_ref() == key {
            let value = attr.value.as_ref().to_string();
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn decode_burp_text(raw: &str, base64: bool) -> DecodedField {
    if !base64 {
        return DecodedField {
            text: raw.to_string(),
            note: None,
        };
    }
    decode_base64_field(raw)
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
        rationale: rationale_with("Imported from Burp Suite XML", &item.decode_notes),
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

    use super::super::capture_payload::encode_base64;

    fn fixture_burp_xml(host: &str) -> String {
        let request = encode_base64(b"GET / HTTP/1.1\r\nHost: api.lab.test\r\n\r\n");
        let response = encode_base64(b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}");
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

    fn import_single_item(item: &str) -> (BurpImportSummary, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let path = tmp.path().join("burp.xml");
        fs::write(&path, format!("<items>{item}</items>")).unwrap();

        (import_burp_xml(&workspace, &path).unwrap(), tmp)
    }

    fn imported_evidence(tmp: &tempfile::TempDir) -> FindingEvidence {
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store.list_findings(10).unwrap()[0].evidence[0].clone()
    }

    #[test]
    fn binary_response_body_is_disclosed_instead_of_passing_as_http_text() {
        let response = encode_base64(b"HTTP/1.1 200 OK\r\n\r\n\xFF\xD8\xFF\xE0jpeg");
        let (summary, tmp) = import_single_item(&format!(
            "<item><url>https://api.lab.test/logo</url><method>GET</method>\
             <response base64=\"true\">{response}</response></item>"
        ));

        assert_eq!(summary.imported, 1);
        let evidence = imported_evidence(&tmp);
        let blob = evidence.response_blob.as_deref().unwrap();
        assert!(blob.starts_with("HTTP/1.1 200 OK"));
        assert!(blob.contains('\u{FFFD}'), "binary bytes must not be dropped");
        assert_eq!(
            evidence.rationale,
            "Imported from Burp Suite XML. The response is binary or not valid UTF-8; \
             undecodable bytes are shown as U+FFFD"
        );
    }

    #[test]
    fn a_field_declared_base64_that_does_not_decode_is_disclosed() {
        let (summary, tmp) = import_single_item(
            "<item><url>https://api.lab.test/x</url>\
             <request base64=\"true\">GET / HTTP/1.1</request></item>",
        );

        assert_eq!(summary.imported, 1);
        let evidence = imported_evidence(&tmp);
        assert_eq!(
            evidence.request_blob.as_deref(),
            Some("GET / HTTP/1.1"),
            "the field text is preserved verbatim when it does not decode"
        );
        assert!(evidence
            .rationale
            .contains("The request was declared base64 but did not decode"));
    }

    #[test]
    fn a_clean_item_carries_no_decode_disclosure() {
        let (_, tmp) = import_single_item(
            "<item><url>https://api.lab.test/x</url><request>GET / HTTP/1.1</request></item>",
        );

        assert_eq!(imported_evidence(&tmp).rationale, "Imported from Burp Suite XML");
    }

    #[test]
    fn items_without_a_url_are_counted_rather_than_dropped_silently() {
        let (summary, _tmp) = import_single_item(
            "<item><method>GET</method></item>\
             <item><url>https://api.lab.test/x</url></item>",
        );

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped_out_of_scope, 0);
        assert_eq!(summary.skipped_unusable, 1);
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
