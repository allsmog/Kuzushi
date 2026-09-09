use super::capture_payload::{decode_base64_field, disclosure, rationale_with, DecodedField};
use super::CaptureTally;
use crate::findings::{Finding, FindingEvidence, FindingStore, Severity};
use crate::workspace::{load_program_scope, ProgramScope, WorkspaceTarget};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;
use uuid::Uuid;

/// Outcome of one HAR import call. The TUI surfaces `imported` and
/// `skipped_out_of_scope` so operators see scope-gate hits at a glance
/// without rereading the transcript. Every entry lands in exactly one
/// counter, so the three add up to the entry count of the file.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HarImportSummary {
    pub run_id: String,
    pub imported: usize,
    pub skipped_out_of_scope: usize,
    /// Entries carrying no request URL. They cannot be scope-checked or
    /// addressed, so they are dropped — but never without saying how many.
    pub skipped_unusable: usize,
    pub source_path: String,
}

/// Parse a HAR (`http archive`) JSON file and persist each entry as a
/// `Finding` whose evidence carries the raw request and response. HAR
/// is a JSON spec used by Burp, Chrome DevTools, Charles, and others —
/// parsing it requires no extra runtime dependency beyond `serde_json`.
///
/// Out-of-scope entries are skipped silently with a counter. Within-
/// scope and Unknown entries are imported.
pub fn import_har(workspace: &WorkspaceTarget, path: &Path) -> Result<HarImportSummary> {
    let document = read_har_document(path)?;
    let entries = document
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("HAR file {} missing log.entries array", path.display()))?;

    let scope = load_program_scope(workspace).context("Could not load scope.toml")?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let run_id = format!("har-{}", Uuid::new_v4());
    let tally = store.with_run_lifecycle(&run_id, workspace.root(), || {
        let mut tally = CaptureTally::default();
        for entry in entries {
            persist_har_entry(&store, &run_id, scope.as_ref(), entry, &mut tally)?;
        }
        Ok((tally, tally.imported))
    })?;

    Ok(HarImportSummary {
        run_id,
        imported: tally.imported,
        skipped_out_of_scope: tally.skipped_out_of_scope,
        skipped_unusable: tally.skipped_unusable,
        source_path: path.display().to_string(),
    })
}

fn read_har_document(path: &Path) -> Result<Value> {
    let body = crate::bounded_file::read_utf8_text(path, 64 * 1024 * 1024)
        .with_context(|| format!("Could not read HAR file {}", path.display()))?;
    serde_json::from_str(&body)
        .with_context(|| format!("HAR file {} is not valid JSON", path.display()))
}

fn persist_har_entry(
    store: &FindingStore,
    run_id: &str,
    scope: Option<&ProgramScope>,
    entry: &Value,
    tally: &mut CaptureTally,
) -> Result<()> {
    let url = entry
        .pointer("/request/url")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty());
    let (Some(request), Some(url)) = (entry.get("request"), url) else {
        tally.skipped_unusable += 1;
        return Ok(());
    };
    if scope.is_some_and(|scope| !scope.host_allowed(url)) {
        tally.skipped_out_of_scope += 1;
        return Ok(());
    }
    let finding = build_har_finding(url, request, entry.get("response"));
    store.insert_finding(run_id, &finding)?;
    tally.imported += 1;
    Ok(())
}

fn build_har_finding(url: &str, request: &Value, response: Option<&Value>) -> Finding {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET");
    let request_message = render_har_request(request);
    let response_message = response.map(render_har_response).unwrap_or_default();
    let notes: Vec<String> = [request_message.note, response_message.note]
        .into_iter()
        .flatten()
        .collect();
    let evidence = FindingEvidence {
        kind: "http-request".to_string(),
        file_path: url.to_string(),
        line: 0,
        snippet: format!("{method} {url}"),
        rationale: rationale_with("Imported from HAR capture", &notes),
        confidence: 50,
        request_blob: Some(request_message.text),
        response_blob: Some(response_message.text).filter(|blob| !blob.is_empty()),
    };
    let summary = format!("{method} {url} (imported)");
    Finding::new_tool(
        "burp-har",
        "http-evidence",
        url,
        0,
        None,
        Severity::Info,
        &summary,
    )
    .with_evidence(vec![evidence])
}

/// One rendered HTTP message, with the disclosure its body needed (if any).
#[derive(Default)]
struct RenderedMessage {
    text: String,
    note: Option<String>,
}

fn render_har_request(request: &Value) -> RenderedMessage {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET");
    let url = request.get("url").and_then(Value::as_str).unwrap_or("");
    let version = request
        .get("httpVersion")
        .and_then(Value::as_str)
        .unwrap_or("HTTP/1.1");
    let mut out = format!("{method} {url} {version}\n");
    render_har_headers(request.get("headers"), &mut out);
    append_har_body(out, har_body(request.get("postData")), "request body")
}

fn render_har_response(response: &Value) -> RenderedMessage {
    let status = response.get("status").and_then(Value::as_u64).unwrap_or(0);
    let status_text = response
        .get("statusText")
        .and_then(Value::as_str)
        .unwrap_or("");
    let version = response
        .get("httpVersion")
        .and_then(Value::as_str)
        .unwrap_or("HTTP/1.1");
    let mut out = format!("{version} {status} {status_text}\n");
    render_har_headers(response.get("headers"), &mut out);
    append_har_body(out, har_body(response.get("content")), "response body")
}

/// HAR carries a binary or compressed payload as base64 and says so with
/// `encoding = "base64"`. Storing that text as-is would present base64 as the
/// HTTP body, so the encoded form is decoded and anything the decode could not
/// preserve is disclosed.
fn har_body(container: Option<&Value>) -> Option<DecodedField> {
    let container = container?;
    let text = container
        .get("text")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())?;
    if !har_declares_base64(container) {
        return Some(DecodedField {
            text: text.to_string(),
            note: None,
        });
    }
    Some(decode_base64_field(text))
}

fn har_declares_base64(container: &Value) -> bool {
    container
        .get("encoding")
        .and_then(Value::as_str)
        .is_some_and(|encoding| encoding.eq_ignore_ascii_case("base64"))
}

fn append_har_body(mut text: String, body: Option<DecodedField>, label: &str) -> RenderedMessage {
    let Some(body) = body else {
        return RenderedMessage { text, note: None };
    };
    text.push('\n');
    text.push_str(&body.text);
    RenderedMessage {
        note: disclosure(label, &body),
        text,
    }
}

fn render_har_headers(headers: Option<&Value>, out: &mut String) {
    let Some(headers) = headers.and_then(Value::as_array) else {
        return;
    };
    for header in headers {
        let name = header.get("name").and_then(Value::as_str).unwrap_or("");
        let value = header.get("value").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("{name}: {value}\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_har() -> String {
        serde_json::json!({
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.lab.test/login",
                            "httpVersion": "HTTP/2",
                            "headers": [
                                { "name": "Content-Type", "value": "application/json" }
                            ],
                            "postData": { "text": "{\"u\":\"a\",\"p\":\"b\"}" }
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "httpVersion": "HTTP/2",
                            "headers": [
                                { "name": "Set-Cookie", "value": "session=abc" }
                            ],
                            "content": { "text": "{\"ok\":true}" }
                        }
                    },
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://evil.example/test",
                            "headers": []
                        }
                    }
                ]
            }
        })
        .to_string()
    }

    #[test]
    fn imports_har_entries_as_findings_with_request_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let har_path = tmp.path().join("burp.har");
        fs::write(&har_path, fixture_har()).unwrap();

        let summary = import_har(&workspace, &har_path).unwrap();

        assert_eq!(summary.imported, 2);
        assert_eq!(summary.skipped_out_of_scope, 0);
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(100).unwrap();
        let api_finding = findings
            .iter()
            .find(|f| f.file_path.contains("api.lab.test"))
            .expect("api finding present");
        assert_eq!(api_finding.tool, "burp-har");
        assert_eq!(api_finding.evidence.len(), 1);
        let evidence = &api_finding.evidence[0];
        assert_eq!(evidence.kind, "http-request");
        let request_blob = evidence.request_blob.as_deref().unwrap();
        assert!(request_blob.starts_with("POST https://api.lab.test/login"));
        assert!(request_blob.contains("Content-Type: application/json"));
        let response_blob = evidence.response_blob.as_deref().unwrap();
        assert!(response_blob.contains("Set-Cookie: session=abc"));
    }

    #[test]
    fn scope_gate_skips_out_of_scope_entries() {
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
        let har_path = tmp.path().join("burp.har");
        fs::write(&har_path, fixture_har()).unwrap();

        let summary = import_har(&workspace, &har_path).unwrap();

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped_out_of_scope, 1);
    }

    #[test]
    fn path_at_sign_spoof_cannot_smuggle_out_of_scope_entries_past_the_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let scope_dir = tmp.path().join(".kuzushi");
        fs::create_dir_all(&scope_dir).unwrap();
        fs::write(
            scope_dir.join("scope.toml"),
            "[in_scope]\nhosts = [\"*.lab.test\"]\n",
        )
        .unwrap();
        let har = serde_json::json!({
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://evil.example/@api.lab.test",
                            "headers": []
                        }
                    }
                ]
            }
        })
        .to_string();
        let har_path = tmp.path().join("spoof.har");
        fs::write(&har_path, har).unwrap();

        let summary = import_har(&workspace, &har_path).unwrap();

        assert_eq!(summary.imported, 0);
        assert_eq!(summary.skipped_out_of_scope, 1);
    }

    fn import_entries(entries: serde_json::Value) -> (HarImportSummary, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let path = tmp.path().join("capture.har");
        fs::write(
            &path,
            serde_json::json!({ "log": { "entries": entries } }).to_string(),
        )
        .unwrap();

        (import_har(&workspace, &path).unwrap(), tmp)
    }

    fn imported_evidence(tmp: &tempfile::TempDir) -> FindingEvidence {
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store.list_findings(10).unwrap()[0].evidence[0].clone()
    }

    fn entry_with_content(content: serde_json::Value) -> serde_json::Value {
        serde_json::json!([{
            "request": { "method": "GET", "url": "https://api.lab.test/x", "headers": [] },
            "response": { "status": 200, "headers": [], "content": content },
        }])
    }

    #[test]
    fn base64_encoded_response_body_is_decoded_before_it_is_stored() {
        let encoded = super::super::capture_payload::encode_base64(b"{\"ok\":true}");
        let (summary, tmp) =
            import_entries(entry_with_content(serde_json::json!({
                "text": encoded,
                "encoding": "base64",
            })));

        assert_eq!(summary.imported, 1);
        let evidence = imported_evidence(&tmp);
        let blob = evidence.response_blob.as_deref().unwrap();
        assert!(
            blob.ends_with("{\"ok\":true}"),
            "a base64 body must not be stored as base64: {blob}"
        );
        assert_eq!(evidence.rationale, "Imported from HAR capture");
    }

    #[test]
    fn binary_response_body_is_disclosed_instead_of_passing_as_http_text() {
        let encoded = super::super::capture_payload::encode_base64(b"\x89PNG\r\n\x1a\n");
        let (_, tmp) = import_entries(entry_with_content(serde_json::json!({
            "text": encoded,
            "encoding": "base64",
        })));

        let evidence = imported_evidence(&tmp);
        assert!(evidence.response_blob.as_deref().unwrap().contains('\u{FFFD}'));
        assert_eq!(
            evidence.rationale,
            "Imported from HAR capture. The response body is binary or not valid UTF-8; \
             undecodable bytes are shown as U+FFFD"
        );
    }

    #[test]
    fn a_plain_text_body_is_stored_verbatim_without_disclosure() {
        let (_, tmp) = import_entries(entry_with_content(serde_json::json!({
            "text": "{\"ok\":true}",
        })));

        let evidence = imported_evidence(&tmp);
        assert!(evidence
            .response_blob
            .as_deref()
            .unwrap()
            .ends_with("{\"ok\":true}"));
        assert_eq!(evidence.rationale, "Imported from HAR capture");
    }

    #[test]
    fn entries_without_a_request_url_are_counted_rather_than_dropped_silently() {
        let (summary, _tmp) = import_entries(serde_json::json!([
            { "response": { "status": 200 } },
            { "request": { "method": "GET", "headers": [] } },
            { "request": { "method": "GET", "url": "https://api.lab.test/x", "headers": [] } },
        ]));

        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped_out_of_scope, 0);
        assert_eq!(summary.skipped_unusable, 2);
    }

    #[test]
    fn missing_log_entries_section_is_a_clean_error() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let path = tmp.path().join("bad.har");
        fs::write(&path, "{}").unwrap();
        let err = import_har(&workspace, &path).unwrap_err().to_string();
        assert!(err.contains("missing log.entries"));
    }
}
