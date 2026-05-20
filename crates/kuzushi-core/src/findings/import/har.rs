use crate::findings::{Finding, FindingEvidence, FindingStore, Severity};
use crate::workspace::{load_program_scope, ScopeVerdict, WorkspaceTarget};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;
use uuid::Uuid;

/// Outcome of one HAR import call. The TUI surfaces `imported` and
/// `skipped_out_of_scope` so operators see scope-gate hits at a glance
/// without rereading the transcript.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HarImportSummary {
    pub run_id: String,
    pub imported: usize,
    pub skipped_out_of_scope: usize,
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
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("Could not read HAR file {}", path.display()))?;
    let document: Value = serde_json::from_str(&body)
        .with_context(|| format!("HAR file {} is not valid JSON", path.display()))?;
    let entries = document
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "HAR file {} missing log.entries array",
                path.display()
            )
        })?;

    let scope = load_program_scope(workspace).context("Could not load scope.toml")?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let run_id = format!("har-{}", Uuid::new_v4());
    store.insert_scan_run(&run_id, workspace.root(), "completed")?;

    let mut imported = 0usize;
    let mut skipped = 0usize;
    for entry in entries {
        let Some(request) = entry.get("request") else {
            continue;
        };
        let Some(url) = request.get("url").and_then(Value::as_str) else {
            continue;
        };
        if let Some(scope) = scope.as_ref() {
            if scope.verdict(url) == ScopeVerdict::OutOfScope {
                skipped += 1;
                continue;
            }
        }
        let finding = build_har_finding(url, request, entry.get("response"));
        store.insert_finding(&run_id, &finding)?;
        imported += 1;
    }

    Ok(HarImportSummary {
        run_id,
        imported,
        skipped_out_of_scope: skipped,
        source_path: path.display().to_string(),
    })
}

fn build_har_finding(url: &str, request: &Value, response: Option<&Value>) -> Finding {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET");
    let request_blob = render_har_request(request);
    let response_blob = response.map(render_har_response).unwrap_or_default();
    let evidence = FindingEvidence {
        kind: "http-request".to_string(),
        file_path: url.to_string(),
        line: 0,
        snippet: format!("{method} {url}"),
        rationale: "Imported from HAR capture".to_string(),
        confidence: 50,
        request_blob: Some(request_blob),
        response_blob: if response_blob.is_empty() {
            None
        } else {
            Some(response_blob)
        },
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

fn render_har_request(request: &Value) -> String {
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
    if let Some(body) = request
        .pointer("/postData/text")
        .and_then(Value::as_str)
        .filter(|body| !body.is_empty())
    {
        out.push('\n');
        out.push_str(body);
    }
    out
}

fn render_har_response(response: &Value) -> String {
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
    if let Some(body) = response
        .pointer("/content/text")
        .and_then(Value::as_str)
        .filter(|body| !body.is_empty())
    {
        out.push('\n');
        out.push_str(body);
    }
    out
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
    fn missing_log_entries_section_is_a_clean_error() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let path = tmp.path().join("bad.har");
        fs::write(&path, "{}").unwrap();
        let err = import_har(&workspace, &path).unwrap_err().to_string();
        assert!(err.contains("missing log.entries"));
    }
}
