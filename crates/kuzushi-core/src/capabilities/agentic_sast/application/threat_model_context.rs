use super::*;

const MAX_DIGEST_THREATS: usize = 12;
const MAX_DIGEST_ENTRIES: usize = 12;
const MAX_DIGEST_FIELD_CHARS: usize = 200;

/// Prompt enrichment resolved once per run: the persisted threat-model
/// digest plus the MCP servers the tool policy actually attached, so the
/// hunt prompt only advertises tools the agent can really call.
#[derive(Debug, Default, Clone)]
pub(crate) struct PromptEnrichment {
    pub(crate) threat_context: Option<String>,
    pub(crate) attached_mcps: Vec<String>,
}

impl PromptEnrichment {
    pub(crate) fn for_run(target: &Path, tool_policy: &AgentToolPolicy) -> Self {
        Self {
            threat_context: threat_model_scan_context(target),
            attached_mcps: tool_policy
                .mcps_attached
                .iter()
                .map(|attachment| attachment.name.clone())
                .collect(),
        }
    }
}

/// Compact digest of the persisted threat model for the scan prompt. The
/// scan stays runnable without one: a missing or malformed artifact yields
/// None and the hunt proceeds uninformed.
pub(crate) fn threat_model_scan_context(target: &Path) -> Option<String> {
    let document = crate::capabilities::threat_model::load_persistent_threat_model(target)?;
    render_threat_model_digest(&document)
}

pub(crate) fn render_threat_model_digest(document: &Value) -> Option<String> {
    let mut sections = Vec::new();
    let threats = threat_lines(document);
    if !threats.is_empty() {
        sections.push(format!("Modeled threats:\n{}", threats.join("\n")));
    }
    let entry_points = attack_surface_lines(document, "entryPoints", entry_point_line);
    if !entry_points.is_empty() {
        sections.push(format!(
            "Attack-surface entry points:\n{}",
            entry_points.join("\n")
        ));
    }
    let sinks = attack_surface_lines(document, "externalSinks", external_sink_line);
    if !sinks.is_empty() {
        sections.push(format!("External sinks:\n{}", sinks.join("\n")));
    }
    if sections.is_empty() {
        return None;
    }
    Some(sections.join("\n\n"))
}

fn threat_lines(document: &Value) -> Vec<String> {
    document
        .get("threats")
        .and_then(Value::as_array)
        .map(|threats| {
            threats
                .iter()
                .take(MAX_DIGEST_THREATS)
                .map(threat_line)
                .collect()
        })
        .unwrap_or_default()
}

fn threat_line(threat: &Value) -> String {
    let severity = field(threat, &["severity", "likelihood"]).unwrap_or_else(|| "unrated".into());
    let title = field(threat, &["title", "description", "id"]).unwrap_or_else(|| "(untitled)".into());
    let mut line = format!("- [{severity}] {title}");
    if let Some(cwe) = field(threat, &["relatedCwe", "relatedCwes", "cwe"]) {
        line.push_str(&format!(" · {cwe}"));
    }
    if let Some(files) = joined_list(threat, "affectedFiles") {
        line.push_str(&format!(" · files: {files}"));
    }
    line
}

fn attack_surface_lines(
    document: &Value,
    key: &str,
    render: fn(&Value) -> String,
) -> Vec<String> {
    document
        .pointer(&format!("/attackSurface/{key}"))
        .and_then(Value::as_array)
        .map(|entries| entries.iter().take(MAX_DIGEST_ENTRIES).map(render).collect())
        .unwrap_or_default()
}

fn entry_point_line(entry: &Value) -> String {
    let name = field(entry, &["name"]).unwrap_or_else(|| "(unnamed)".into());
    let mut line = format!("- {name}");
    if let Some(zone) = field(entry, &["trustZone"]) {
        line.push_str(&format!(" ({zone})"));
    }
    if let Some(evidence) = field(entry, &["evidence"]) {
        line.push_str(&format!(" — {evidence}"));
    }
    line
}

fn external_sink_line(sink: &Value) -> String {
    let name = field(sink, &["name"]).unwrap_or_else(|| "(unnamed)".into());
    match field(sink, &["category"]) {
        Some(category) => format!("- {name} [{category}]"),
        None => format!("- {name}"),
    }
}

fn field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match value.get(key) {
        Some(Value::String(text)) if !text.trim().is_empty() => Some(cap(text.trim())),
        Some(Value::Array(items)) => {
            let joined = items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            (!joined.is_empty()).then(|| cap(&joined))
        }
        _ => None,
    })
}

fn joined_list(value: &Value, key: &str) -> Option<String> {
    field(value, &[key])
}

fn cap(text: &str) -> String {
    if text.chars().count() <= MAX_DIGEST_FIELD_CHARS {
        return text.to_string();
    }
    let mut capped: String = text.chars().take(MAX_DIGEST_FIELD_CHARS).collect();
    capped.push_str("...");
    capped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_renders_threats_entry_points_and_sinks() {
        let document = json!({
            "threats": [{
                "severity": "high",
                "title": "Command spec reaches execve unchecked",
                "relatedCwe": "CWE-78",
                "affectedFiles": ["execd_lib.cpp"],
            }],
            "attackSurface": {
                "entryPoints": [{"name": "HandleRequest", "trustZone": "rpc", "evidence": "execd_server.cpp:42"}],
                "externalSinks": [{"name": "execve", "category": "exec"}],
            },
        });

        let digest = render_threat_model_digest(&document).unwrap();

        assert!(digest.contains("[high] Command spec reaches execve unchecked · CWE-78 · files: execd_lib.cpp"));
        assert!(digest.contains("- HandleRequest (rpc) — execd_server.cpp:42"));
        assert!(digest.contains("- execve [exec]"));
    }

    #[test]
    fn empty_or_malformed_documents_yield_no_digest() {
        assert!(render_threat_model_digest(&json!({})).is_none());
        assert!(render_threat_model_digest(&json!({"threats": []})).is_none());
        assert!(render_threat_model_digest(&json!({"threats": "not-a-list"})).is_none());
    }
}
