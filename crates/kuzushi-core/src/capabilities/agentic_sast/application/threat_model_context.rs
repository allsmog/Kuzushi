use super::*;

pub(crate) const MAX_DIGEST_THREATS: usize = 12;
pub(crate) const MAX_DIGEST_ENTRIES: usize = 12;
pub(crate) const MAX_DIGEST_FIELD_CHARS: usize = 200;
pub(crate) const MAX_DIGEST_LESSONS: usize = 8;
pub(crate) const MAX_DIGEST_LESSON_FIELD_CHARS: usize = 2048;

mod map_digest;

#[cfg(test)]
mod context_binding_tests;
#[cfg(test)]
mod overview_tests;

pub(crate) fn select_threat_digest_overview(document: &Value) -> Option<&str> {
    ["systemContext", "system_context"]
        .into_iter()
        .filter_map(|key| document.get(key).and_then(Value::as_str))
        .map(str::trim)
        .find(|text| !text.is_empty())
}

/// Prompt enrichment resolved once per run: the persisted threat-model
/// digest plus the MCP servers the tool policy actually attached, so the
/// hunt prompt only advertises tools the agent can really call.
#[derive(Debug, Default, Clone)]
pub(crate) struct PromptEnrichment {
    pub(crate) threat_context: Option<String>,
    pub(crate) context_enrichment: Option<String>,
    pub(crate) attached_mcps: Vec<String>,
}

impl PromptEnrichment {
    pub(crate) fn for_run(
        target: &Path,
        tool_policy: &AgentToolPolicy,
        input: &Value,
    ) -> Result<Self> {
        Ok(Self {
            threat_context: selected_threat_model_scan_context(target, input)?,
            context_enrichment: crate::scan::selected_scan_context(target, input)?,
            attached_mcps: tool_policy
                .mcps_attached
                .iter()
                .map(|attachment| attachment.name.clone())
                .collect(),
        })
    }
}

pub(crate) fn context_enrichment_scan_context(target: &Path) -> Result<Option<String>> {
    let path = crate::context::context_snapshot_path(target);
    if !path.try_exists()? {
        return Ok(None);
    }
    let raw = crate::bounded_file::read_utf8_text_within(
        target,
        &path,
        crate::context::MAX_CONTEXT_SNAPSHOT_BYTES,
    )?;
    let snapshot: Value = serde_json::from_str(&raw)?;
    anyhow::ensure!(crate::context::context_snapshot_freshness(target, &snapshot).is_current(),
        "Supporting context is stale or unverifiable; regenerate it or explicitly omit it with scanContextRef=null");
    Ok(snapshot
        .get("enrichedContext")
        .and_then(render_context_enrichment_digest))
}

fn render_context_enrichment_digest(enrichment: &Value) -> Option<String> {
    let mut lines = Vec::new();
    push_context_claims(
        &mut lines,
        enrichment.get("customMiddleware"),
        "middleware",
        &["name", "purpose"],
    );
    push_context_claims(
        &mut lines,
        enrichment.get("customSanitizers"),
        "sanitizer",
        &["name", "sanitizationType"],
    );
    push_context_claims(
        &mut lines,
        enrichment.get("trustBoundaries"),
        "trust boundary",
        &["name", "description"],
    );
    push_context_claims(
        &mut lines,
        enrichment.get("dataClassifications"),
        "data",
        &["dataType", "sensitivity"],
    );
    push_context_claims(
        &mut lines,
        enrichment.get("architecturalNotes"),
        "architecture",
        &["note"],
    );
    (!lines.is_empty()).then(|| lines.into_iter().take(20).collect::<Vec<_>>().join("\n"))
}

fn push_context_claims(
    lines: &mut Vec<String>,
    claims: Option<&Value>,
    label: &str,
    fields: &[&str],
) {
    let Some(claims) = claims.and_then(Value::as_array) else {
        return;
    };
    for claim in claims {
        let text = fields
            .iter()
            .filter_map(|field| claim.get(field).and_then(Value::as_str))
            .filter(|value| !value.trim().is_empty())
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" · ");
        if !text.is_empty() {
            lines.push(format!("- {label}: {text}{}", first_evidence_suffix(claim)));
        }
    }
}

fn first_evidence_suffix(claim: &Value) -> String {
    let Some(evidence) = claim
        .get("evidence")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    else {
        return String::new();
    };
    let Some(path) = evidence.get("filePath").and_then(Value::as_str) else {
        return String::new();
    };
    match evidence.get("line").and_then(Value::as_u64) {
        Some(line) => format!(" · {path}:{line}"),
        None => format!(" · {path}"),
    }
}

/// Compact digest of the persisted threat model for the scan prompt. The
/// scan stays runnable without one. Store corruption remains a hard integrity
/// error; a stale or verification-failed document keeps its digest but leads
/// with an honesty warning.
#[cfg(test)]
pub(crate) fn threat_model_scan_context(target: &Path) -> Result<Option<String>> {
    selected_threat_model_scan_context(target, &Value::Null)
}

pub(crate) fn selected_threat_model_scan_context(
    target: &Path,
    input: &Value,
) -> Result<Option<String>> {
    use crate::capabilities::threat_model::ThreatModelSelection;
    let selection = ThreatModelSelection::from_input(input)?;
    if input.get("allowanceRef").is_some() {
        crate::scan::require_frozen_threat_model_digest(input, "agentic-sast:scan")?;
    }
    if let Some(value) = input.get("threatModelDigestRef") {
        return frozen_threat_context(target, value, &selection);
    }
    render_selected_threat_context(target, &selection)
}

fn render_selected_threat_context(
    target: &Path,
    selection: &crate::capabilities::threat_model::ThreatModelSelection,
) -> Result<Option<String>> {
    let Some(document) =
        crate::capabilities::threat_model::load_selected_threat_model(target, selection)?
    else {
        return Ok(None);
    };
    let Some(digest) = render_threat_model_digest(&document) else {
        return Ok(None);
    };
    Ok(
        match crate::capabilities::threat_model::verification_warning(&document, target) {
            Some(warning) => Some(format!("{warning}\n\n{digest}")),
            None => Some(digest),
        },
    )
}

fn frozen_threat_context(
    target: &Path,
    value: &Value,
    selection: &crate::capabilities::threat_model::ThreatModelSelection,
) -> Result<Option<String>> {
    use crate::capabilities::threat_model::ThreatModelSelection;
    let ThreatModelSelection::Revision(reference) = selection else {
        anyhow::bail!("Frozen scanner context requires an exact threatModelRef");
    };
    let frozen = crate::scan::read_bound_threat_model_digest(target, value, reference)?;
    Ok(frozen.preview["text"].as_str().map(str::to_owned))
}

pub(crate) fn render_threat_model_digest(document: &Value) -> Option<String> {
    let sections: Vec<String> = [
        ("Modeled threats", threat_lines(document)),
        (
            "Operator-reviewed lessons for this context",
            reviewed_lesson_lines(document),
        ),
        (
            "Attack-surface entry points",
            attack_surface_lines(document, "entryPoints", entry_point_line),
        ),
        (
            "External sinks",
            attack_surface_lines(document, "externalSinks", external_sink_line),
        ),
        (
            "Context variant patterns (unverified leads; assess current source independently)",
            variant_pattern_lines(document),
        ),
    ]
    .into_iter()
    .chain(map_digest::sections(document))
    .filter(|(_, lines)| !lines.is_empty())
    .map(|(heading, lines)| format!("{heading}:\n{}", lines.join("\n")))
    .collect();
    (!sections.is_empty()).then(|| sections.join("\n\n"))
}

fn reviewed_lesson_lines(document: &Value) -> Vec<String> {
    document.get("reviewedLessons").and_then(Value::as_array).into_iter().flatten().take(MAX_DIGEST_LESSONS).map(|record| {
        let content=&record["content"];
        let text=|key|content[key].as_str().unwrap_or_default().chars().take(MAX_DIGEST_LESSON_FIELD_CHARS).collect::<String>();
        format!("- {}: {}\n  Applies: {}\n  Limits: {}\n  Origin: {} revision {}. Historical guidance; assess current source independently.",text("title"),text("text"),text("applicability"),text("limitations"),record["id"].as_str().unwrap_or_default(),record["revision"])
    }).collect()
}

fn variant_pattern_lines(document: &Value) -> Vec<String> {
    crate::capabilities::threat_model::threat_variant_patterns(document)
        .into_iter()
        .take(MAX_DIGEST_ENTRIES)
        .map(variant_pattern_line)
        .collect()
}

fn variant_pattern_line(pattern: &Value) -> String {
    let text = |field: &str| pattern.get(field).and_then(Value::as_str).unwrap_or("");
    let cwe = pattern
        .get("cwe")
        .and_then(Value::as_str)
        .unwrap_or("unclassified");
    let code: String = text("code").chars().take(MAX_DIGEST_FIELD_CHARS).collect();
    format!(
        "- {cwe} at {} · {} · `{code}`",
        text("location"),
        text("title")
    )
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
    let title =
        field(threat, &["title", "description", "id"]).unwrap_or_else(|| "(untitled)".into());
    let mut line = format!("- [{severity}] {title}");
    if let Some(cwe) = field(threat, &["relatedCwe", "relatedCwes", "cwe"]) {
        line.push_str(&format!(" · {cwe}"));
    }
    if let Some(files) = joined_list(threat, "affectedFiles") {
        line.push_str(&format!(" · files: {files}"));
    }
    line
}

fn attack_surface_lines(document: &Value, key: &str, render: fn(&Value) -> String) -> Vec<String> {
    document
        .pointer(&format!("/attackSurface/{key}"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .take(MAX_DIGEST_ENTRIES)
                .map(render)
                .collect()
        })
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
    select_threat_digest_field(value, keys).map(|(_, text)| cap(&text))
}

pub(crate) fn select_threat_digest_field<'a>(
    value: &Value,
    keys: &[&'a str],
) -> Option<(&'a str, String)> {
    keys.iter()
        .find_map(|key| digest_field_text(value.get(key)?).map(|text| (*key, text)))
}

fn digest_field_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => nonempty_digest_text(text.trim()),
        Value::Array(items) => joined_digest_text(items),
        _ => None,
    }
}

fn nonempty_digest_text(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_string())
}

fn joined_digest_text(items: &[Value]) -> Option<String> {
    let joined = items
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    nonempty_digest_text(&joined)
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

        assert!(digest.contains(
            "[high] Command spec reaches execve unchecked · CWE-78 · files: execd_lib.cpp"
        ));
        assert!(digest.contains("- HandleRequest (rpc) — execd_server.cpp:42"));
        assert!(digest.contains("- execve [exec]"));
    }

    #[test]
    fn digest_lists_confirmed_variant_patterns_to_hunt() {
        let document = json!({"threats": [{
            "id": "T-1",
            "title": "SQL injection",
            "variantPatterns": [{
                "cwe": "CWE-89",
                "location": "routes/search.ts:23",
                "title": "SQL Injection via Product Search",
                "code": "models.sequelize.query(`SELECT ... ${criteria}`)"
            }]
        }]});

        let digest = render_threat_model_digest(&document).unwrap();

        assert!(
            digest.contains("Context variant patterns (unverified leads"),
            "{digest}"
        );
        assert!(digest.contains(
            "- CWE-89 at routes/search.ts:23 · SQL Injection via Product Search · `models.sequelize.query(`SELECT ... ${criteria}`)`"
        ), "{digest}");
    }

    #[test]
    fn empty_or_malformed_documents_yield_no_digest() {
        assert!(render_threat_model_digest(&json!({})).is_none());
        assert!(render_threat_model_digest(&json!({"threats": []})).is_none());
        assert!(render_threat_model_digest(&json!({"threats": "not-a-list"})).is_none());
    }

    #[test]
    fn architecture_and_questions_reach_scans_without_inventing_threats() {
        let document = json!({"threats":[], "dfd":{
            "nodes":[{"id":"app","name":"Command line application","description":"Prints a greeting","trustZone":"internal"}],
            "flows":[{"sourceId":"app","targetId":"terminal","description":"Standard output"}],
            "trustBoundaries":[{"name":"Operator boundary","description":"Local user invokes the program"}]
        },"openQuestions":["Which callers supply input?"]});
        let digest = render_threat_model_digest(&document).unwrap();
        assert!(digest.contains("Command line application"));
        assert!(digest.contains("app -> terminal"));
        assert!(digest.contains("Operator boundary"));
        assert!(digest.contains("Which callers supply input?"));
        assert!(!digest.contains("Modeled threats:"));
    }

    #[test]
    fn architecture_digest_is_bounded_and_discloses_omitted_elements() {
        let document = json!({"dfd":{"nodes":(0..50).map(|i|json!({"name":format!("node-{i}"),"description":"x".repeat(2000)})).collect::<Vec<_>>()}});
        let digest = render_threat_model_digest(&document).unwrap();
        assert!(digest.contains("38 additional elements omitted"));
        assert!(!digest.contains("node-12"));
        assert!(digest.len() < 6000);
        assert!(digest.contains("..."));
    }

    #[test]
    fn context_enrichment_digest_keeps_claims_tied_to_source() {
        let enrichment = json!({
            "customMiddleware": [{
                "name": "operator guard",
                "purpose": "requires an operator token",
                "evidence": [{"filePath": "src/auth.rs", "line": 42}]
            }]
        });

        let digest = render_context_enrichment_digest(&enrichment).unwrap();

        assert_eq!(
            digest,
            "- middleware: operator guard · requires an operator token · src/auth.rs:42"
        );
    }

    #[test]
    fn scan_context_propagates_active_object_integrity_errors() {
        let target = tempfile::tempdir().unwrap();
        crate::capabilities::threat_model::save_persistent_threat_model(
            target.path(),
            &json!({
                "methodology": "stride",
                "threats": [{"title": "command execution"}]
            }),
            true,
        )
        .unwrap();
        crate::capabilities::threat_model::open_writable_threat_model_store(target.path()).unwrap();
        let active = crate::capabilities::threat_model::load_active_threat_model(target.path())
            .unwrap()
            .unwrap();
        let object = crate::capabilities::threat_model::threat_model_object_path(
            target.path(),
            &active.model_ref.sha256,
        )
        .unwrap();
        std::fs::write(object, b"{}").unwrap();

        let error = threat_model_scan_context(target.path()).unwrap_err();

        assert!(error.to_string().contains("failed SHA verification"));
    }
}
