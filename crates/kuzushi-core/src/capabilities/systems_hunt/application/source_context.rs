use super::*;
use crate::workspace::inventory::{collect_source_prefixes, SourcePrefix, SourcePrefixLimits};

pub(super) struct SourceContextRequest<'a> {
    pub tool: &'a str,
    pub limits: SourcePrefixLimits,
    pub prompt_bytes: usize,
    pub selected: &'a dyn Fn(&str) -> bool,
}

pub(super) struct PreparedSources {
    pub files: Vec<(String, String)>,
    pub inspection: Value,
}

pub(super) fn prepare_sources(
    root: &Path,
    ctx: &ToolExecutionContext<'_>,
    request: SourceContextRequest<'_>,
) -> Result<PreparedSources> {
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let prefixes = collect_source_prefixes(
        root,
        request.limits,
        request.selected,
        &mut |entries| {
            if heartbeat.ready() {
                emit_progress(ctx, request.tool, entries);
            }
        },
        &|| ctx.is_cancelled(),
    )?;
    let total = prefixes.files.len();
    let (files, clipped) = prompt_sources(prefixes.files, request.prompt_bytes);
    anyhow::ensure!(!files.is_empty(),
        "No systems source excerpts available; no model request started. Inventory limit: {}. Omitted source files: {}. Available source bytes: {}.",
        prefixes.coverage["inventory"]["truncation"].as_str().unwrap_or("none recorded"),
        prefixes.coverage["omittedSourceFiles"], prefixes.coverage["maxSourceBytes"]);
    let mut inspection = prefixes.coverage;
    inspection["promptSourceFiles"] = json!(files.len());
    inspection["promptOmittedFiles"] = json!(total.saturating_sub(files.len()));
    inspection["promptTruncatedSourceFiles"] = json!(clipped);
    inspection["maxPromptSourceBytes"] = json!(request.prompt_bytes);
    if total > files.len() || clipped > 0 {
        inspection["status"] = json!("partial");
    }
    Ok(PreparedSources { files, inspection })
}

fn emit_progress(ctx: &ToolExecutionContext<'_>, tool: &str, entries: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                tool,
                format!("repository inventory · {entries} entries examined"),
            )
            .emit();
    }
}

fn prompt_sources(files: Vec<SourcePrefix>, budget: usize) -> (Vec<(String, String)>, usize) {
    let mut remaining = budget;
    let mut sources = Vec::new();
    let mut clipped = 0;
    for file in files {
        let overhead = file.relative.len().saturating_add(64);
        if remaining <= overhead {
            break;
        }
        let text = prefix(&file.text, remaining - overhead);
        clipped += usize::from(text.len() < file.text.len());
        remaining -= overhead + text.len();
        sources.push((file.relative, text));
    }
    (sources, clipped)
}

pub(super) fn supporting_context(
    root: &Path,
    input: &Value,
    inspection: &mut Value,
) -> Result<Value> {
    let context = project_context(root, input)?;
    let selected = crate::capabilities::threat_model::ThreatModelSelection::from_input(input)?;
    let threat = crate::capabilities::threat_model::load_selected_threat_model(root, &selected)?;
    Ok(
        json!({"context":excerpt(context.as_ref(), "context", inspection)?,
        "threatModel":excerpt(threat.as_ref(), "threatModel", inspection)?,
        "selectedThreatModelRef":input.get("threatModelRef").cloned().unwrap_or(json!("active at capture")),
        "selectedScanContextRef":input.get("scanContextRef").cloned().unwrap_or(json!("active at capture"))}),
    )
}

fn project_context(root: &Path, input: &Value) -> Result<Option<Value>> {
    if input.get("scanContextRef").is_some() {
        return crate::scan::selected_scan_context(root, input).map(|text| text.map(Value::String));
    }
    let path = crate::context::context_snapshot_path(root);
    match crate::bounded_file::read_utf8_text_within(root, &path, 16 * 1024 * 1024) {
        Ok(text) => Ok(Some(serde_json::from_str(&text).context(
            "Stored project context is malformed; repair it before model work",
        )?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn excerpt(value: Option<&Value>, label: &str, inspection: &mut Value) -> Result<Option<String>> {
    let Some(value) = value else {
        inspection[label] = json!({"status":"absent"});
        return Ok(None);
    };
    let text = match value.as_str() {
        Some(text) => text.to_owned(),
        None => serde_json::to_string(value)?,
    };
    let included = prefix(&text, 8192);
    let truncated = included.len() < text.len();
    inspection[label] = json!({"status":if truncated {"truncated"} else {"included"},
        "sourceBytes":text.len(),"includedBytes":included.len()});
    if truncated {
        inspection["status"] = json!("partial");
    }
    Ok(Some(included))
}

pub(super) fn prefix(text: &str, maximum: usize) -> String {
    let mut end = text.len().min(maximum);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].into()
}
