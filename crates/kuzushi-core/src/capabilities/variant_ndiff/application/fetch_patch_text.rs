use super::*;

pub(crate) fn fetch_patch_text(url: &str, input: &Value) -> Result<Option<String>> {
    if let Some(text) = patch_fixture(url, input) {
        return Ok(Some(text));
    }
    if offline_patch_fetch(input) {
        return Ok(None);
    }
    let path = PathBuf::from(url);
    if path.exists() {
        return read_local_patch(&path);
    }
    curl_text(&patch_fetch_url(url), input, "ndiff:extract-fix-pattern")
}

fn patch_fixture(url: &str, input: &Value) -> Option<String> {
    input
        .get("patchFixtures")
        .or_else(|| input.get("patch_fixtures"))
        .and_then(Value::as_object)
        .and_then(|fixtures| fixtures.get(url))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn offline_patch_fetch(input: &Value) -> bool {
    input
        .get("offline")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn read_local_patch(path: &Path) -> Result<Option<String>> {
    crate::bounded_file::read_utf8_text(path, 16 * 1024 * 1024)
        .map(Some)
        .with_context(|| format!("Could not read patch file {}", path.display()))
}

fn patch_fetch_url(url: &str) -> String {
    let needs_patch_suffix = url.starts_with("https://github.com/")
        && (url.contains("/commit/") || url.contains("/pull/"))
        && !url.ends_with(".patch")
        && !url.ends_with(".diff");
    if needs_patch_suffix {
        format!("{url}.patch")
    } else {
        url.to_string()
    }
}

pub(crate) fn curl_json(url: &str, input: &Value, tool: &str) -> Result<Value> {
    let text = curl_text(url, input, tool)?.context("curl returned no response body")?;
    serde_json::from_str(&text).with_context(|| format!("{tool} could not parse JSON from {url}"))
}

pub(crate) fn curl_text(url: &str, input: &Value, tool: &str) -> Result<Option<String>> {
    let binary = input
        .get("curlBinary")
        .or_else(|| input.get("curl_binary"))
        .or_else(|| input.get("binary"))
        .and_then(Value::as_str)
        .unwrap_or("curl");
    let mut command = Command::new(binary);
    command
        .args(["-fsSL", "--max-time", "15", "-H", "Accept: text/plain"])
        .arg(url);
    let output = crate::bounded_subprocess::output(&mut command, "curl patch fetch").with_context(|| {
        format!("{tool} requires curl to fetch advisories or patches; install curl or pass patchText/offline fixtures")
    })?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

pub(crate) fn format_cve_summary(record: &CveRecord) -> String {
    let mut lines = vec![format!(
        "{} ({})",
        record.id,
        record.source.to_ascii_uppercase()
    )];
    if let Some(severity) = &record.severity {
        lines.push(match record.cvss_score {
            Some(score) => format!("  Severity: {severity} ({score})"),
            None => format!("  Severity: {severity}"),
        });
    }
    if !record.cwes.is_empty() {
        lines.push(format!("  CWEs:     {}", record.cwes.join(", ")));
    }
    if let Some(published_at) = &record.published_at {
        lines.push(format!("  Published: {published_at}"));
    }
    lines.push(String::new());
    lines.push(record.description.trim().to_string());
    if !record.patches.is_empty() {
        lines.push(String::new());
        lines.push("Patches:".to_string());
        for patch in record.patches.iter().take(5) {
            lines.push(format!("  - {}", patch.url));
        }
    }
    lines
        .into_iter()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn require_runtime<'a>(
    tool: &str,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.with_context(|| {
        format!("{tool} requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.")
    })
}

pub(crate) fn require_model(
    tool: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        tool,
        input
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        ctx.config.model.as_deref(),
    )
}
