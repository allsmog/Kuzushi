use crate::capabilities::threat_intel::application::regression_gate::RegressionGateOutcome;
use crate::capabilities::threat_intel::domain::HuntKind;
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use anyhow::{Context, Result};
use serde_json::{json, Value};

#[derive(Debug)]
pub(super) enum HarvestedEntry {
    Entry(HarvestedCatalogEntry),
    Skipped { reason: String },
}

#[derive(Debug)]
pub(super) struct HarvestedCatalogEntry {
    pub(super) id: String,
    pub(super) cve: String,
    pub(super) title: String,
    pub(super) cwe: String,
    pub(super) severity: String,
    pub(super) hunt: HuntKind,
    pub(super) source_signals: Vec<String>,
    pub(super) sink_signals: Vec<String>,
    pub(super) sanitizer_signals: Vec<String>,
    pub(super) structural_queries: Vec<String>,
    pub(super) languages: Vec<String>,
    pub(super) affected_files: Vec<String>,
    pub(super) confidence: String,
    pub(super) description: String,
    pub(super) fetched_record: Value,
    pub(super) fetched_pattern: Value,
    pub(super) gate_outcome: Option<RegressionGateOutcome>,
    pub(super) extraction_receipt: Value,
}

pub(super) fn harvest_one(
    cve: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: &mut impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<HarvestedEntry> {
    let record = match fetch_cve_record(cve, input, ctx, runtime, dispatch_tool)? {
        Ok(record) => record,
        Err(reason) => return Ok(HarvestedEntry::Skipped { reason }),
    };
    let extracted =
        match extract_fix_pattern(cve, record.clone(), input, ctx, runtime, dispatch_tool)? {
            Ok(pattern) => pattern,
            Err(reason) => return Ok(HarvestedEntry::Skipped { reason }),
        };
    let mut entry = catalog_entry_from_pattern(cve, record, extracted["data"]["pattern"].clone());
    entry.extraction_receipt = extracted;
    Ok(HarvestedEntry::Entry(entry))
}

fn fetch_cve_record(
    cve: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: &mut impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<std::result::Result<Value, String>> {
    let mut child = json!({"id":cve});
    copy_harvest_options(
        input,
        &mut child,
        &["offline", "fixtures", "maxMetadataBytes", "binary"],
    );
    let fetched = dispatch_tool("ndiff:fetch-cve", child, ctx, runtime)
        .with_context(|| format!("ndiff:fetch-cve {cve} failed"))?;
    if fetched.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(Err(fetch_skip_reason(&fetched)));
    }
    let Some(record) = fetched
        .get("data")
        .and_then(|data| data.get("record"))
        .cloned()
    else {
        return Ok(Err(
            "ndiff:fetch-cve returned ok but no `data.record`".to_string()
        ));
    };
    Ok(Ok(record))
}

fn extract_fix_pattern(
    cve: &str,
    record: Value,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: &mut impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<std::result::Result<Value, String>> {
    let child = extraction_child_input(record, input);
    let pattern = dispatch_tool("ndiff:extract-fix-pattern", child, ctx, runtime)
        .with_context(|| format!("ndiff:extract-fix-pattern {cve} failed"))?;
    if pattern.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(Err(pattern_skip_reason(&pattern)));
    }
    let Some(_) = pattern.get("data").and_then(|data| data.get("pattern")) else {
        return Ok(Err(
            "ndiff:extract-fix-pattern returned ok but no `data.pattern`".to_string(),
        ));
    };
    Ok(Ok(pattern))
}

fn extraction_child_input(record: Value, input: &Value) -> Value {
    let mut child = json!({"record":record});
    copy_harvest_options(
        input,
        &mut child,
        &[
            "offline",
            "patchFixtures",
            "maxMetadataBytes",
            "maxPatchBytes",
            "maxSourceBytes",
            "maxContextBytes",
            "thinkingLevel",
            "maxOutputTokens",
            "maxModelTurns",
            "model",
            "binary",
        ],
    );
    child
}

fn copy_harvest_options(input: &Value, child: &mut Value, keys: &[&str]) {
    for key in keys {
        if let Some(value) = input.get(*key) {
            child[*key] = value.clone();
        }
    }
}

fn fetch_skip_reason(fetched: &Value) -> String {
    fetched
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or("ndiff:fetch-cve did not return a usable record")
        .to_string()
}

fn pattern_skip_reason(pattern: &Value) -> String {
    pattern
        .get("output")
        .and_then(Value::as_str)
        .unwrap_or("ndiff:extract-fix-pattern returned an unusable response")
        .to_string()
}

pub(super) fn catalog_entry_from_pattern(
    cve: &str,
    record: Value,
    pattern: Value,
) -> HarvestedCatalogEntry {
    let cwe = first_cwe(&pattern, &record).unwrap_or_else(|| "CWE-Other".to_string());
    HarvestedCatalogEntry {
        id: sanitize_entry_id(&format!("redis-{cve}")),
        cve: cve.to_string(),
        title: title_from_record_or_pattern(cve, &record, &pattern),
        severity: nvd_severity(&record).unwrap_or_else(|| "high".to_string()),
        hunt: hunt_kind_for_cwe(&cwe),
        source_signals: pattern_signals_from_vulnerable_shape(&pattern),
        sink_signals: pattern_signals_from_detection_query(&pattern),
        sanitizer_signals: pattern_signals_from_fix_shape(&pattern),
        structural_queries: pattern_keywords(&pattern),
        languages: pattern_languages(&pattern),
        affected_files: pattern_affected_files(&record),
        confidence: string_field_or_default(&pattern, "confidence", "MEDIUM"),
        description: string_field_or_default(&pattern, "description", ""),
        fetched_record: record,
        fetched_pattern: pattern,
        gate_outcome: None,
        extraction_receipt: Value::Null,
        cwe,
    }
}

fn title_from_record_or_pattern(cve: &str, record: &Value, pattern: &Value) -> String {
    record
        .get("description")
        .and_then(Value::as_str)
        .map(first_sentence)
        .unwrap_or_else(|| pattern_description(pattern).unwrap_or_else(|| cve.to_string()))
}

fn hunt_kind_for_cwe(cwe: &str) -> HuntKind {
    match cwe.to_ascii_uppercase().as_str() {
        "CWE-416" | "CWE-415" | "CWE-364" | "CWE-367" | "CWE-672" => HuntKind::UafHunt,
        _ => HuntKind::TaintIrisNext,
    }
}

fn first_cwe(pattern: &Value, record: &Value) -> Option<String> {
    first_array_string(pattern, "cwe").or_else(|| first_array_string(record, "cwes"))
}

fn first_array_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn pattern_description(pattern: &Value) -> Option<String> {
    pattern
        .get("description")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn first_sentence(text: &str) -> String {
    let trimmed = text.trim();
    if let Some(end) = trimmed.find(". ") {
        return trimmed[..=end].trim_end_matches(". ").to_string();
    }
    trimmed.chars().take(160).collect::<String>()
}

fn nvd_severity(record: &Value) -> Option<String> {
    record.get("severity").and_then(Value::as_str).map(|raw| {
        match raw.to_ascii_uppercase().as_str() {
            "CRITICAL" => "critical".to_string(),
            "HIGH" => "high".to_string(),
            "MEDIUM" | "MED" => "medium".to_string(),
            "LOW" => "low".to_string(),
            _ => "high".to_string(),
        }
    })
}

fn pattern_signals_from_vulnerable_shape(pattern: &Value) -> Vec<String> {
    string_field_split(pattern, "vulnerableShape")
}

fn pattern_signals_from_detection_query(pattern: &Value) -> Vec<String> {
    let mut signals = string_field_split(pattern, "detectionQuery");
    signals.extend(string_field_split(pattern, "fixShape"));
    dedup_string_vec(signals)
}

fn pattern_signals_from_fix_shape(pattern: &Value) -> Vec<String> {
    string_field_split(pattern, "fixShape")
}

fn pattern_keywords(pattern: &Value) -> Vec<String> {
    string_array_field(pattern, "keywords", str::to_string)
}

fn pattern_languages(pattern: &Value) -> Vec<String> {
    string_array_field(pattern, "languages", str::to_ascii_lowercase)
}

fn pattern_affected_files(record: &Value) -> Vec<String> {
    record
        .get("affectedFiles")
        .or_else(|| record.get("affected_files"))
        .and_then(Value::as_array)
        .map(|items| collect_string_items(items, str::to_string))
        .unwrap_or_default()
}

fn string_array_field(value: &Value, key: &str, map: fn(&str) -> String) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| collect_string_items(items, map))
        .unwrap_or_default()
}

fn collect_string_items(items: &[Value], map: fn(&str) -> String) -> Vec<String> {
    items
        .iter()
        .filter_map(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(map)
        .collect()
}

fn string_field_split(pattern: &Value, key: &str) -> Vec<String> {
    let raw = pattern.get(key).and_then(Value::as_str).unwrap_or("");
    raw.split(|c: char| matches!(c, ',' | ';' | '\n'))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .take(8)
        .map(str::to_string)
        .collect()
}

fn string_field_or_default(pattern: &Value, key: &str, default: &str) -> String {
    pattern
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

fn dedup_string_vec(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

fn sanitize_entry_id(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase()
}

#[cfg(test)]
#[path = "harvest_entry_tests.rs"]
mod tests;
