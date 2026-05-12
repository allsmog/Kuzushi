use crate::capabilities::threat_intel::application::regression_gate::{
    run_regression_gate, RegressionGateOutcome, RegressionGateStatus,
};
use crate::capabilities::threat_intel::domain::HuntKind;
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Harvest a threat-intel catalog by walking a list of CVE IDs and
/// converting each one's fix-commit context into a catalog entry.
///
/// Pipeline per CVE:
///   1. `ndiff:fetch-cve` — pull the advisory + patch references
///   2. `ndiff:extract-fix-pattern` — LLM extracts source / sink /
///      sanitizer / detection-query from the fix diff
///   3. translate the fix-pattern shape into a catalog-entry shape
///      and serialise as TOML
///
/// The dispatch goes through the supplied `dispatch_tool` closure
/// (same shape as `apply`) so the harvester re-uses the existing
/// ndiff tools instead of duplicating their logic.
///
/// `outputPath` is the file the TOML is written to. Defaults to
/// `<target>/.kuzushi/catalogs/harvested.toml`. If the file exists,
/// the harvester appends entries — operators run harvest more than
/// once as new CVEs land.
pub fn harvest_threat_intel_catalog(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    mut dispatch_tool: impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<Value> {
    let cves = parse_cve_list(input)?;
    let output_path = resolve_output_path(input, ctx)?;
    let gate_enabled = input
        .get("regressionGate")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let accept_rejected = input
        .get("acceptRejected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut per_cve = Vec::with_capacity(cves.len());
    let mut new_entries = Vec::new();
    let mut stats = HarvestStats::default();
    let gate = HarvestGateConfig {
        enabled: gate_enabled,
        accept_rejected,
        target: ctx.workspace.map(|w| w.root().to_path_buf()),
    };

    for cve in &cves {
        harvest_cve_into_catalog(
            cve,
            ctx,
            runtime,
            &mut dispatch_tool,
            &gate,
            &mut stats,
            &mut per_cve,
            &mut new_entries,
        );
    }

    let toml_text = render_catalog_toml(&new_entries, &output_path)?;
    write_catalog_with_append(&output_path, &toml_text)?;

    Ok(json!({
        "ok": true,
        "data": {
            "outputPath": output_path.display().to_string(),
            "perCve": per_cve,
        },
        "summary": {
            "totalCves": cves.len(),
            "harvested": stats.harvested,
            "skipped": stats.skipped,
            "failed": stats.failed,
            "regressionGate": {
                "enabled": gate_enabled,
                "acceptRejected": accept_rejected,
                "validated": stats.validated_by_gate,
                "unverified": stats.unverified_by_gate,
                "rejected": stats.rejected_by_gate,
            },
        },
    }))
}

#[derive(Default)]
struct HarvestStats {
    harvested: u32,
    skipped: u32,
    failed: u32,
    rejected_by_gate: u32,
    validated_by_gate: u32,
    unverified_by_gate: u32,
}

struct HarvestGateConfig {
    enabled: bool,
    accept_rejected: bool,
    target: Option<PathBuf>,
}

fn harvest_cve_into_catalog(
    cve: &str,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: &mut impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
    gate: &HarvestGateConfig,
    stats: &mut HarvestStats,
    per_cve: &mut Vec<Value>,
    new_entries: &mut Vec<HarvestedCatalogEntry>,
) {
    match harvest_one(cve, ctx, runtime, dispatch_tool) {
        Ok(HarvestedEntry::Entry(entry)) => {
            record_harvested_entry(cve, entry, gate, stats, per_cve, new_entries);
        }
        Ok(HarvestedEntry::Skipped { reason }) => {
            stats.skipped += 1;
            per_cve.push(json!({"cve": cve, "status": "skipped", "reason": reason}));
        }
        Err(err) => {
            stats.failed += 1;
            per_cve.push(json!({
                "cve": cve,
                "status": "failed",
                "error": format!("{err:#}"),
            }));
        }
    }
}

fn record_harvested_entry(
    cve: &str,
    mut entry: HarvestedCatalogEntry,
    gate: &HarvestGateConfig,
    stats: &mut HarvestStats,
    per_cve: &mut Vec<Value>,
    new_entries: &mut Vec<HarvestedCatalogEntry>,
) {
    let gate_outcome = harvest_gate_outcome(gate, cve, &entry);
    record_gate_stats(stats, gate_outcome.as_ref());
    if let Some(outcome) = &gate_outcome {
        entry.gate_outcome = Some(outcome.clone());
    }
    if harvest_rejected_by_gate(gate, gate_outcome.as_ref()) {
        stats.skipped += 1;
        per_cve.push(rejected_gate_row(cve, gate_outcome.as_ref()));
        return;
    }
    stats.harvested += 1;
    per_cve.push(harvested_entry_row(cve, &entry, gate_outcome));
    new_entries.push(entry);
}

fn harvest_gate_outcome(
    gate: &HarvestGateConfig,
    cve: &str,
    entry: &HarvestedCatalogEntry,
) -> Option<RegressionGateOutcome> {
    if !gate.enabled {
        return None;
    }
    Some(match gate.target.as_deref() {
        Some(target) => {
            gate_outcome_or_unverified(target, cve, &entry.fetched_record, &entry.fetched_pattern)
        }
        None => RegressionGateOutcome::unverified(
            "no workspace target available; pass --target <repo> to enable the regression gate"
                .to_string(),
        ),
    })
}

fn record_gate_stats(stats: &mut HarvestStats, outcome: Option<&RegressionGateOutcome>) {
    match outcome.map(|outcome| &outcome.status) {
        Some(RegressionGateStatus::Validated) => stats.validated_by_gate += 1,
        Some(RegressionGateStatus::Unverified) => stats.unverified_by_gate += 1,
        Some(RegressionGateStatus::Rejected) => stats.rejected_by_gate += 1,
        None => {}
    }
}

fn harvest_rejected_by_gate(
    gate: &HarvestGateConfig,
    outcome: Option<&RegressionGateOutcome>,
) -> bool {
    outcome.is_some_and(|outcome| matches!(outcome.status, RegressionGateStatus::Rejected))
        && !gate.accept_rejected
}

fn rejected_gate_row(cve: &str, outcome: Option<&RegressionGateOutcome>) -> Value {
    json!({
        "cve": cve,
        "status": "rejected-by-gate",
        "reason": outcome.map(|o| o.reason.clone()),
        "preFixHits": outcome.and_then(|o| o.pre_fix_hits),
        "postFixHits": outcome.and_then(|o| o.post_fix_hits),
    })
}

fn harvested_entry_row(
    cve: &str,
    entry: &HarvestedCatalogEntry,
    gate_outcome: Option<RegressionGateOutcome>,
) -> Value {
    json!({
        "cve": cve,
        "status": "harvested",
        "entryId": entry.id,
        "hunt": entry.hunt.as_str(),
        "cwe": entry.cwe,
        "gate": gate_outcome,
    })
}

fn gate_outcome_or_unverified(
    target: &Path,
    cve: &str,
    record: &Value,
    pattern: &Value,
) -> RegressionGateOutcome {
    match run_regression_gate(target, cve, record, pattern) {
        Ok(outcome) => outcome,
        Err(err) => {
            RegressionGateOutcome::unverified(format!("regression-gate error for {cve}: {err:#}"))
        }
    }
}

#[derive(Debug)]
enum HarvestedEntry {
    Entry(HarvestedCatalogEntry),
    Skipped { reason: String },
}

#[derive(Debug)]
struct HarvestedCatalogEntry {
    id: String,
    cve: String,
    title: String,
    cwe: String,
    severity: String,
    hunt: HuntKind,
    source_signals: Vec<String>,
    sink_signals: Vec<String>,
    sanitizer_signals: Vec<String>,
    structural_queries: Vec<String>,
    languages: Vec<String>,
    affected_files: Vec<String>,
    confidence: String,
    description: String,
    /// Raw ndiff:fetch-cve `record` Value, kept so the regression gate
    /// can read patches/affectedFiles without re-fetching.
    fetched_record: Value,
    /// Raw ndiff:extract-fix-pattern `pattern` Value, kept for the
    /// same reason — `keywords` / `detectionQuery` feed the gate.
    fetched_pattern: Value,
    /// Set after the regression gate runs. None when the gate was
    /// disabled (`regressionGate: false` in the input).
    gate_outcome: Option<RegressionGateOutcome>,
}

fn parse_cve_list(input: &Value) -> Result<Vec<String>> {
    let raw = input
        .get("cves")
        .context("threat-intel:harvest requires `cves` (array of CVE IDs)")?;
    let items = raw
        .as_array()
        .context("threat-intel:harvest `cves` must be an array of strings")?;
    if items.is_empty() {
        anyhow::bail!("threat-intel:harvest `cves` is empty; pass at least one CVE id");
    }
    items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            item.as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .with_context(|| format!("cves[{idx}] must be a non-empty string"))
        })
        .collect()
}

fn resolve_output_path(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(explicit) = input
        .get("outputPath")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let path = PathBuf::from(explicit);
        return Ok(if path.is_absolute() {
            path
        } else if let Some(workspace) = ctx.workspace {
            workspace.root().join(path)
        } else {
            std::env::current_dir()
                .context("threat-intel: could not resolve current directory")?
                .join(path)
        });
    }
    let workspace = ctx.workspace.ok_or_else(|| {
        anyhow::anyhow!(
            "threat-intel:harvest needs a workspace target or an explicit `outputPath`. \
             Pass --target <repo> or `outputPath` in the input."
        )
    })?;
    Ok(workspace
        .root()
        .join(".kuzushi")
        .join("catalogs")
        .join("harvested.toml"))
}

fn harvest_one(
    cve: &str,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_tool: &mut impl FnMut(
        &str,
        Value,
        &ToolExecutionContext<'_>,
        Option<&dyn AgentRuntime>,
    ) -> Result<Value>,
) -> Result<HarvestedEntry> {
    let fetched = dispatch_tool("ndiff:fetch-cve", json!({"id": cve}), ctx, runtime)
        .with_context(|| format!("ndiff:fetch-cve {cve} failed"))?;
    if fetched.get("ok").and_then(Value::as_bool) != Some(true) {
        let reason = fetched
            .get("output")
            .and_then(Value::as_str)
            .unwrap_or("ndiff:fetch-cve did not return a usable record")
            .to_string();
        return Ok(HarvestedEntry::Skipped { reason });
    }
    let record = match fetched.get("data").and_then(|d| d.get("record")) {
        Some(value) => value.clone(),
        None => {
            return Ok(HarvestedEntry::Skipped {
                reason: "ndiff:fetch-cve returned ok but no `data.record`".to_string(),
            })
        }
    };

    let pattern_input = json!({"record": record});
    let pattern = dispatch_tool("ndiff:extract-fix-pattern", pattern_input, ctx, runtime)
        .with_context(|| format!("ndiff:extract-fix-pattern {cve} failed"))?;
    if pattern.get("ok").and_then(Value::as_bool) != Some(true) {
        let reason = pattern
            .get("output")
            .and_then(Value::as_str)
            .unwrap_or("ndiff:extract-fix-pattern returned an unusable response")
            .to_string();
        return Ok(HarvestedEntry::Skipped { reason });
    }
    let pattern_data = match pattern.get("data").and_then(|d| d.get("pattern")) {
        Some(value) => value.clone(),
        None => {
            return Ok(HarvestedEntry::Skipped {
                reason: "ndiff:extract-fix-pattern returned ok but no `data.pattern`".to_string(),
            })
        }
    };

    Ok(HarvestedEntry::Entry(catalog_entry_from_pattern(
        cve,
        record,
        pattern_data,
    )))
}

fn catalog_entry_from_pattern(cve: &str, record: Value, pattern: Value) -> HarvestedCatalogEntry {
    let cwe = first_cwe(&pattern, &record).unwrap_or_else(|| "CWE-Other".to_string());
    let title = record
        .get("description")
        .and_then(Value::as_str)
        .map(first_sentence)
        .unwrap_or_else(|| pattern_description(&pattern).unwrap_or_else(|| cve.to_string()));
    let severity = nvd_severity(&record).unwrap_or_else(|| "high".to_string());
    let id = sanitize_entry_id(&format!("redis-{}", cve));
    let hunt = hunt_kind_for_cwe(&cwe);
    let source_signals = pattern_signals_from_vulnerable_shape(&pattern);
    let sink_signals = pattern_signals_from_detection_query(&pattern);
    let sanitizer_signals = pattern_signals_from_fix_shape(&pattern);
    let structural_queries = pattern_keywords(&pattern);
    let languages = pattern_languages(&pattern);
    let affected_files = pattern_affected_files(&record);
    let confidence = pattern
        .get("confidence")
        .and_then(Value::as_str)
        .unwrap_or("MEDIUM")
        .to_string();
    let description = pattern
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    HarvestedCatalogEntry {
        id,
        cve: cve.to_string(),
        title,
        cwe,
        severity,
        hunt,
        source_signals,
        sink_signals,
        sanitizer_signals,
        structural_queries,
        languages,
        affected_files,
        confidence,
        description,
        fetched_record: record,
        fetched_pattern: pattern,
        gate_outcome: None,
    }
}

/// Map a CWE to the hunt module best suited to detect it. Temporal /
/// lifetime classes go to uaf-hunt (the only scanner that walks the
/// call graph); everything else gets taint-iris-next, which is now
/// catalog-extendable.
fn hunt_kind_for_cwe(cwe: &str) -> HuntKind {
    match cwe.to_ascii_uppercase().as_str() {
        "CWE-416" | "CWE-415" | "CWE-364" | "CWE-367" | "CWE-672" => HuntKind::UafHunt,
        _ => HuntKind::TaintIrisNext,
    }
}

fn first_cwe(pattern: &Value, record: &Value) -> Option<String> {
    pattern
        .get("cwe")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            record
                .get("cwes")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
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
    pattern
        .get("keywords")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn pattern_languages(pattern: &Value) -> Vec<String> {
    pattern
        .get("languages")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default()
}

fn pattern_affected_files(record: &Value) -> Vec<String> {
    record
        .get("affectedFiles")
        .or_else(|| record.get("affected_files"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
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

fn render_catalog_toml(entries: &[HarvestedCatalogEntry], output_path: &Path) -> Result<String> {
    let mut out = String::new();
    if !output_path.exists() {
        out.push_str("# Auto-generated by threat-intel:harvest.\n");
        out.push_str("# Each entry was produced from one CVE's fix-commit context via\n");
        out.push_str("# ndiff:fetch-cve + ndiff:extract-fix-pattern. The signal arrays\n");
        out.push_str("# are LLM-extracted: review before promoting to a trusted catalog.\n\n");
        out.push_str("schema_version = \"1\"\n\n");
    }
    for entry in entries {
        render_entry_toml(&mut out, entry);
    }
    Ok(out)
}

fn render_entry_toml(buf: &mut String, entry: &HarvestedCatalogEntry) {
    buf.push_str("[[entry]]\n");
    push_toml_string(buf, "id", &entry.id);
    push_toml_string_array(buf, "cves", &[entry.cve.clone()]);
    push_toml_string(buf, "title", &entry.title);
    push_toml_string(buf, "cwe", &entry.cwe);
    push_toml_string(buf, "severity", &entry.severity);
    push_toml_string(buf, "provenance", &provenance_string(entry));
    push_toml_string(buf, "source_repo", "");
    push_toml_string(
        buf,
        "fix_commit",
        entry
            .gate_outcome
            .as_ref()
            .and_then(|outcome| outcome.fix_sha.as_deref())
            .unwrap_or(""),
    );
    push_toml_string(buf, "hunt", entry.hunt.as_str());

    let subtable = match entry.hunt {
        HuntKind::UafHunt => "uaf_hunt",
        HuntKind::TaintIrisNext => "taint_iris_next",
        HuntKind::SystemsHunt => "systems_hunt",
        HuntKind::Variant => "variant",
        HuntKind::Unsupported(_) => "unknown",
    };
    buf.push('\n');
    buf.push_str(&format!("[entry.{}]\n", subtable));
    match entry.hunt {
        HuntKind::UafHunt => render_uaf_hunt_subtable(buf, entry),
        HuntKind::TaintIrisNext => render_taint_iris_next_subtable(buf, entry),
        _ => render_taint_iris_next_subtable(buf, entry),
    }
    if !entry.description.is_empty() {
        push_toml_string(buf, "description", &entry.description);
    }
    buf.push('\n');
}

fn provenance_string(entry: &HarvestedCatalogEntry) -> String {
    let mut chunks = vec![format!(
        "harvested via threat-intel:harvest from {} (confidence={})",
        entry.cve, entry.confidence
    )];
    if let Some(outcome) = &entry.gate_outcome {
        let label = match outcome.status {
            crate::capabilities::threat_intel::application::regression_gate::RegressionGateStatus::Validated => "regression-gate=validated",
            crate::capabilities::threat_intel::application::regression_gate::RegressionGateStatus::Unverified => "regression-gate=unverified",
            crate::capabilities::threat_intel::application::regression_gate::RegressionGateStatus::Rejected => "regression-gate=rejected",
        };
        chunks.push(label.to_string());
        if let (Some(pre), Some(post)) = (outcome.pre_fix_hits, outcome.post_fix_hits) {
            chunks.push(format!("hits pre/post={pre}/{post}"));
        }
        if let Some(sha) = &outcome.fix_sha {
            chunks.push(format!("fix={}", &sha[..sha.len().min(12)]));
        }
    } else {
        chunks.push("regression-gate=disabled".to_string());
    }
    chunks.push("verify before trusting".to_string());
    chunks.join("; ")
}

fn render_uaf_hunt_subtable(buf: &mut String, entry: &HarvestedCatalogEntry) {
    // The harvester can't produce alloc/free pairs from the patch text
    // alone — they're project conventions, not patch artefacts. Emit
    // an empty array with an explanatory comment so the operator
    // fills them in before dispatch. Dispatch will skip the entry
    // with a clear reason in the meantime.
    buf.push_str("# alloc_free_pairs is intentionally empty — the harvester cannot infer\n");
    buf.push_str("# allocator/freeer names from a patch. Edit before promoting:\n");
    buf.push_str("alloc_free_pairs = []\n");
    if !entry.affected_files.is_empty() {
        push_toml_string_array(buf, "focus_files", &entry.affected_files);
    }
}

fn render_taint_iris_next_subtable(buf: &mut String, entry: &HarvestedCatalogEntry) {
    push_toml_string(buf, "taint_class", &taint_class_from_cwe(&entry.cwe));
    if !entry.languages.is_empty() {
        push_toml_string_array(buf, "languages", &entry.languages);
    }
    push_toml_string_array(buf, "source_signals", &entry.source_signals);
    push_toml_string_array(buf, "sink_signals", &entry.sink_signals);
    push_toml_string_array(buf, "sanitizer_signals", &entry.sanitizer_signals);
    push_toml_string_array(buf, "structural_queries", &entry.structural_queries);
    if !entry.affected_files.is_empty() {
        push_toml_string_array(buf, "affected_files", &entry.affected_files);
    }
}

fn taint_class_from_cwe(cwe: &str) -> String {
    match cwe.to_ascii_uppercase().as_str() {
        "CWE-79" => "xss".to_string(),
        "CWE-89" => "sql-injection".to_string(),
        "CWE-78" => "command-injection".to_string(),
        "CWE-22" => "path-traversal".to_string(),
        "CWE-94" => "code-injection".to_string(),
        "CWE-117" => "log-injection".to_string(),
        "CWE-190" => "integer-overflow".to_string(),
        "CWE-122" | "CWE-787" | "CWE-121" => "heap-buffer-overflow".to_string(),
        "CWE-502" => "deserialization".to_string(),
        "CWE-862" => "missing-authorization".to_string(),
        "CWE-918" => "ssrf".to_string(),
        _ => format!("threat-intel-{}", cwe.to_ascii_lowercase()),
    }
}

fn push_toml_string(buf: &mut String, key: &str, value: &str) {
    if value.is_empty() {
        buf.push_str(&format!("{key} = \"\"\n"));
    } else {
        buf.push_str(&format!("{key} = \"{}\"\n", escape_toml_string(value)));
    }
}

fn push_toml_string_array(buf: &mut String, key: &str, items: &[String]) {
    if items.is_empty() {
        buf.push_str(&format!("{key} = []\n"));
        return;
    }
    buf.push_str(&format!("{key} = [\n"));
    for item in items {
        buf.push_str(&format!("    \"{}\",\n", escape_toml_string(item)));
    }
    buf.push_str("]\n");
}

fn escape_toml_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn write_catalog_with_append(path: &Path, new_text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    if path.exists() {
        let mut existing = fs::read_to_string(path)
            .with_context(|| format!("could not read existing catalog at {}", path.display()))?;
        if !existing.ends_with('\n') {
            existing.push('\n');
        }
        existing.push_str(new_text);
        fs::write(path, existing)
            .with_context(|| format!("could not write catalog to {}", path.display()))?;
    } else {
        fs::write(path, new_text)
            .with_context(|| format!("could not write catalog to {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_cwes_to_uaf_hunt_or_taint_iris_next() {
        assert_eq!(hunt_kind_for_cwe("CWE-416"), HuntKind::UafHunt);
        assert_eq!(hunt_kind_for_cwe("CWE-415"), HuntKind::UafHunt);
        assert_eq!(hunt_kind_for_cwe("CWE-367"), HuntKind::UafHunt);
        assert_eq!(hunt_kind_for_cwe("CWE-190"), HuntKind::TaintIrisNext);
        assert_eq!(hunt_kind_for_cwe("CWE-79"), HuntKind::TaintIrisNext);
        assert_eq!(hunt_kind_for_cwe("CWE-122"), HuntKind::TaintIrisNext);
    }

    #[test]
    fn taint_class_from_cwe_covers_common_redis_cve_classes() {
        assert_eq!(taint_class_from_cwe("CWE-190"), "integer-overflow");
        assert_eq!(taint_class_from_cwe("CWE-122"), "heap-buffer-overflow");
        assert_eq!(taint_class_from_cwe("CWE-862"), "missing-authorization");
        assert_eq!(taint_class_from_cwe("CWE-78"), "command-injection");
        assert_eq!(
            taint_class_from_cwe("CWE-9999"),
            "threat-intel-cwe-9999",
            "unknown CWE falls back to a stable namespaced class"
        );
    }

    #[test]
    fn parse_cve_list_rejects_empty_array_with_clear_message() {
        let err = parse_cve_list(&serde_json::json!({"cves": []})).unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("empty"), "must name the problem: {chain}");
    }

    #[test]
    fn parse_cve_list_requires_cves_field() {
        let err = parse_cve_list(&serde_json::json!({})).unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("`cves`"), "must name the field: {chain}");
    }

    #[test]
    fn catalog_entry_from_pattern_picks_first_cwe_and_routes_uaf_to_uaf_hunt() {
        let record = serde_json::json!({
            "id": "CVE-2025-49844",
            "description": "Use-after-free in Lua client lifecycle.",
            "severity": "CRITICAL",
        });
        let pattern = serde_json::json!({
            "cwe": ["CWE-416"],
            "languages": ["c"],
            "vulnerableShape": "freed pointer dereferenced after freeClient",
            "fixShape": "guard with client->flags",
            "detectionQuery": "freeClient.*client->",
            "keywords": ["freeClient", "lua_client"],
            "description": "Lua client UAF",
            "confidence": "HIGH",
        });
        let entry = catalog_entry_from_pattern("CVE-2025-49844", record, pattern);
        assert_eq!(entry.cwe, "CWE-416");
        assert_eq!(entry.hunt, HuntKind::UafHunt);
        assert_eq!(entry.severity, "critical");
        assert_eq!(entry.id, "redis-cve-2025-49844");
        assert_eq!(entry.languages, vec!["c"]);
        assert!(!entry.source_signals.is_empty());
        assert!(!entry.structural_queries.is_empty());
    }

    #[test]
    fn rendered_toml_round_trips_through_the_loader() {
        let entry = HarvestedCatalogEntry {
            id: "redis-cve-test".to_string(),
            cve: "CVE-9999-0001".to_string(),
            title: "Test entry".to_string(),
            cwe: "CWE-190".to_string(),
            severity: "high".to_string(),
            hunt: HuntKind::TaintIrisNext,
            source_signals: vec!["external input".to_string(), "count argv".to_string()],
            sink_signals: vec!["zmalloc(count * sizeof(...))".to_string()],
            sanitizer_signals: vec!["bounds check".to_string()],
            structural_queries: vec!["XAUTOCLAIM".to_string()],
            languages: vec!["c".to_string()],
            affected_files: vec!["src/t_stream.c".to_string()],
            confidence: "HIGH".to_string(),
            description: "Stream count overflow".to_string(),
            fetched_record: serde_json::json!({}),
            fetched_pattern: serde_json::json!({}),
            gate_outcome: None,
        };
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("harvested.toml");
        let text = render_catalog_toml(&[entry], &path).unwrap();
        fs::write(&path, &text).unwrap();
        let parsed = crate::capabilities::threat_intel::parse_catalog_str(&text, &path).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].cwe, "CWE-190");
        assert_eq!(parsed[0].hunt, HuntKind::TaintIrisNext);
        let sub = parsed[0].hunt_config.get("taint_iris_next").unwrap();
        assert_eq!(
            sub.get("taint_class").unwrap().as_str(),
            Some("integer-overflow")
        );
    }

    #[test]
    fn rendered_toml_emits_uaf_subtable_for_uaf_hunt_entries() {
        let entry = HarvestedCatalogEntry {
            id: "redis-cve-uaf".to_string(),
            cve: "CVE-9999-0002".to_string(),
            title: "UAF".to_string(),
            cwe: "CWE-416".to_string(),
            severity: "critical".to_string(),
            hunt: HuntKind::UafHunt,
            source_signals: vec![],
            sink_signals: vec![],
            sanitizer_signals: vec![],
            structural_queries: vec![],
            languages: vec!["c".to_string()],
            affected_files: vec!["src/networking.c".to_string()],
            confidence: "HIGH".to_string(),
            description: "Client UAF".to_string(),
            fetched_record: serde_json::json!({}),
            fetched_pattern: serde_json::json!({}),
            gate_outcome: None,
        };
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("harvested.toml");
        let text = render_catalog_toml(&[entry], &path).unwrap();
        assert!(text.contains("[entry.uaf_hunt]"));
        assert!(text.contains("alloc_free_pairs = []"));
        assert!(text.contains("focus_files"));
        assert!(
            text.contains("intentionally empty"),
            "must explain why alloc_free_pairs is empty so the operator knows to fill it in"
        );
    }
}
