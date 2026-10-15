use super::*;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Upper bound on the inventory file so a mispointed path (a corpus
/// tarball, a database) fails fast instead of being slurped into memory.
const SINK_INVENTORY_MAX_BYTES: u64 = 64 * 1024 * 1024;
const SINK_INVENTORY_MAX_ROWS: usize = 100_000;
/// Cap distinct callee signals per catalog entry; beyond this the
/// signals stop discriminating and only slow the discovery sweep.
const SINK_SIGNALS_PER_ENTRY: usize = 64;

/// One line of a sink-inventory JSONL file. Only the classification
/// fields matter for catalog import; call-site fields (`file`, `line`,
/// `code`) are provenance the discovery sweep re-derives itself.
#[derive(Debug, Deserialize)]
struct SinkInventoryRow {
    #[serde(default, alias = "class", alias = "vector")]
    tag: String,
    #[serde(default, alias = "symbol", alias = "function", alias = "sink")]
    callee: String,
    #[serde(default)]
    cwe: String,
    #[serde(default, alias = "lang")]
    language: String,
}

/// Keyword table mapping inventory tags/callees onto CWE classes.
/// First match wins, so more specific keywords come first (`printf`
/// before `int`, which it contains as a substring).
const SINK_CLASS_KEYWORDS: &[(&str, &str, &str, &str)] = &[
    ("exec", "CWE-78", "OS Command Injection", "command-injection"),
    ("spawn", "CWE-78", "OS Command Injection", "command-injection"),
    ("popen", "CWE-78", "OS Command Injection", "command-injection"),
    ("system", "CWE-78", "OS Command Injection", "command-injection"),
    ("shell", "CWE-78", "OS Command Injection", "command-injection"),
    ("cmd", "CWE-78", "OS Command Injection", "command-injection"),
    ("sql", "CWE-89", "SQL Injection", "sql-injection"),
    ("traversal", "CWE-22", "Path Traversal", "path-traversal"),
    ("path", "CWE-22", "Path Traversal", "path-traversal"),
    ("printf", "CWE-134", "Format String", "format-string"),
    ("format", "CWE-134", "Format String", "format-string"),
    ("fmt", "CWE-134", "Format String", "format-string"),
    ("deserial", "CWE-502", "Unsafe Deserialization", "deserialization"),
    ("pickle", "CWE-502", "Unsafe Deserialization", "deserialization"),
    ("unmarshal", "CWE-502", "Unsafe Deserialization", "deserialization"),
    ("xxe", "CWE-611", "XML External Entity", "xml-external-entity"),
    ("xml", "CWE-611", "XML External Entity", "xml-external-entity"),
    ("ssrf", "CWE-918", "Server-Side Request Forgery", "ssrf"),
    ("trunc", "CWE-190", "Integer Overflow or Truncation", "integer-overflow"),
    ("overflow", "CWE-190", "Integer Overflow or Truncation", "integer-overflow"),
    ("memcpy", "CWE-787", "Out-of-bounds Write", "memory-corruption"),
    ("mem", "CWE-787", "Out-of-bounds Write", "memory-corruption"),
    ("copy", "CWE-787", "Out-of-bounds Write", "memory-corruption"),
    ("buf", "CWE-787", "Out-of-bounds Write", "memory-corruption"),
    ("write", "CWE-787", "Out-of-bounds Write", "memory-corruption"),
];

const FALLBACK_SINK_CLASS: (&str, &str, &str) =
    ("CWE-20", "Imported Sink Inventory", "imported-sinks");

#[derive(Debug, Default)]
struct ImportedSinkClass {
    name: String,
    taint_class: String,
    callees: BTreeSet<String>,
    tags: BTreeSet<String>,
    rows: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TaintIrisNextSinkImportReport {
    pub(crate) target: String,
    pub(crate) status: String,
    pub(crate) catalog_path: String,
    pub(crate) sinks_path: String,
    pub(crate) imported_rows: usize,
    pub(crate) skipped_lines: usize,
    pub(crate) merged_existing: bool,
    pub(crate) entries: Vec<TaintIrisNextRankedCatalogEntry>,
}

impl TaintIrisNextSinkImportReport {
    pub(crate) fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "status": if self.skipped_lines == 0 { "completed" } else { "partial" },
            "warnings": sink_import_warnings(self.skipped_lines),
            "output": render_sink_import_summary(self),
            "data": serde_json::to_value(self).unwrap_or(Value::Null),
        })
    }
}

fn sink_import_warnings(skipped: usize) -> Vec<String> {
    if skipped == 0 {
        return Vec::new();
    }
    vec![format!(
        "Skipped {skipped} unusable inventory lines. Complete import is not claimed."
    )]
}

fn render_sink_import_summary(report: &TaintIrisNextSinkImportReport) -> String {
    let mut lines = vec![
        format!("taint-iris-next:import-sinks: {}", report.status),
        format!("inventory: {}", report.sinks_path),
        format!(
            "rows: {} imported, {} lines skipped",
            report.imported_rows, report.skipped_lines
        ),
        "Catalog metadata only. No discovery ran; source and scope freshness are not assessed."
            .to_string(),
        format!("catalog: {}", report.catalog_path),
        format!(
            "entries: {}{}",
            report.entries.len(),
            if report.merged_existing {
                " (merged into existing target catalog)"
            } else {
                ""
            }
        ),
    ];
    lines.extend(sink_import_warnings(report.skipped_lines));
    for entry in &report.entries {
        lines.push(format!(
            "- {}: {} [{}] {} sink signals",
            entry.cwe,
            entry.name,
            entry.taint_class,
            entry.sink_signals.len()
        ));
    }
    lines.join("\n")
}

/// Deterministically import a JSONL sink inventory (one call-site row
/// per line) into the target-specific taint catalog that
/// `taint-iris-next:hunt` prefers over the static table. No agent
/// runtime is involved.
pub(crate) fn run_taint_iris_next_sink_import_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<TaintIrisNextSinkImportReport> {
    let canceled = || ctx.is_cancelled();
    ensure_import_active(&canceled)?;
    let target = resolve_tool_target(input, ctx)?;
    let sinks_path = required_sink_inventory_path(input)?;
    let raw = read_sink_inventory(&sinks_path)?;
    let (rows, skipped_lines) = parse_sink_inventory_rows(&raw, &canceled)?;
    require_usable_rows(&rows, &sinks_path, skipped_lines)?;
    let imported_rows = rows.len();
    let languages = imported_entry_languages(input, &rows);
    let imported = build_imported_entries(&rows, &languages, &sinks_path);
    let (entries, merged_existing) = merge_with_target_catalog(input, &target, imported)?;
    ensure_import_active(&canceled)?;
    persist_target_catalog(&target, &entries)?;
    Ok(TaintIrisNextSinkImportReport {
        target: target.display().to_string(),
        status: if skipped_lines == 0 {
            "imported"
        } else {
            "partial"
        }
        .to_string(),
        catalog_path: taint_iris_next_target_catalog_path(&target)
            .display()
            .to_string(),
        sinks_path: sinks_path.display().to_string(),
        imported_rows,
        skipped_lines,
        merged_existing,
        entries,
    })
}

fn ensure_import_active(canceled: &dyn Fn() -> bool) -> Result<()> {
    anyhow::ensure!(
        !canceled(),
        "Sink inventory import canceled; prior catalog was not replaced"
    );
    Ok(())
}

fn require_usable_rows(rows: &[SinkInventoryRow], path: &Path, skipped: usize) -> Result<()> {
    anyhow::ensure!(!rows.is_empty(),
        "no usable sink rows in {} ({} lines skipped): expected JSONL rows with a callee and optional tag/cwe/language",
        path.display(), skipped);
    Ok(())
}

fn required_sink_inventory_path(input: &Value) -> Result<PathBuf> {
    let raw = input
        .get("sinksPath")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("taint-iris-next:import-sinks requires a `sinksPath` JSONL file")
        })?;
    Ok(PathBuf::from(raw))
}

fn read_sink_inventory(path: &Path) -> Result<String> {
    let text = crate::bounded_file::read_utf8_text(path, SINK_INVENTORY_MAX_BYTES as usize)
        .with_context(|| format!("could not read bounded sink inventory {}", path.display()))?;
    anyhow::ensure!(
        !text.is_empty(),
        "sink inventory is empty: {}",
        path.display()
    );
    Ok(text)
}

fn parse_sink_inventory_rows(
    raw: &str,
    canceled: &dyn Fn() -> bool,
) -> Result<(Vec<SinkInventoryRow>, usize)> {
    let mut rows = Vec::new();
    let mut skipped = 0usize;
    let mut records = 0usize;
    for line in raw.lines() {
        ensure_import_active(canceled)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        records += 1;
        anyhow::ensure!(
            records <= SINK_INVENTORY_MAX_ROWS,
            "Sink inventory exceeds {} nonempty lines; prior catalog was not replaced",
            SINK_INVENTORY_MAX_ROWS
        );
        match serde_json::from_str::<SinkInventoryRow>(trimmed) {
            Ok(row) if !row.callee.trim().is_empty() => rows.push(row),
            _ => skipped += 1,
        }
    }
    Ok((rows, skipped))
}

/// Languages stamped on imported entries: an explicit `languages`
/// option wins, then per-row `language` fields, then `"any"` so the
/// entries apply regardless of what the context pass detected.
fn imported_entry_languages(input: &Value, rows: &[SinkInventoryRow]) -> Vec<String> {
    let explicit: Vec<String> = input
        .get("languages")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(|language| normalize_taint_next_language(language))
                .filter(|language| !language.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    if !explicit.is_empty() {
        return explicit;
    }
    let from_rows: Vec<String> = rows
        .iter()
        .map(|row| normalize_taint_next_language(&row.language))
        .filter(|language| !language.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if from_rows.is_empty() {
        vec!["any".to_string()]
    } else {
        from_rows
    }
}

/// Resolve a row to `(cwe, name, taint_class)`. An explicit per-row
/// `cwe` wins; otherwise the first keyword hit on the tag, then on the
/// callee; otherwise the CWE-20 fallback bucket.
fn classify_sink_row(row: &SinkInventoryRow) -> (String, String, String) {
    let explicit = normalize_taint_next_cwe(&row.cwe);
    if explicit.starts_with("CWE-") {
        return (explicit.clone(), explicit, "imported-sinks".to_string());
    }
    for haystack in [row.tag.to_lowercase(), row.callee.to_lowercase()] {
        for (keyword, cwe, name, taint_class) in SINK_CLASS_KEYWORDS {
            if haystack.contains(keyword) {
                return (cwe.to_string(), name.to_string(), taint_class.to_string());
            }
        }
    }
    let (cwe, name, taint_class) = FALLBACK_SINK_CLASS;
    (cwe.to_string(), name.to_string(), taint_class.to_string())
}

fn group_sink_rows(rows: &[SinkInventoryRow]) -> BTreeMap<String, ImportedSinkClass> {
    let mut classes: BTreeMap<String, ImportedSinkClass> = BTreeMap::new();
    for row in rows {
        let (cwe, name, taint_class) = classify_sink_row(row);
        let class = classes.entry(cwe).or_default();
        if class.name.is_empty() {
            class.name = name;
            class.taint_class = taint_class;
        }
        class.callees.insert(row.callee.trim().to_string());
        if !row.tag.trim().is_empty() {
            class.tags.insert(row.tag.trim().to_string());
        }
        class.rows += 1;
    }
    classes
}

fn build_imported_entries(
    rows: &[SinkInventoryRow],
    languages: &[String],
    sinks_path: &Path,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    let inventory_name = sinks_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| sinks_path.display().to_string());
    group_sink_rows(rows)
        .into_iter()
        .map(|(cwe, class)| imported_entry(cwe, class, languages, &inventory_name))
        .collect()
}

fn imported_entry(
    cwe: String,
    class: ImportedSinkClass,
    languages: &[String],
    inventory_name: &str,
) -> TaintIrisNextRankedCatalogEntry {
    let sink_signals: Vec<String> = class
        .callees
        .iter()
        .take(SINK_SIGNALS_PER_ENTRY)
        .map(|callee| format!("{callee}("))
        .collect();
    let (source_signals, sanitizer_signals) = static_catalog_signals(&cwe);
    let score = (100 + class.callees.len() as i32).min(400);
    let reason = format!(
        "imported {} sink call sites ({} distinct callees) from {} (tags: {})",
        class.rows,
        class.callees.len(),
        inventory_name,
        class.tags.iter().cloned().collect::<Vec<_>>().join(", ")
    );
    TaintIrisNextRankedCatalogEntry {
        cwe,
        name: class.name,
        taint_class: class.taint_class,
        languages: languages.to_vec(),
        source_signals,
        sink_signals,
        sanitizer_signals,
        structural_queries: Vec::new(),
        regex_markers: Vec::new(),
        score,
        reasons: vec![reason],
    }
}

/// Imported entries carry only sinks; seed sources/sanitizers from the
/// static catalog entry for the same CWE so the discovery sweep can
/// still link source→sink stories.
fn static_catalog_signals(cwe: &str) -> (Vec<String>, Vec<String>) {
    TAINT_IRIS_NEXT_CATALOG
        .iter()
        .find(|entry| entry.cwe == cwe)
        .map(|entry| {
            (
                entry.source_signals.iter().map(|s| s.to_string()).collect(),
                entry
                    .sanitizer_signals
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            )
        })
        .unwrap_or_default()
}

/// Union imported entries into the existing target catalog when
/// `merge` (default true) and a catalog exists; otherwise the imported
/// entries become the catalog.
fn merge_with_target_catalog(
    input: &Value,
    target: &Path,
    imported: Vec<TaintIrisNextRankedCatalogEntry>,
) -> Result<(Vec<TaintIrisNextRankedCatalogEntry>, bool)> {
    let merge = input.get("merge").and_then(Value::as_bool).unwrap_or(true);
    if !merge {
        return Ok((imported, false));
    }
    let existing = super::dynamic_catalog::load_target_catalog_for_merge(target)
        .context("Saved catalog cannot be merged. Inspect it or explicitly choose merge=false to replace it. Prior catalog was not changed.")?;
    Ok(match existing {
        Some(existing) => (merge_catalog_entries(existing, imported), true),
        None => (imported, false),
    })
}

fn merge_catalog_entries(
    existing: Vec<TaintIrisNextRankedCatalogEntry>,
    imported: Vec<TaintIrisNextRankedCatalogEntry>,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    let mut merged = existing;
    for entry in imported {
        match merged.iter_mut().find(|current| current.cwe == entry.cwe) {
            Some(current) => merge_entry_signals(current, entry),
            None => merged.push(entry),
        }
    }
    merged
}

fn merge_entry_signals(
    current: &mut TaintIrisNextRankedCatalogEntry,
    imported: TaintIrisNextRankedCatalogEntry,
) {
    let mut seen: BTreeSet<String> = current.sink_signals.iter().cloned().collect();
    for signal in imported.sink_signals {
        if seen.insert(signal.clone()) {
            current.sink_signals.push(signal);
        }
    }
    current.score = current.score.max(imported.score);
    for reason in imported.reasons {
        if !current.reasons.contains(&reason) {
            current.reasons.push(reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn row(tag: &str, callee: &str) -> SinkInventoryRow {
        SinkInventoryRow {
            tag: tag.to_string(),
            callee: callee.to_string(),
            cwe: String::new(),
            language: String::new(),
        }
    }

    #[test]
    fn classify_sink_row_maps_tags_callees_and_fallback() {
        assert_eq!(classify_sink_row(&row("exec-L0", "execvp")).0, "CWE-78");
        // Unknown tag falls through to the callee keyword.
        assert_eq!(classify_sink_row(&row("semantic", "memcpy")).0, "CWE-787");
        assert_eq!(classify_sink_row(&row("host2app", "Recv")).0, "CWE-20");
        // printf must not be swallowed by the `int` truncation keyword.
        assert_eq!(classify_sink_row(&row("", "vsnprintf")).0, "CWE-134");
    }

    #[test]
    fn explicit_row_cwe_wins_over_keywords() {
        let mut explicit = row("exec-L0", "execvp");
        explicit.cwe = "cwe-502".to_string();
        assert_eq!(classify_sink_row(&explicit).0, "CWE-502");
    }

    #[test]
    fn parse_sink_inventory_rows_skips_bad_lines() {
        let raw = concat!(
            "{\"tag\":\"exec-L0\",\"callee\":\"execvp\"}\n",
            "\n",
            "not json\n",
            "{\"tag\":\"exec-L0\"}\n",
            "{\"tag\":\"mem\",\"callee\":\"memcpy\"}\n",
        );
        let (rows, skipped) = parse_sink_inventory_rows(raw, &|| false).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(skipped, 2, "bad json + missing callee are both skipped");
    }

    #[test]
    fn parsing_checks_cancellation_between_inventory_lines() {
        let probes = std::cell::Cell::new(0);
        let canceled = || {
            let count = probes.get();
            probes.set(count + 1);
            count > 0
        };
        let result = parse_sink_inventory_rows(
            "{\"callee\":\"OwnedAlpha\"}\n{\"callee\":\"OwnedBeta\"}\n",
            &canceled,
        );
        assert!(result.unwrap_err().to_string().contains("canceled"));
        assert_eq!(probes.get(), 2);
    }

    #[test]
    fn build_imported_entries_groups_and_seeds_static_sources() {
        let rows = vec![
            row("exec-L0", "execvp"),
            row("exec-L0", "popen"),
            row("exec-L0", "execvp"),
        ];
        let entries = build_imported_entries(
            &rows,
            &["c".to_string()],
            Path::new("/tmp/app-sinks.jsonl"),
        );
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.cwe, "CWE-78");
        assert_eq!(
            entry.sink_signals,
            vec!["execvp(".to_string(), "popen(".to_string()]
        );
        assert!(
            !entry.source_signals.is_empty(),
            "sources should seed from the static CWE-78 catalog entry"
        );
        assert!(entry.reasons[0].contains("3 sink call sites"));
        assert!(entry.reasons[0].contains("app-sinks.jsonl"));
    }

    #[test]
    fn memsafety_rows_seed_sources_from_the_native_pack() {
        // mem-tagged inventory rows land on CWE-787, which the static
        // memory-safety pack now covers — sources must seed from it.
        let entries = build_imported_entries(
            &[row("mem", "SDDecompress")],
            &["cpp".to_string()],
            Path::new("sinks.jsonl"),
        );
        assert_eq!(entries[0].cwe, "CWE-787");
        assert!(
            entries[0].source_signals.contains(&"recv(".to_string()),
            "CWE-787 sources should seed from the static pack, got {:?}",
            entries[0].source_signals
        );
    }

    #[test]
    fn merge_catalog_entries_unions_sinks_and_keeps_existing() {
        let existing = vec![TaintIrisNextRankedCatalogEntry {
            cwe: "CWE-78".to_string(),
            name: "OS Command Injection".to_string(),
            taint_class: "command-injection".to_string(),
            languages: vec!["c".to_string()],
            source_signals: vec!["argv".to_string()],
            sink_signals: vec!["system(".to_string()],
            sanitizer_signals: vec![],
            structural_queries: vec![],
            regex_markers: vec![],
            score: 90,
            reasons: vec!["agent".to_string()],
        }];
        let imported = build_imported_entries(
            &[row("exec-L0", "execvp"), row("sql", "SqlExec")],
            &["c".to_string()],
            Path::new("sinks.jsonl"),
        );
        let merged = merge_catalog_entries(existing, imported);
        assert_eq!(merged.len(), 2);
        let exec = merged.iter().find(|e| e.cwe == "CWE-78").unwrap();
        assert_eq!(
            exec.sink_signals,
            vec!["system(".to_string(), "execvp(".to_string()]
        );
        assert_eq!(exec.source_signals, vec!["argv".to_string()]);
        assert!(merged.iter().any(|e| e.cwe == "CWE-89"));
    }

    #[test]
    fn imported_catalog_persists_and_loads_back() {
        let temp = tempdir().unwrap();
        let target = temp.path();
        std::fs::create_dir_all(target.join(".kuzushi")).unwrap();
        let entries = build_imported_entries(
            &[row("exec-L0", "execvp")],
            &["c".to_string()],
            Path::new("sinks.jsonl"),
        );
        persist_target_catalog(target, &entries).unwrap();
        let loaded = load_taint_iris_next_target_catalog(target).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].cwe, "CWE-78");
        assert_eq!(loaded[0].sink_signals, vec!["execvp(".to_string()]);
    }

    #[test]
    fn read_sink_inventory_rejects_missing_and_empty_files() {
        let temp = tempdir().unwrap();
        assert!(read_sink_inventory(&temp.path().join("absent.jsonl")).is_err());
        let empty = temp.path().join("empty.jsonl");
        std::fs::write(&empty, b"").unwrap();
        assert!(read_sink_inventory(&empty).is_err());
    }
}
