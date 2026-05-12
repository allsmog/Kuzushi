use crate::capabilities::threat_intel::domain::{CatalogEntry, HuntKind};
use anyhow::{Context, Result};
use serde_json::{json, Value};

/// What kind of action the dispatcher chose for a given catalog entry.
/// `Dispatched` means we built a tool input and the orchestrator
/// should invoke the named tool. `SkippedSilently` is not used —
/// every skip carries a `reason` operators can see in the apply
/// result, per the no-silent-fallback rule.
#[derive(Debug, Clone)]
pub enum DispatchPlan {
    Dispatched { tool_name: &'static str, input: Value },
    Skipped { reason: String },
}

/// Translate a catalog entry into a concrete `(tool_name, input)`
/// invocation for the existing hunt modules, or a `Skipped` plan with
/// a clear operator-readable reason. Today only uaf-hunt entries
/// dispatch live; taint-iris-next entries return a `Skipped` plan
/// with a "catalog-extension not yet wired" reason. That's deliberate
/// — wiring taint-iris-next's catalog to consume threat-intel TOML is
/// a follow-up (the existing catalog is hardcoded Rust). The dispatch
/// shape demonstrates the architecture today, and the follow-up
/// surface area is named in the skip reason.
pub fn plan_for_entry(entry: &CatalogEntry) -> DispatchPlan {
    match &entry.hunt {
        HuntKind::UafHunt => plan_uaf_hunt(entry),
        HuntKind::TaintIrisNext => plan_taint_iris_next(entry),
        HuntKind::SystemsHunt => DispatchPlan::Skipped {
            reason: format!(
                "systems-hunt does not yet consume operator-supplied catalog entries; \
                 entry {:?} recorded as pending.",
                entry.id
            ),
        },
        HuntKind::Variant => DispatchPlan::Skipped {
            reason: format!(
                "variant:hunt requires a pre-lifted pattern (variant:lift-pattern); \
                 entry {:?} would need a fix-commit fingerprint that the harvester \
                 will produce in a later phase.",
                entry.id
            ),
        },
        HuntKind::Unsupported(raw) => DispatchPlan::Skipped {
            reason: format!(
                "unknown hunt discriminator {raw:?} in entry {:?}; \
                 supported: uaf-hunt, taint-iris-next, systems-hunt, variant",
                entry.id
            ),
        },
    }
}

fn plan_uaf_hunt(entry: &CatalogEntry) -> DispatchPlan {
    let sub = entry.hunt_config.get(entry.hunt.config_key());
    let alloc_free_pairs = match sub.and_then(|sub| sub.get("alloc_free_pairs")) {
        Some(value) => uaf_pairs_to_json(value, &entry.id),
        None => Ok(Value::Array(Vec::new())),
    };
    let pairs = match alloc_free_pairs {
        Ok(value) => value,
        Err(err) => {
            return DispatchPlan::Skipped {
                reason: format!(
                    "uaf-hunt entry {:?} has invalid `alloc_free_pairs`: {err:#}",
                    entry.id
                ),
            }
        }
    };
    let alloc_array = match pairs.as_array() {
        Some(items) if !items.is_empty() => items.clone(),
        _ => {
            return DispatchPlan::Skipped {
                reason: format!(
                    "uaf-hunt entry {:?} has no `alloc_free_pairs`; nothing to hunt",
                    entry.id
                ),
            }
        }
    };
    let max_findings = sub
        .and_then(|s| s.get("max_findings"))
        .and_then(|v| v.as_integer())
        .filter(|n| *n > 0)
        .unwrap_or(10) as u64;
    let max_agent_steps = sub
        .and_then(|s| s.get("max_agent_steps"))
        .and_then(|v| v.as_integer())
        .filter(|n| *n > 0)
        .unwrap_or(120) as u64;
    let input = json!({
        "allocFreePairs": Value::Array(alloc_array),
        "maxFindings": max_findings,
        "maxAgentSteps": max_agent_steps,
    });
    DispatchPlan::Dispatched {
        tool_name: "uaf-hunt:hunt",
        input,
    }
}

fn plan_taint_iris_next(entry: &CatalogEntry) -> DispatchPlan {
    let sub = match entry.hunt_config.get(entry.hunt.config_key()) {
        Some(value) => value,
        None => {
            return DispatchPlan::Skipped {
                reason: format!(
                    "taint-iris-next entry {:?} has no `[entry.taint_iris_next]` subtable; \
                     declare at least `taint_class` and `sink_signals` to dispatch",
                    entry.id
                ),
            }
        }
    };
    let json_entry = match toml_subtable_to_catalog_json(entry, sub) {
        Ok(value) => value,
        Err(err) => {
            return DispatchPlan::Skipped {
                reason: format!(
                    "taint-iris-next entry {:?} has invalid subtable: {err:#}",
                    entry.id
                ),
            }
        }
    };
    let input = json!({
        "mode": "hunt",
        "extraCatalogEntries": [json_entry],
    });
    DispatchPlan::Dispatched {
        tool_name: "taint-iris-next:hunt",
        input,
    }
}

fn toml_subtable_to_catalog_json(entry: &CatalogEntry, sub: &toml::Value) -> Result<Value> {
    let table = sub.as_table().context("subtable must be a TOML table")?;
    let taint_class = table
        .get("taint_class")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("threat-intel-{}", entry.cwe.to_ascii_lowercase()));
    let name = table
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if entry.title.is_empty() {
                format!("threat-intel {}", entry.id)
            } else {
                entry.title.clone()
            }
        });
    let languages = toml_string_array(table, "languages")?;
    let source_signals = toml_string_array(table, "source_signals")?;
    let sink_signals = toml_string_array(table, "sink_signals")?;
    let sanitizer_signals = toml_string_array(table, "sanitizer_signals")?;
    let structural_queries = toml_string_array(table, "structural_queries")?;
    Ok(json!({
        "cwe": entry.cwe,
        "name": name,
        "taintClass": taint_class,
        "languages": languages,
        "sourceSignals": source_signals,
        "sinkSignals": sink_signals,
        "sanitizerSignals": sanitizer_signals,
        "structuralQueries": structural_queries,
    }))
}

fn toml_string_array(table: &toml::value::Table, key: &str) -> Result<Vec<String>> {
    let Some(value) = table.get(key) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .with_context(|| format!("`{key}` must be an array of strings"))?;
    items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            item.as_str()
                .map(str::to_string)
                .with_context(|| format!("`{key}[{idx}]` must be a string"))
        })
        .collect()
}

fn uaf_pairs_to_json(value: &toml::Value, entry_id: &str) -> Result<Value> {
    let items = value
        .as_array()
        .with_context(|| format!("`alloc_free_pairs` in {entry_id:?} must be an array"))?;
    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let table = item.as_table().with_context(|| {
            format!("`alloc_free_pairs[{idx}]` in {entry_id:?} must be a TOML table")
        })?;
        let alloc = table
            .get("alloc")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .with_context(|| {
                format!("`alloc_free_pairs[{idx}].alloc` in {entry_id:?} is required")
            })?
            .to_string();
        let free = table
            .get("free")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .with_context(|| {
                format!("`alloc_free_pairs[{idx}].free` in {entry_id:?} is required")
            })?
            .to_string();
        out.push(json!({"alloc": alloc, "free": free}));
    }
    Ok(Value::Array(out))
}
