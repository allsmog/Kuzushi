use serde_json::Value;
use std::path::{Path, PathBuf};

const ENTRY_POINTS_FILE: &str = "entry-points.json";
const MAX_ENTRY_POINTS_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapEvidenceFacts {
    pub files_indexed: usize,
    pub entry_points: usize,
    pub concrete_nodes: usize,
    pub flows: usize,
    pub threats: usize,
    pub explicit_import: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapEvidenceAdequacy {
    Adequate,
    Inadequate,
}

impl MapEvidenceAdequacy {
    pub const fn is_adequate(self) -> bool {
        matches!(self, Self::Adequate)
    }
}

pub fn assess_map_evidence(facts: &MapEvidenceFacts) -> MapEvidenceAdequacy {
    if facts.files_indexed > 0 || facts.entry_points > 0 {
        return MapEvidenceAdequacy::Adequate;
    }
    if facts.explicit_import && has_concrete_model_evidence(facts) {
        return MapEvidenceAdequacy::Adequate;
    }
    if has_concrete_model_evidence(facts) {
        return MapEvidenceAdequacy::Adequate;
    }
    MapEvidenceAdequacy::Inadequate
}

pub fn collect_map_evidence(target: &Path, run_refs: &[String]) -> MapEvidenceFacts {
    if !run_refs.is_empty() {
        return collect_referenced_run_evidence(target, run_refs);
    }
    collect_legacy_target_evidence(target)
}

/// Compatibility path for callers that predate canonical run references.
/// Referenced attempts never use these mutable target-global documents.
fn collect_legacy_target_evidence(target: &Path) -> MapEvidenceFacts {
    let context = read_json(target, &crate::context::context_snapshot_path(target));
    let entry_points = read_json(target, &entry_points_path(target));
    let threat_model = read_json(
        target,
        &crate::capabilities::persistent_threat_model_path(target),
    );
    facts_from_documents(
        context.as_ref(),
        entry_points.as_ref(),
        threat_model.as_ref(),
    )
}

fn collect_referenced_run_evidence(target: &Path, run_refs: &[String]) -> MapEvidenceFacts {
    run_refs
        .iter()
        .filter_map(|run_id| read_run_result(target, run_id))
        .map(|result| facts_from_run_result(&result))
        .fold(MapEvidenceFacts::default(), merge_evidence_facts)
}

fn facts_from_run_result(result: &Value) -> MapEvidenceFacts {
    let context = run_context_document(result);
    let entry_points = run_entry_points_document(result);
    let threat_model = run_threat_model_document(result);
    let mut facts = facts_from_documents(context, entry_points, threat_model);
    facts.explicit_import = result_sources_include_operator_input(result);
    facts
}

fn merge_evidence_facts(
    mut accumulated: MapEvidenceFacts,
    next: MapEvidenceFacts,
) -> MapEvidenceFacts {
    accumulated.files_indexed = accumulated.files_indexed.max(next.files_indexed);
    accumulated.entry_points = accumulated.entry_points.max(next.entry_points);
    accumulated.concrete_nodes = accumulated.concrete_nodes.max(next.concrete_nodes);
    accumulated.flows = accumulated.flows.max(next.flows);
    accumulated.threats = accumulated.threats.max(next.threats);
    accumulated.explicit_import |= next.explicit_import;
    accumulated
}

fn run_context_document(result: &Value) -> Option<&Value> {
    result
        .pointer("/data/snapshot")
        .or_else(|| result.pointer("/data/context"))
        .or_else(|| {
            result
                .pointer("/data")
                .filter(|data| data.get("filesIndexed").is_some())
        })
}

fn run_entry_points_document(result: &Value) -> Option<&Value> {
    result
        .pointer("/data")
        .filter(|data| data.get("total").is_some() || data.get("entryPoints").is_some())
}

fn run_threat_model_document(result: &Value) -> Option<&Value> {
    result
        .pointer("/data/document")
        .or_else(|| result.pointer("/structured/document"))
        .or_else(|| {
            result
                .pointer("/data")
                .filter(|data| data.get("dfd").is_some())
        })
}

/// The attempt-scoped verdict must not read as a target-scoped one. This
/// message once said "select another target" while the workspace held
/// perfectly good durable map artifacts — the attempt was empty, not the
/// target. Consult the workspace before wording the advice.
pub fn insufficient_map_evidence_message(target: &Path) -> String {
    let workspace = collect_legacy_target_evidence(target);
    if assess_map_evidence(&workspace).is_adequate() {
        return format!(
            "This attempt carried no map evidence, but `{}` already holds durable map artifacts ({}). Open the run to see why the attempt came back empty, or continue from the workspace state with `next`.",
            target.display(),
            workspace_evidence_summary(&workspace)
        );
    }
    format!(
        "This attempt carried no map evidence, and `{}` has no durable map artifacts yet. Build the context snapshot (`context build`) or import design evidence, then map again.",
        target.display()
    )
}

fn workspace_evidence_summary(facts: &MapEvidenceFacts) -> String {
    let mut parts = Vec::new();
    if facts.files_indexed > 0 {
        parts.push(format!("{} file(s) indexed", facts.files_indexed));
    }
    if facts.entry_points > 0 {
        parts.push(format!("{} entry point(s)", facts.entry_points));
    }
    if facts.threats > 0 {
        parts.push(format!("{} threat(s)", facts.threats));
    }
    if facts.flows > 0 {
        parts.push(format!("{} data flow(s)", facts.flows));
    }
    parts.join(" \u{b7} ")
}

pub fn threat_model_has_concrete_content(document: &Value) -> bool {
    let facts = threat_model_facts(document);
    has_concrete_model_evidence(&facts)
}

pub fn threat_model_has_concrete_dfd(document: &Value) -> bool {
    let facts = threat_model_facts(document);
    facts.flows > 0 || facts.concrete_nodes > 1
}

pub fn threat_model_is_scope_placeholder_only(document: &Value) -> bool {
    let total_nodes = array_len(document.pointer("/dfd/nodes"));
    let facts = threat_model_facts(document);
    total_nodes > 0 && facts.concrete_nodes == 0 && facts.flows == 0 && facts.threats == 0
}

fn has_concrete_model_evidence(facts: &MapEvidenceFacts) -> bool {
    facts.threats > 0 || facts.flows > 0 || facts.concrete_nodes > 1
}

fn facts_from_documents(
    context: Option<&Value>,
    entry_points: Option<&Value>,
    threat_model: Option<&Value>,
) -> MapEvidenceFacts {
    let mut facts = threat_model.map(threat_model_facts).unwrap_or_default();
    facts.files_indexed = context.map(context_file_count).unwrap_or_default();
    facts.entry_points = entry_points.map(entry_point_count).unwrap_or_default();
    facts
}

fn threat_model_facts(document: &Value) -> MapEvidenceFacts {
    let nodes = document
        .pointer("/dfd/nodes")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    MapEvidenceFacts {
        concrete_nodes: nodes
            .iter()
            .filter(|node| !is_scope_placeholder(node))
            .count(),
        flows: array_len(document.pointer("/dfd/flows")),
        threats: array_len(document.pointer("/threats")),
        ..MapEvidenceFacts::default()
    }
}

fn is_scope_placeholder(node: &Value) -> bool {
    field_contains(node, "trustZone", "analysis-scope")
        || field_contains(node, "name", "repository scope")
        || field_contains(node, "description", "repository target under analysis")
        || is_deterministic_repository_placeholder(node)
}

fn is_deterministic_repository_placeholder(node: &Value) -> bool {
    (matches_field(node, "id", "actor-external")
        && matches_field(node, "description", "Repository user or caller"))
        || (matches_field(node, "id", "app")
            && matches_field(node, "description", "Repository application boundary"))
}

fn matches_field(node: &Value, field: &str, expected: &str) -> bool {
    node.get(field).and_then(Value::as_str) == Some(expected)
}

fn field_contains(node: &Value, field: &str, needle: &str) -> bool {
    node.get(field)
        .and_then(Value::as_str)
        .is_some_and(|value| value.to_ascii_lowercase().contains(needle))
}

fn context_file_count(document: &Value) -> usize {
    document
        .get("filesIndexed")
        .or_else(|| document.pointer("/fileIndex/totalFiles"))
        .and_then(Value::as_u64)
        .unwrap_or_default() as usize
}

fn entry_point_count(document: &Value) -> usize {
    document
        .get("total")
        .and_then(Value::as_u64)
        .map(|count| count as usize)
        .unwrap_or_else(|| array_len(document.get("entryPoints")))
}

fn array_len(value: Option<&Value>) -> usize {
    value
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default()
}

fn read_run_result(target: &Path, run_id: &str) -> Option<Value> {
    let crate::RunArtifactRead::Ready { value, .. } =
        crate::read_run_artifact_text(target, run_id, "result.json")
    else {
        return None;
    };
    serde_json::from_str(&value).ok()
}

fn result_sources_include_operator_input(result: &Value) -> bool {
    result
        .pointer("/data/sources")
        .and_then(Value::as_array)
        .is_some_and(|sources| sources.iter().any(is_loaded_operator_source))
}

fn is_loaded_operator_source(source: &Value) -> bool {
    source.get("kind").and_then(Value::as_str) == Some("operator")
        && source.get("status").and_then(Value::as_str) == Some("loaded")
}

fn entry_points_path(target: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(ENTRY_POINTS_FILE)
}

fn read_json(target: &Path, path: &Path) -> Option<Value> {
    let limit = if path.file_name().and_then(|name| name.to_str())
        == Some(crate::context::CONTEXT_SNAPSHOT_FILE)
    {
        crate::context::MAX_CONTEXT_SNAPSHOT_BYTES
    } else {
        MAX_ENTRY_POINTS_BYTES
    };
    crate::bounded_file::read_utf8_text_within(target, path, limit)
        .ok()
        .and_then(|body| serde_json::from_str(&body).ok())
}

#[cfg(test)]
#[path = "map_evidence/tests.rs"]
mod tests;
