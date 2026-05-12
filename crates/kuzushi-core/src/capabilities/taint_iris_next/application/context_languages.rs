use super::*;

pub(crate) fn taint_iris_next_context_languages(context: Option<&Value>) -> Vec<String> {
    context
        .and_then(|value| value.pointer("/repoContext/languages"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(normalize_taint_next_language)
                .filter(|language| !language.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn taint_iris_next_context_keywords(
    context: Option<&Value>,
    target: &Path,
) -> Result<String> {
    let mut parts = Vec::new();
    if let Some(context) = context {
        if let Some(repo_context) = context.get("repoContext") {
            parts.push(repo_context.to_string());
        }
    }
    for file in [
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "go.mod",
        "pom.xml",
    ] {
        let path = target.join(file);
        if let Ok(raw) = fs::read_to_string(path) {
            parts.push(raw);
        }
    }
    Ok(parts.join("\n").to_ascii_lowercase())
}

pub(crate) fn collect_taint_iris_next_cwes(value: Option<&Value>) -> BTreeSet<String> {
    let mut cwes = BTreeSet::new();
    if let Some(value) = value {
        collect_taint_iris_next_cwes_inner(value, &mut cwes);
    }
    cwes
}

pub(crate) fn collect_taint_iris_next_cwes_inner(value: &Value, cwes: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            for token in text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-') {
                let normalized = normalize_taint_next_cwe(token);
                if normalized.starts_with("CWE-") {
                    cwes.insert(normalized);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_taint_iris_next_cwes_inner(item, cwes);
            }
        }
        Value::Object(object) => {
            for value in object.values() {
                collect_taint_iris_next_cwes_inner(value, cwes);
            }
        }
        _ => {}
    }
}

/// Structured attack-surface hints harvested from the threat-model
/// document's `attackSurface` field (when threat-model:build populated
/// it). Empty / missing fields collapse to empty vecs — callers treat
/// "no hints" as "use the static catalog only".
#[derive(Debug, Clone, Default)]
pub(crate) struct TaintIrisNextAttackSurfaceHints {
    pub(crate) entry_points: Vec<String>,
    pub(crate) external_sinks: Vec<String>,
    pub(crate) role_gates: Vec<String>,
}

impl TaintIrisNextAttackSurfaceHints {
    pub(crate) fn is_empty(&self) -> bool {
        self.entry_points.is_empty() && self.external_sinks.is_empty() && self.role_gates.is_empty()
    }
}

/// Walk a `ThreatModelDocument` JSON value and lift the optional
/// `attackSurface` block into a flat hints struct that
/// `rank_taint_iris_next_catalog` and the agent prompt can consume.
/// Tolerates the field being absent, partially populated, or
/// schema-drifted — anything not matching the expected shape is
/// silently dropped instead of failing the hunt.
pub(crate) fn collect_taint_iris_next_attack_surface_hints(
    value: Option<&Value>,
) -> TaintIrisNextAttackSurfaceHints {
    let Some(root) = value else {
        return TaintIrisNextAttackSurfaceHints::default();
    };
    let attack_surface = root
        .get("attackSurface")
        .or_else(|| root.get("attack_surface"));
    let Some(attack_surface) = attack_surface else {
        return TaintIrisNextAttackSurfaceHints::default();
    };
    TaintIrisNextAttackSurfaceHints {
        entry_points: collect_named_strings(attack_surface, "entryPoints", "entry_points"),
        external_sinks: collect_named_strings(attack_surface, "externalSinks", "external_sinks"),
        role_gates: collect_role_gates(attack_surface),
    }
}

fn collect_named_strings(root: &Value, primary: &str, fallback: &str) -> Vec<String> {
    let array = root
        .get(primary)
        .or_else(|| root.get(fallback))
        .and_then(Value::as_array);
    let Some(array) = array else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::with_capacity(array.len());
    for item in array {
        if let Some(name) = extract_attack_surface_name(item) {
            out.push(name);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Role-gate entries pair a check (`superuser`, `has_privs_of_role`)
/// with a guarded API. We extract both names so the agent can probe
/// either direction with `joern.callers_of` /
/// `tree_sitter:callers`.
fn collect_role_gates(root: &Value) -> Vec<String> {
    let Some(array) = root
        .get("roleGates")
        .or_else(|| root.get("role_gates"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::with_capacity(array.len() * 2);
    for item in array {
        for key in ["check", "guarded", "name"] {
            if let Some(name) = item.get(key).and_then(Value::as_str) {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn extract_attack_surface_name(item: &Value) -> Option<String> {
    if let Some(s) = item.as_str() {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
        return None;
    }
    if let Some(s) = item.get("name").and_then(Value::as_str) {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}
