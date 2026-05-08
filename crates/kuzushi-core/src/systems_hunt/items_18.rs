use super::prelude::*;
use super::*;

pub(crate) fn hardening_signals(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut out = Vec::new();
    for candidate in [
        "checked_",
        "saturating_",
        "validate",
        "guard",
        "assert",
        "bounds",
    ] {
        if lower.contains(candidate) {
            out.push(trim_line(line));
        }
    }
    out
}

#[derive(Debug, Clone)]
pub(crate) struct SurfaceAccumulator {
    pub(crate) file_path: String,
    pub(crate) start_line: u32,
    pub(crate) kind: String,
    pub(crate) score: i64,
    pub(crate) domains: BTreeSet<String>,
    pub(crate) reasons: BTreeSet<String>,
    pub(crate) attacker_controlled_fields: BTreeSet<String>,
    pub(crate) hardening_signals: BTreeSet<String>,
    pub(crate) evidence: Vec<SystemsSurfaceSignal>,
}

impl SurfaceAccumulator {
    pub(crate) fn new(file_path: String, kind: String, start_line: u32) -> Self {
        Self {
            file_path,
            start_line,
            kind,
            score: 0,
            domains: BTreeSet::new(),
            reasons: BTreeSet::new(),
            attacker_controlled_fields: BTreeSet::new(),
            hardening_signals: BTreeSet::new(),
            evidence: Vec::new(),
        }
    }

    pub(crate) fn finish(self) -> RankedSystemsSurface {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (&self.kind, &self.file_path).hash(&mut hasher);
        let id = format!("surface-{:016x}", hasher.finish());
        RankedSystemsSurface {
            id,
            file_path: self.file_path.clone(),
            start_line: self.start_line,
            display_name: Path::new(&self.file_path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(&self.file_path)
                .to_string(),
            kind: self.kind,
            score: self.score,
            domains: self.domains.into_iter().collect(),
            reasons: self.reasons.into_iter().collect(),
            attacker_controlled_fields: self.attacker_controlled_fields.into_iter().collect(),
            hardening_signals: self.hardening_signals.into_iter().collect(),
            evidence: self.evidence.into_iter().take(12).collect(),
        }
    }
}

pub(crate) fn parse_invariants(raw: &Value) -> Vec<SystemsInvariant> {
    let Some(items) = raw.get("invariants").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            let id = string_field(object.get("id"));
            let surface_id = string_field(object.get("surfaceId"));
            let summary = string_field(object.get("summary"));
            let statement = string_field(object.get("statement"));
            let rationale = string_field(object.get("rationale"));
            if id.is_empty()
                || surface_id.is_empty()
                || summary.is_empty()
                || statement.is_empty()
                || rationale.is_empty()
            {
                return None;
            }
            Some(SystemsInvariant {
                id,
                surface_id,
                kind: string_field(object.get("kind")),
                summary,
                statement,
                rationale,
                evidence: string_array(object.get("evidence")),
                attacker_controlled_fields: string_array(object.get("attackerControlledFields")),
                cheap_verifiable: object
                    .get("cheapVerifiable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}
