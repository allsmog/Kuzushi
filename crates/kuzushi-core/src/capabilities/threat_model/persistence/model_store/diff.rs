use super::*;

const MAX_DIFF_CHANGES: usize = 100;
const MAX_VALUE_SUMMARY_CHARS: usize = 160;

pub fn inspect_threat_model_mirror_diff(root: &Path) -> Result<ThreatModelMirrorDiff> {
    let active = load_active_threat_model(root)?.context("no active threat model to inspect")?;
    let mirror = load_mirror_for_diff(root)?;
    let mirror_sha256 = document_sha256(&mirror)?;
    let mut changes = Vec::new();
    let mut truncated = false;
    collect_changes(
        "",
        Some(&active.document),
        Some(&mirror),
        &mut changes,
        &mut truncated,
    );
    Ok(ThreatModelMirrorDiff {
        active: active.model_ref,
        mirror_sha256,
        changes,
        truncated,
    })
}

fn load_mirror_for_diff(root: &Path) -> Result<Value> {
    match super::super::store::inspect_legacy_threat_model(root)? {
        super::super::store::LegacyMirrorInspection::Document(document) => Ok(document),
        super::super::store::LegacyMirrorInspection::Missing => {
            anyhow::bail!("compatibility mirror is missing")
        }
        super::super::store::LegacyMirrorInspection::Unadoptable { sha256, reason } => {
            anyhow::bail!("compatibility mirror {sha256} cannot be diffed because it {reason}")
        }
    }
}

fn collect_changes(
    pointer: &str,
    active: Option<&Value>,
    mirror: Option<&Value>,
    changes: &mut Vec<ThreatModelJsonChange>,
    truncated: &mut bool,
) {
    if diff_collection_complete(active, mirror, changes, truncated) {
        return;
    }
    match (active, mirror) {
        (Some(Value::Object(left)), Some(Value::Object(right))) => {
            collect_object_changes(pointer, left, right, changes, truncated);
        }
        _ => changes.push(ThreatModelJsonChange {
            pointer: normalized_pointer(pointer),
            active: active.map(value_summary),
            mirror: mirror.map(value_summary),
        }),
    }
}

fn diff_collection_complete(
    active: Option<&Value>,
    mirror: Option<&Value>,
    changes: &[ThreatModelJsonChange],
    truncated: &mut bool,
) -> bool {
    if active == mirror || *truncated {
        return true;
    }
    if changes.len() < MAX_DIFF_CHANGES {
        return false;
    }
    *truncated = true;
    true
}

fn collect_object_changes(
    pointer: &str,
    active: &serde_json::Map<String, Value>,
    mirror: &serde_json::Map<String, Value>,
    changes: &mut Vec<ThreatModelJsonChange>,
    truncated: &mut bool,
) {
    let keys = active.keys().chain(mirror.keys()).collect::<BTreeSet<_>>();
    for key in keys {
        collect_changes(
            &child_pointer(pointer, key),
            active.get(key),
            mirror.get(key),
            changes,
            truncated,
        );
    }
}

fn child_pointer(parent: &str, key: &str) -> String {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{escaped}")
}

fn normalized_pointer(pointer: &str) -> String {
    if pointer.is_empty() {
        "/".to_string()
    } else {
        pointer.to_string()
    }
}

fn value_summary(value: &Value) -> String {
    let raw = match value {
        Value::Array(rows) => format!("[{} items]", rows.len()),
        Value::Object(fields) => format!("{{{} keys}}", fields.len()),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "<unprintable>".to_string()),
    };
    truncate_chars(&raw, MAX_VALUE_SUMMARY_CHARS)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut clipped = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    clipped.push('…');
    clipped
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diff_reports_json_pointers_without_mutating_the_store() {
        let root = tempfile::tempdir().unwrap();
        let original = document("managed", "old");
        let committed = commit_threat_model_revision(root.path(), &original, request()).unwrap();
        let edited = document("edited", "new");
        super::super::super::store::write_persistent_threat_model_unchecked(root.path(), &edited)
            .unwrap();

        let report = inspect_threat_model_mirror_diff(root.path()).unwrap();

        assert_eq!(report.active, committed.model_ref);
        assert_eq!(report.changes.len(), 2);
        assert!(report
            .changes
            .iter()
            .any(|row| row.pointer == "/summary/text"));
        assert!(report.changes.iter().any(|row| row.pointer == "/threats"));
        assert_eq!(
            load_active_threat_model(root.path())
                .unwrap()
                .unwrap()
                .document,
            original
        );
    }

    fn document(summary: &str, threat: &str) -> Value {
        json!({
            "version": "2.0",
            "methodology": "stride",
            "dfd": {"nodes": [{"id": "app"}], "flows": [], "trustBoundaries": []},
            "threats": [{"id": threat, "targetElementIds": ["app"]}],
            "summary": {"text": summary}
        })
    }

    fn request() -> ThreatModelCommit {
        ThreatModelCommit {
            model_id: None,
            new_model: false,
            label: "Root".to_string(),
            scope: ScopeRef {
                scope_id: "root".to_string(),
                rel_path: PathBuf::from("."),
                project_model_sha256: format!("sha256:{}", "1".repeat(64)),
                target_revision: "test".to_string(),
            },
            methodology: "stride".to_string(),
            source: ThreatModelRevisionSource::Build,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "test".to_string(),
        }
    }
}
