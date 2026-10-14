//! Shared source selection for supplied context. No reads or persistence.
use anyhow::{Context, Result};
use serde_json::Value;

pub(crate) enum ThreatModelImportSource<'a> {
    Inline(&'a Value),
    File(&'a str),
}

/// Validate source presence without reading the document. Content validation
/// and bounded file reading remain the executor's responsibility.
pub fn validate_threat_model_import_source(input: &Value) -> Result<()> {
    select_import_source(input).map(|_| ())
}

pub(crate) fn select_import_source(input: &Value) -> Result<ThreatModelImportSource<'_>> {
    if let Some(document) = input.get("document").filter(|document| !document.is_null()) {
        return Ok(ThreatModelImportSource::Inline(document));
    }
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .context("Choose a context JSON path or supply an inline document before importing")?;
    Ok(ThreatModelImportSource::File(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_null_blank_and_invalid_paths_require_an_explicit_source() {
        for input in [
            json!({}),
            json!({"document":null}),
            json!({"path":"  "}),
            json!({"path":7}),
        ] {
            assert!(validate_threat_model_import_source(&input).is_err());
        }
    }

    #[test]
    fn inline_precedence_and_null_fallback_preserve_the_existing_contract() {
        let inline = json!({"document":{"title":"Owned context"},"path":"unused.json"});
        let ThreatModelImportSource::Inline(document) = select_import_source(&inline).unwrap()
        else {
            panic!("inline input must retain precedence")
        };
        assert_eq!(document, &inline["document"]);
        let file = json!({"document":null,"path":"  owned.json  "});
        let ThreatModelImportSource::File(path) = select_import_source(&file).unwrap() else {
            panic!("null inline input must use its path")
        };
        assert_eq!(path, "owned.json");
    }

    #[test]
    fn preflight_does_not_open_or_validate_file_contents() {
        assert!(validate_threat_model_import_source(
            &json!({"path":"/nonexistent/owned-context.json"})
        )
        .is_ok());
        assert!(validate_threat_model_import_source(&json!({"document":false})).is_ok());
    }
}
