//! Read recorded reference fields without opening stores or granting authority.
use kuzushi_core::{scan::ScanContextRef, workspace::ScanScopeRef, ThreatModelRef};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

#[derive(Clone, Copy)]
pub(super) enum ReferenceKind {
    Scope,
    Architecture,
    Supplemental,
}

impl ReferenceKind {
    fn fields(self, value: &Value) -> Option<Vec<String>> {
        match self {
            Self::Scope => scope_fields(value),
            Self::Architecture => architecture_fields(value),
            Self::Supplemental => supplemental_fields(value),
        }
    }
}

pub(super) fn binding_lines(
    label: &str,
    kind: ReferenceKind,
    value: Option<&Value>,
) -> Vec<String> {
    match value {
        None => vec![format!("{label}: not recorded")],
        Some(Value::Null) => vec![format!("{label}: explicitly omitted")],
        Some(value) => recorded_lines(label, kind, value),
    }
}

fn recorded_lines(label: &str, kind: ReferenceKind, value: &Value) -> Vec<String> {
    let Some(fields) = kind.fields(value) else {
        return unrecognized_lines(label, value);
    };
    let mut lines = vec![format!("{label}: recorded reference")];
    lines.extend(fields.into_iter().map(|field| format!("  {field}")));
    lines
}

fn exact_reference<T: DeserializeOwned + Serialize>(value: &Value) -> Option<T> {
    let reference: T = serde_json::from_value(value.clone()).ok()?;
    (serde_json::to_value(&reference).ok()?.eq(value)).then_some(reference)
}

fn scope_fields(value: &Value) -> Option<Vec<String>> {
    let reference: ScanScopeRef = exact_reference(value)?;
    Some(vec![
        field("Scope id", &reference.scope_id),
        field("Proposal id", &reference.proposal.proposal_id),
        format!("Revision: {}", reference.proposal.revision),
        field("Record hash", &reference.proposal.record_hash),
    ])
}

fn architecture_fields(value: &Value) -> Option<Vec<String>> {
    let reference: ThreatModelRef = exact_reference(value)?;
    Some(vec![
        field("Model id", reference.model_id.as_str()),
        field("Revision id", reference.revision_id.as_str()),
        field("SHA256", &reference.sha256),
    ])
}

fn supplemental_fields(value: &Value) -> Option<Vec<String>> {
    let reference: ScanContextRef = exact_reference(value)?;
    Some(vec![
        format!("Schema: {}", reference.schema_version),
        field("Object kind", reference.object.kind.as_str()),
        field("Object hash", &reference.object.hash.to_string()),
        format!("Bytes: {}", reference.object.size_bytes),
    ])
}

fn field(label: &str, value: &str) -> String {
    let needs_quotes = value.is_empty() || value.chars().any(quote_character);
    let literal = if needs_quotes {
        Value::String(value.to_owned()).to_string()
    } else {
        value.to_owned()
    };
    format!("{label}: {literal}")
}

fn quote_character(character: char) -> bool {
    character.is_control() || character.is_whitespace() || matches!(character, '"' | '\\')
}

fn unrecognized_lines(label: &str, value: &Value) -> Vec<String> {
    let mut lines = vec![format!("{label}: unrecognized recorded format")];
    let text = serde_json::to_string_pretty(value)
        .unwrap_or_else(|_| "Reference could not be displayed".into());
    lines.extend(text.lines().map(|line| format!("  {line}")));
    lines
}

#[cfg(test)]
mod tests;
