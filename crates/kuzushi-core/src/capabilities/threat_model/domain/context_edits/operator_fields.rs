//! Operator architecture changes share the exact-copy boundary, never model regeneration.
use super::*;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFieldChoice {
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextEditConstraint {
    Text,
    SingleLine,
    Choice(Arc<[ContextFieldChoice]>),
}

impl ContextEditConstraint {
    pub fn validate(&self, text: &str) -> Result<()> {
        match self {
            Self::Text => Ok(()),
            Self::SingleLine => {
                anyhow::ensure!(
                    !text.trim().is_empty() && !text.chars().any(char::is_control),
                    "Enter nonempty text on one line"
                );
                Ok(())
            }
            Self::Choice(choices) => {
                anyhow::ensure!(
                    choices.iter().any(|choice| choice.value == text),
                    "Choose one of the available values"
                );
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextEditField {
    pub text: ContextTextField,
    pub constraint: ContextEditConstraint,
    pub regeneratable: bool,
}

pub fn context_operator_fields(document: &Value) -> Vec<ContextEditField> {
    let mut fields = context_text_fields(document)
        .into_iter()
        .map(|text| ContextEditField {
            text,
            constraint: ContextEditConstraint::Text,
            regeneratable: true,
        })
        .collect();
    append_node_fields(document, &mut fields);
    append_flow_fields(document, &mut fields);
    append_boundary_fields(document, &mut fields);
    fields
}

fn append_node_fields(document: &Value, fields: &mut Vec<ContextEditField>) {
    for (index, node) in object_rows(document, "/dfd/nodes") {
        let name = element_name(node);
        let base = format!("/dfd/nodes/{index}");
        for (key, label) in [("name", "Name"), ("trustZone", "Trust zone")] {
            append_field(
                document,
                fields,
                &base,
                key,
                &name,
                label,
                ContextEditConstraint::SingleLine,
            );
        }
        append_field(
            document,
            fields,
            &base,
            "type",
            &name,
            "Role",
            node_role_constraint(),
        );
    }
}

fn node_role_constraint() -> ContextEditConstraint {
    ContextEditConstraint::Choice(
        [
            ("process", "Process"),
            ("external-entity", "External participant"),
            ("data-store", "Data store"),
        ]
        .into_iter()
        .map(|(value, label)| ContextFieldChoice {
            value: value.into(),
            label: label.into(),
        })
        .collect::<Vec<_>>()
        .into(),
    )
}

fn append_flow_fields(document: &Value, fields: &mut Vec<ContextEditField>) {
    let choices: Arc<[ContextFieldChoice]> = node_choices(document).into();
    for (index, flow) in object_rows(document, "/dfd/flows") {
        let name = element_name(flow);
        let base = format!("/dfd/flows/{index}");
        append_field(
            document,
            fields,
            &base,
            "description",
            &name,
            "Flow description",
            ContextEditConstraint::Text,
        );
        for (key, label) in [
            ("sourceId", "Flow source"),
            ("targetId", "Flow destination"),
        ] {
            append_field(
                document,
                fields,
                &base,
                key,
                &name,
                label,
                ContextEditConstraint::Choice(choices.clone()),
            );
        }
    }
}

fn append_boundary_fields(document: &Value, fields: &mut Vec<ContextEditField>) {
    for (index, boundary) in object_rows(document, "/dfd/trustBoundaries") {
        let name = element_name(boundary);
        let base = format!("/dfd/trustBoundaries/{index}");
        append_field(
            document,
            fields,
            &base,
            "name",
            &name,
            "Boundary name",
            ContextEditConstraint::SingleLine,
        );
        append_field(
            document,
            fields,
            &base,
            "description",
            &name,
            "Boundary description",
            ContextEditConstraint::Text,
        );
    }
}

fn append_field(
    document: &Value,
    fields: &mut Vec<ContextEditField>,
    base: &str,
    key: &str,
    name: &str,
    label: &str,
    constraint: ContextEditConstraint,
) {
    fields.push(ContextEditField {
        text: text_field(
            document,
            format!("{base}/{key}"),
            format!("{name} · {label}"),
        ),
        constraint,
        regeneratable: false,
    });
}

fn object_rows<'a>(document: &'a Value, pointer: &str) -> impl Iterator<Item = (usize, &'a Value)> {
    rows(document, pointer)
        .iter()
        .enumerate()
        .filter(|(_, row)| row.is_object())
}

fn element_name(element: &Value) -> String {
    element
        .get("name")
        .or_else(|| element.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("Unnamed element")
        .into()
}

fn node_choices(document: &Value) -> Vec<ContextFieldChoice> {
    let mut unique = BTreeMap::new();
    for (_, node) in object_rows(document, "/dfd/nodes") {
        if let Some(id) = node
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| valid_choice_id(id))
        {
            unique.entry(id).or_insert_with(Vec::new).push(node);
        }
    }
    unique
        .into_iter()
        .filter(|(_, nodes)| nodes.len() == 1)
        .map(|(id, nodes)| ContextFieldChoice {
            value: id.into(),
            label: element_name(nodes[0]),
        })
        .collect()
}

fn valid_choice_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_CONTEXT_EDIT_BYTES && !id.chars().any(char::is_control)
}

pub fn apply_context_operator_edits(document: &Value, edits: &[ContextTextEdit]) -> Result<Value> {
    let fields = context_operator_fields(document)
        .into_iter()
        .map(|field| (field.text.pointer.clone(), field))
        .collect::<BTreeMap<_, _>>();
    for edit in edits {
        if let Some(field) = fields
            .get(&edit.pointer)
            .filter(|field| field.text.text != edit.text)
        {
            field
                .constraint
                .validate(&edit.text)
                .with_context(|| format!("Invalid context edit at {}", edit.pointer))?;
        }
    }
    let values = fields
        .into_iter()
        .map(|(pointer, field)| (pointer, field.text.text))
        .collect();
    apply_known_context_edits(document, edits, &values)
}

#[cfg(test)]
mod tests;
