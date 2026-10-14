use super::*;

struct KeyedTextField {
    identity: String,
    field: ContextTextField,
}

pub(super) fn compare_context_text(before: &Value, after: &Value) -> Vec<ContextTextDifference> {
    let previous = keyed_fields(before);
    let current = keyed_fields(after);
    let ambiguous = duplicate_identities(&previous)
        .union(&duplicate_identities(&current))
        .cloned()
        .collect::<BTreeSet<_>>();
    let previous = field_index(previous, &ambiguous);
    let current = field_index(current, &ambiguous);
    previous
        .keys()
        .chain(current.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|key| difference(previous.get(key), current.get(key)))
        .collect()
}

fn keyed_fields(document: &Value) -> Vec<KeyedTextField> {
    context_text_fields(document)
        .into_iter()
        .map(|field| KeyedTextField {
            identity: comparison_identity(document, &field.pointer),
            field,
        })
        .collect()
}

fn comparison_identity(document: &Value, pointer: &str) -> String {
    if pointer == "/systemContext" {
        return "0:overview".into();
    }
    component_identity(document, pointer)
        .or_else(|| question_identity(document, pointer))
        .unwrap_or_else(|| format!("3:pointer:{pointer}"))
}

fn component_identity(document: &Value, pointer: &str) -> Option<String> {
    let (index, field) = pointer.strip_prefix("/dfd/nodes/")?.split_once('/')?;
    let id = document
        .pointer(&format!("/dfd/nodes/{index}"))?
        .get("id")?
        .as_str()?;
    Some(format!("1:component:{id}:{field}"))
}

fn question_identity(document: &Value, pointer: &str) -> Option<String> {
    let (index, _) = pointer.strip_prefix("/openQuestions/")?.split_once('/')?;
    let question = document.pointer(&format!("/openQuestions/{index}"))?;
    question
        .get("id")
        .and_then(Value::as_str)
        .map(|id| format!("2:question-id:{id}"))
        .or_else(|| question_prompt(question).map(|text| format!("2:question-text:{text}")))
}

fn question_prompt(question: &Value) -> Option<&str> {
    question.as_str().or_else(|| {
        question
            .get("question")
            .or_else(|| question.get("description"))
            .and_then(Value::as_str)
    })
}

fn duplicate_identities(fields: &[KeyedTextField]) -> BTreeSet<String> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for field in fields {
        *counts.entry(&field.identity).or_default() += 1;
    }
    counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(key, _)| key.into())
        .collect()
}

fn field_index(
    fields: Vec<KeyedTextField>,
    ambiguous: &BTreeSet<String>,
) -> BTreeMap<String, ContextTextField> {
    fields
        .into_iter()
        .map(|field| {
            let identity = if ambiguous.contains(&field.identity) {
                format!("3:pointer:{}", field.field.pointer)
            } else {
                field.identity
            };
            (identity, field.field)
        })
        .collect()
}

fn difference(
    before: Option<&ContextTextField>,
    after: Option<&ContextTextField>,
) -> Option<ContextTextDifference> {
    let field = after.or(before)?;
    let original = before.map(|field| field.text.as_str()).unwrap_or_default();
    let revised = after.map(|field| field.text.as_str()).unwrap_or_default();
    (original != revised).then(|| ContextTextDifference {
        pointer: field.pointer.clone(),
        label: field.label.clone(),
        before: original.into(),
        after: revised.into(),
    })
}
