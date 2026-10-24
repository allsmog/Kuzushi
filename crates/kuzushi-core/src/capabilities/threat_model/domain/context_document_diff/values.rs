use super::*;

type Pending<'a> = (String, Option<&'a Value>, Option<&'a Value>);

pub(super) struct Location {
    pub section: ContextDifferenceSection,
    pub collection: Option<String>,
    pub identity: Option<String>,
    pub matching: ContextDifferenceMatching,
    pub before_base: Option<String>,
    pub after_base: Option<String>,
}

impl Location {
    pub(super) fn difference(
        &self,
        field: String,
        before: Option<&Value>,
        after: Option<&Value>,
    ) -> ContextValueDifference {
        ContextValueDifference {
            section: self.section,
            collection: self.collection.clone(),
            identity: self.identity.clone(),
            matching: self.matching,
            before_pointer: present_pointer(&self.before_base, &field, before),
            after_pointer: present_pointer(&self.after_base, &field, after),
            field,
            before: before.cloned(),
            after: after.cloned(),
        }
    }
}

fn present_pointer(base: &Option<String>, field: &str, value: Option<&Value>) -> Option<String> {
    value.and_then(|_| base.as_ref().map(|base| format!("{base}{field}")))
}

pub(super) fn differences(
    before: Option<&Value>,
    after: Option<&Value>,
    location: &Location,
) -> Vec<ContextValueDifference> {
    let mut pending = vec![(String::new(), before, after)];
    let mut changes = Vec::new();
    while let Some((field, before, after)) = pending.pop() {
        if before == after {
            continue;
        }
        if let Some(children) = object_children(&field, before, after) {
            pending.extend(children);
            continue;
        }
        changes.push(location.difference(field, before, after));
    }
    changes
}

fn object_children<'a>(
    field: &str,
    before: Option<&'a Value>,
    after: Option<&'a Value>,
) -> Option<Vec<Pending<'a>>> {
    let left = object_or_missing(before)?;
    let right = object_or_missing(after)?;
    let keys = left
        .into_iter()
        .flat_map(|map| map.keys())
        .chain(right.into_iter().flat_map(|map| map.keys()))
        .collect::<BTreeSet<_>>();
    if keys.is_empty() {
        return None;
    }
    Some(
        keys.into_iter()
            .rev()
            .map(|key| {
                (
                    child_pointer(field, key),
                    left.and_then(|map| map.get(key)),
                    right.and_then(|map| map.get(key)),
                )
            })
            .collect(),
    )
}

fn object_or_missing(value: Option<&Value>) -> Option<Option<&serde_json::Map<String, Value>>> {
    match value {
        Some(Value::Object(map)) => Some(Some(map)),
        None => Some(None),
        _ => None,
    }
}

fn child_pointer(parent: &str, key: &str) -> String {
    let key = key.replace('~', "~0").replace('/', "~1");
    format!("{parent}/{key}")
}
