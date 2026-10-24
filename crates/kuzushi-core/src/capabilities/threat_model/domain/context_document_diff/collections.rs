use super::*;
use values::Location;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RowKey {
    Id(String),
    Position(usize),
}

struct Row<'a> {
    value: &'a Value,
    index: usize,
    identity: Option<&'a str>,
    matching: ContextDifferenceMatching,
}

pub(super) fn compare(
    path: &str,
    section: ContextDifferenceSection,
    before: Option<&Value>,
    after: Option<&Value>,
    result: &mut ContextDocumentDiff,
) {
    if before == after {
        return;
    }
    match (before, after) {
        (Some(Value::Array(left)), Some(Value::Array(right))) => {
            result
                .changes
                .extend(row_changes(path, section, left, right));
            if let Some(order) = order_change(path, left, right) {
                result.reordered_collections.push(order);
            }
        }
        _ => result.changes.extend(values::differences(
            before,
            after,
            &Location {
                section,
                collection: Some(path.into()),
                identity: None,
                matching: ContextDifferenceMatching::DocumentField,
                before_base: before.map(|_| path.into()),
                after_base: after.map(|_| path.into()),
            },
        )),
    }
}

fn row_changes(
    path: &str,
    section: ContextDifferenceSection,
    before: &[Value],
    after: &[Value],
) -> Vec<ContextValueDifference> {
    let ambiguous = duplicate_ids(before)
        .union(&duplicate_ids(after))
        .cloned()
        .collect::<BTreeSet<_>>();
    let left = indexed_rows(before, &ambiguous);
    let right = indexed_rows(after, &ambiguous);
    left.keys()
        .chain(right.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .flat_map(|key| {
            let previous = left.get(key);
            let current = right.get(key);
            let location = row_location(path, section, previous, current);
            compare_row(
                previous.map(|row| row.value),
                current.map(|row| row.value),
                &location,
            )
        })
        .collect()
}

fn compare_row(
    before: Option<&Value>,
    after: Option<&Value>,
    location: &Location,
) -> Vec<ContextValueDifference> {
    match (before, after) {
        (Some(_), Some(_)) => values::differences(before, after, location),
        _ => vec![location.difference(String::new(), before, after)],
    }
}

fn row_location(
    path: &str,
    section: ContextDifferenceSection,
    before: Option<&Row<'_>>,
    after: Option<&Row<'_>>,
) -> Location {
    let row = after
        .or(before)
        .expect("A union comparison key has at least one row");
    let matching = if before
        .into_iter()
        .chain(after)
        .any(|row| row.matching == ContextDifferenceMatching::AmbiguousPosition)
    {
        ContextDifferenceMatching::AmbiguousPosition
    } else {
        row.matching
    };
    Location {
        section,
        collection: Some(path.into()),
        identity: row.identity.map(str::to_owned),
        matching,
        before_base: before.map(|row| format!("{path}/{}", row.index)),
        after_base: after.map(|row| format!("{path}/{}", row.index)),
    }
}

fn row_id(row: &Value) -> Option<&str> {
    row.get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

fn duplicate_ids(rows: &[Value]) -> BTreeSet<String> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for id in rows.iter().filter_map(row_id) {
        *counts.entry(id).or_default() += 1;
    }
    counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(id, _)| id.into())
        .collect()
}

fn indexed_rows<'a>(rows: &'a [Value], ambiguous: &BTreeSet<String>) -> BTreeMap<RowKey, Row<'a>> {
    rows.iter()
        .enumerate()
        .map(|(index, value)| {
            let identity = row_id(value);
            let (key, matching) = match identity {
                Some(id) if !ambiguous.contains(id) => {
                    (RowKey::Id(id.into()), ContextDifferenceMatching::Id)
                }
                Some(_) => (
                    RowKey::Position(index),
                    ContextDifferenceMatching::AmbiguousPosition,
                ),
                None => (RowKey::Position(index), ContextDifferenceMatching::Position),
            };
            (
                key,
                Row {
                    value,
                    index,
                    identity,
                    matching,
                },
            )
        })
        .collect()
}

fn unique_order(rows: &[Value]) -> Option<Vec<String>> {
    let ids = rows.iter().map(row_id).collect::<Option<Vec<_>>>()?;
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return None;
    }
    Some(ids.into_iter().map(str::to_owned).collect())
}

fn order_change(
    path: &str,
    before: &[Value],
    after: &[Value],
) -> Option<ContextCollectionOrderDifference> {
    let before = unique_order(before)?;
    let after = unique_order(after)?;
    let same_members =
        before.iter().collect::<BTreeSet<_>>() == after.iter().collect::<BTreeSet<_>>();
    (same_members && before != after).then(|| ContextCollectionOrderDifference {
        collection: path.into(),
        before,
        after,
    })
}
