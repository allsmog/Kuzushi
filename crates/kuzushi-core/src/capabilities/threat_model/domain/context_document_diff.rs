//! Complete stored-context comparison. IDs match literally; ambiguous rows stay explicit.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
mod collections;
mod types;
mod values;
pub use types::*;

const COLLECTIONS: [(&str, ContextDifferenceSection); 12] = [
    ("/dfd/nodes", ContextDifferenceSection::Architecture),
    ("/dfd/flows", ContextDifferenceSection::Architecture),
    (
        "/dfd/trustBoundaries",
        ContextDifferenceSection::Architecture,
    ),
    ("/assets", ContextDifferenceSection::SecurityContext),
    (
        "/attackSurface/entryPoints",
        ContextDifferenceSection::SecurityContext,
    ),
    (
        "/attackSurface/roleGates",
        ContextDifferenceSection::SecurityContext,
    ),
    (
        "/attackSurface/externalSinks",
        ContextDifferenceSection::SecurityContext,
    ),
    (
        "/attackSurface/trustedCallers",
        ContextDifferenceSection::SecurityContext,
    ),
    ("/threats", ContextDifferenceSection::SecurityContext),
    (
        "/recommendedMitigations",
        ContextDifferenceSection::SecurityContext,
    ),
    ("/deprioritized", ContextDifferenceSection::SecurityContext),
    ("/openQuestions", ContextDifferenceSection::Questions),
];

pub fn context_document_differences(before: &Value, after: &Value) -> ContextDocumentDiff {
    let mut result = ContextDocumentDiff {
        schema_version: 1,
        changes: Vec::new(),
        reordered_collections: Vec::new(),
        source_claims: ContextSourceClaims {
            before: source_claims(before),
            after: source_claims(after),
        },
    };
    for (path, section) in COLLECTIONS {
        collections::compare(
            path,
            section,
            before.pointer(path),
            after.pointer(path),
            &mut result,
        );
    }
    result.changes.extend(remainder_changes(before, after));
    result
}

fn remainder(document: &Value) -> Value {
    let mut remaining = document.clone();
    for (pointer, _) in COLLECTIONS {
        let (parent, key) = pointer
            .rsplit_once('/')
            .expect("Collection paths contain a separator");
        if let Some(object) = remaining.pointer_mut(parent).and_then(Value::as_object_mut) {
            object.remove(key);
        }
    }
    remaining
}

fn remainder_changes(before: &Value, after: &Value) -> Vec<ContextValueDifference> {
    let location = values::Location {
        section: ContextDifferenceSection::Other,
        collection: None,
        identity: None,
        matching: ContextDifferenceMatching::DocumentField,
        before_base: Some(String::new()),
        after_base: Some(String::new()),
    };
    let mut changes =
        values::differences(Some(&remainder(before)), Some(&remainder(after)), &location);
    for change in &mut changes {
        change.section = field_section(&change.field);
        change.before = change
            .before_pointer
            .as_deref()
            .and_then(|pointer| before.pointer(pointer))
            .cloned();
        change.after = change
            .after_pointer
            .as_deref()
            .and_then(|pointer| after.pointer(pointer))
            .cloned();
    }
    changes
}

fn field_section(pointer: &str) -> ContextDifferenceSection {
    let inputs = [
        "/provenance",
        "/targetGit",
        "/treeHash",
        "/snapshotHash",
        "/coverage",
    ];
    if inputs
        .iter()
        .any(|prefix| pointer == *prefix || pointer.starts_with(&format!("{prefix}/")))
    {
        return ContextDifferenceSection::Inputs;
    }
    ContextDifferenceSection::Other
}

fn source_claims(document: &Value) -> BTreeMap<String, Value> {
    [
        "/provenance/revision",
        "/provenance/gitRevision",
        "/provenance/revisionDirty",
        "/provenance/treeHash",
        "/provenance/snapshotHash",
        "/provenance/targetGit",
        "/targetGit",
        "/treeHash",
        "/snapshotHash",
        "/provenance/scope",
        "/provenance/fileContext/receipt/inventory/source",
        "/provenance/fileContext/receipt/sourcePaths",
        "/provenance/fileContext/receipt/sourcePartial",
        "/provenance/fileContext/receipt/completeRepositoryCoverage",
    ]
    .into_iter()
    .filter_map(|pointer| {
        document
            .pointer(pointer)
            .map(|value| (pointer.into(), value.clone()))
    })
    .collect()
}

#[cfg(test)]
mod tests;
