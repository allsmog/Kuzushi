use serde_json::Value;

#[derive(Debug, Default)]
pub(super) struct ReceiptFields {
    pub(super) catalog_status: Option<String>,
    pub(super) catalog_digest: Option<String>,
    pub(super) model_catalog_digest: Option<String>,
    pub(super) catalog_timestamp_ms: Option<u64>,
    pub(super) snapshot_timestamp_ms: Option<u64>,
    pub(super) model_built_at_ms: Option<u64>,
    pub(super) revision: Option<String>,
    pub(super) revision_dirty: Option<bool>,
    pub(super) catalog_revision: Option<String>,
    pub(super) catalog_revision_dirty: Option<bool>,
    pub(super) catalog_context_digest: Option<String>,
    pub(super) catalog_tree_hash: Option<String>,
    pub(super) model_revision: Option<String>,
    pub(super) model_revision_dirty: Option<bool>,
    pub(super) model_context_digest: Option<String>,
    pub(super) model_tree_hash: Option<String>,
    pub(super) records: Option<usize>,
    pub(super) records_selected: Option<usize>,
    pub(super) grounding_limit: Option<usize>,
    pub(super) grounding_records_selected: Option<usize>,
    pub(super) records_linked: Option<usize>,
    pub(super) selection_policy: Option<String>,
}

pub(super) fn receipt_fields(catalog: Option<&Value>, model: Option<&Value>) -> ReceiptFields {
    let receipt = model.and_then(|doc| doc.pointer("/provenance/entryPointCatalog"));
    let mut fields = artifact_receipt_fields(catalog, model, receipt);
    apply_coverage_fields(&mut fields, model, receipt);
    fields
}

fn artifact_receipt_fields(
    catalog: Option<&Value>,
    model: Option<&Value>,
    receipt: Option<&Value>,
) -> ReceiptFields {
    let catalog_revision = pointer_string(catalog, "/provenance/revision");
    let catalog_revision_dirty = pointer_bool(catalog, "/provenance/revisionDirty");
    let model_revision = receipt.and_then(|value| string_field(value, "revision"));
    let model_revision_dirty = receipt
        .and_then(|value| value.get("revisionDirty"))
        .and_then(Value::as_bool);
    ReceiptFields {
        catalog_status: receipt.and_then(|value| string_field(value, "status")),
        catalog_digest: pointer_string(catalog, "/provenance/sha256"),
        model_catalog_digest: receipt.and_then(|value| string_field(value, "sha256")),
        catalog_timestamp_ms: pointer_u64(catalog, "/timestamp"),
        snapshot_timestamp_ms: receipt
            .and_then(|value| value.get("snapshotTimestamp"))
            .and_then(Value::as_u64)
            .or_else(|| pointer_u64(catalog, "/snapshotTimestamp")),
        model_built_at_ms: pointer_u64(model, "/provenance/builtAtMs"),
        revision: catalog_revision.clone().or_else(|| model_revision.clone()),
        revision_dirty: catalog_revision_dirty.or(model_revision_dirty),
        catalog_revision,
        catalog_revision_dirty,
        catalog_context_digest: pointer_string(catalog, "/provenance/contextSnapshotSha256"),
        catalog_tree_hash: pointer_string(catalog, "/provenance/contextSnapshotTreeHash"),
        model_revision,
        model_revision_dirty,
        model_context_digest: receipt.and_then(|value| string_field(value, "contextSha256")),
        model_tree_hash: receipt.and_then(|value| string_field(value, "treeHash")),
        selection_policy: receipt.and_then(|value| string_field(value, "selectionPolicy")),
        ..Default::default()
    }
}

fn apply_coverage_fields(
    fields: &mut ReceiptFields,
    model: Option<&Value>,
    receipt: Option<&Value>,
) {
    fields.records = receipt
        .and_then(|value| value.get("records"))
        .and_then(value_as_usize)
        .or_else(|| pointer_usize(model, "/coverage/catalogEntryPointsTotal"));
    fields.records_selected = receipt
        .and_then(|value| value.get("recordsSelected"))
        .and_then(value_as_usize)
        .or_else(|| pointer_usize(model, "/coverage/catalogEntryPointsSelected"));
    fields.grounding_limit = receipt
        .and_then(|value| value.get("groundingLimit"))
        .and_then(value_as_usize);
    fields.grounding_records_selected = receipt
        .and_then(|value| value.get("groundingRecordsSelected"))
        .and_then(value_as_usize);
    fields.records_linked = pointer_usize(model, "/coverage/catalogEntryPointsLinked");
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value.get(field)?.as_str().map(str::to_string)
}

fn pointer_string(value: Option<&Value>, pointer: &str) -> Option<String> {
    value
        .and_then(|value| value.pointer(pointer))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn pointer_u64(value: Option<&Value>, pointer: &str) -> Option<u64> {
    value
        .and_then(|value| value.pointer(pointer))
        .and_then(Value::as_u64)
}

pub(super) fn pointer_usize(value: Option<&Value>, pointer: &str) -> Option<usize> {
    value
        .and_then(|value| value.pointer(pointer))
        .and_then(value_as_usize)
}

fn pointer_bool(value: Option<&Value>, pointer: &str) -> Option<bool> {
    value
        .and_then(|value| value.pointer(pointer))
        .and_then(Value::as_bool)
}

fn value_as_usize(value: &Value) -> Option<usize> {
    value.as_u64().and_then(|value| usize::try_from(value).ok())
}
