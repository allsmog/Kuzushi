use serde_json::{json, Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
pub(crate) struct ScopeUpdate {
    pub(crate) vendor_name: Option<String>,
    pub(crate) product_name: Option<String>,
    pub(crate) primary_domain: Option<String>,
    pub(crate) use_case: Option<String>,
    pub(crate) profile: Option<String>,
    pub(crate) data_classes: Option<Vec<String>>,
    pub(crate) integrations: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub(crate) struct AttachmentInput {
    pub(crate) source: String,
    pub(crate) kind: String,
    pub(crate) title: Option<String>,
    pub(crate) scope_update: ScopeUpdate,
}

pub(crate) fn empty_scope() -> Value {
    json!({
        "version": "1",
        "vendorName": "",
        "productName": "",
        "primaryDomain": "",
        "useCase": "",
        "profile": "enterprise-ai",
        "dataClasses": [],
        "integrations": [],
        "documents": [],
        "updatedAt": unix_millis(),
    })
}

pub(crate) fn merge_scope_inputs(mut scope: Value, update: &ScopeUpdate) -> Value {
    let Value::Object(ref mut object) = scope else {
        return empty_scope();
    };
    insert_string_update(object, "vendorName", &update.vendor_name);
    insert_string_update(object, "productName", &update.product_name);
    insert_string_update(object, "primaryDomain", &update.primary_domain);
    insert_string_update(object, "useCase", &update.use_case);
    insert_string_update(object, "profile", &update.profile);
    insert_array_update(object, "dataClasses", &update.data_classes);
    insert_array_update(object, "integrations", &update.integrations);
    object.insert("updatedAt".to_string(), json!(unix_millis()));
    scope
}

fn insert_string_update(object: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(value) = value {
        object.insert(key.to_string(), json!(value));
    }
}

fn insert_array_update(object: &mut Map<String, Value>, key: &str, value: &Option<Vec<String>>) {
    if let Some(value) = value {
        object.insert(key.to_string(), json!(value));
    }
}

pub(crate) fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
