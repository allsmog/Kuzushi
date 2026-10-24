//! Export recorded source-input metadata without copying captured source text.
use serde_json::{json, Map, Value};

const RECEIPT_FIELDS: &[&str] = &[
    "schemaVersion",
    "model",
    "runId",
    "inheritedContextRef",
    "scopeRef",
    "sourcePaths",
    "selectedFileCount",
    "discoveryFileCount",
    "sharedFileCount",
    "sourcePartial",
    "completeRepositoryCoverage",
    "synthesisRequests",
    "promptSha256",
];
const SOURCE_FIELDS: &[&str] = &[
    "policy",
    "scopePath",
    "treeHash",
    "eligibleFiles",
    "selectedFiles",
    "byteBudget",
    "fileLimit",
    "readBytes",
    "omissions",
];
const FILE_FIELDS: &[&str] = &[
    "path",
    "fileSha256",
    "language",
    "scopeRole",
    "totalLines",
    "omittedLines",
    "excludedTestLines",
    "projection",
];
const INVENTORY_FIELDS: &[&str] = &[
    "schemaVersion",
    "selectedMembershipKnown",
    "enumerationComplete",
    "enumeration",
    "enumeratedFiles",
    "entries",
    "maxEntries",
    "inspectedBytes",
    "maxInspectedBytes",
    "maxFileInspectionBytes",
    "truncation",
    "omittedPathCount",
    "omittedPaths",
    "additionalOmittedPaths",
    "truncatedFileCount",
    "truncatedFiles",
    "additionalTruncatedFiles",
    "completeRepositoryCoverage",
    "inventoryHash",
    "source",
];

pub(super) fn project(document: &Value) -> Value {
    json!({"schemaVersion":1,"projection":"metadata-only","sourceTextIncluded":false,
        "scopeContext":wrapper(document.pointer("/provenance/scopeContext")),
        "fileContext":wrapper(document.pointer("/provenance/fileContext"))})
}

fn wrapper(value: Option<&Value>) -> Value {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Value::Null;
    };
    let Some(receipt) = value.get("receipt").filter(|value| value.is_object()) else {
        return unavailable("Recorded source-input receipt is malformed.");
    };
    if receipt["schemaVersion"].as_u64() != Some(1) {
        return unavailable("Recorded source-input receipt version is unsupported or missing.");
    }
    project_receipt(receipt)
}

fn project_receipt(receipt: &Value) -> Value {
    let Some(source) = receipt
        .get("sourceEvidence")
        .filter(|source| valid_source(source))
    else {
        return unavailable("Recorded source-input file evidence is malformed or missing.");
    };
    let mut metadata = fields(receipt, RECEIPT_FIELDS);
    metadata["sourceEvidence"] = source_metadata(source);
    if let Some(inventory) = receipt.get("inventory") {
        metadata["inventory"] = fields(inventory, INVENTORY_FIELDS);
    }
    json!({"status":"recorded","receipt":metadata})
}

fn valid_source(source: &Value) -> bool {
    source["files"]
        .as_array()
        .is_some_and(|files| files.iter().all(valid_file))
}

fn valid_file(file: &Value) -> bool {
    let Some(path) = file["path"].as_str() else {
        return false;
    };
    let Some(lines) = file["lines"].as_array() else {
        return false;
    };
    !path.is_empty() && lines.iter().all(|line| line["ref"].is_string())
}

fn source_metadata(source: &Value) -> Value {
    let mut metadata = fields(source, SOURCE_FIELDS);
    metadata["files"] = Value::Array(
        source["files"]
            .as_array()
            .into_iter()
            .flatten()
            .map(file_metadata)
            .collect(),
    );
    metadata
}

fn file_metadata(file: &Value) -> Value {
    let mut metadata = fields(file, FILE_FIELDS);
    metadata["lines"] = Value::Array(
        file["lines"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|line| fields(line, &["ref"]))
            .collect(),
    );
    metadata
}

fn fields(value: &Value, keys: &[&str]) -> Value {
    Value::Object(
        keys.iter()
            .filter_map(|key| {
                value
                    .get(*key)
                    .map(|value| ((*key).to_owned(), value.clone()))
            })
            .collect::<Map<String, Value>>(),
    )
}

fn unavailable(message: &str) -> Value {
    json!({"status":"unavailable","message":message})
}
