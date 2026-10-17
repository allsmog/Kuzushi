use super::*;
use serde_json::json;

#[test]
fn legacy_json_options_remain_read_only_and_omit_new_metadata() {
    let spec = OptionSpec::new("allowanceRef", OptionType::Json, "Approved work reference");
    let value = serde_json::to_value(&spec).unwrap();
    assert!(value.get("editableJson").is_none());
    let loaded: OptionSpec = serde_json::from_value(value).unwrap();
    assert!(!loaded.editable_json);
    assert_eq!(loaded, spec);
}

#[test]
fn operator_authored_json_opts_into_editing_explicitly() {
    let spec =
        OptionSpec::new("pairs", OptionType::Json, "Owned allocation/free pairs").editable_json();
    let value = serde_json::to_value(&spec).unwrap();
    assert_eq!(value["editableJson"], json!(true));
    assert_eq!(serde_json::from_value::<OptionSpec>(value).unwrap(), spec);
}
