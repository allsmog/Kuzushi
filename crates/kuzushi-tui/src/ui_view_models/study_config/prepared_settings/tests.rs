use super::*;
use kuzushi_core::modules::OptionType;
use serde_json::json;

fn specs() -> Vec<OptionSpec> {
    let mut ordinary = OptionSpec::new(
        "workerCount",
        OptionType::Int,
        "Maximum concurrent workers.",
    );
    ordinary.default = Some(json!(1));
    let mut advanced = OptionSpec::new(
        "inventoryByteLimit",
        OptionType::Int,
        "Maximum inspected bytes.",
    );
    advanced.advanced = true;
    vec![ordinary, advanced]
}

#[test]
fn cards_use_descriptor_help_and_recorded_values_without_inventing_defaults() {
    let input = json!({"workerCount":3,"inventoryByteLimit":4096,"sourceReceipt":{"sha":"owned"}});
    let before = input.clone();
    let text = settings_lines(&input, &specs()).join("\n");
    assert!(text.contains("Worker count (workerCount)\nValue: 3\nMaximum concurrent workers."));
    assert!(text.contains("Inventory byte limit (inventoryByteLimit)\nValue: 4096"));
    assert!(text.contains("sourceReceipt") && text.contains("owned"));
    assert!(text.find("SCAN SETTINGS").unwrap() < text.find("ADVANCED SETTINGS").unwrap());
    assert!(text.find("ADVANCED SETTINGS").unwrap() < text.find("RECORDED BINDINGS").unwrap());
    assert_eq!(input, before);
    assert!(!text.contains("Value: 1\n"));
}

#[test]
fn every_field_and_exact_json_value_survives_missing_metadata() {
    let input = json!({"omitted":null,"empty":"","off":false,"list":["界","é"],"nested":{"revision":"r1"},"multiline":"one\ntwo"});
    let text = settings_lines(&input, &[]).join("\n");
    assert!(text.contains("6 recorded fields"));
    for (key, value) in input.as_object().unwrap() {
        assert!(text.contains(&format!("({key})\nValue: {value}")), "{text}");
    }
    assert!(!text.contains("SCAN SETTINGS"));
    assert!(text.contains("Value: null") && text.contains("Value: \"\""));
    assert!(text.contains("one\\ntwo"));
}

#[test]
fn absent_fields_and_malformed_shapes_are_not_replaced_with_defaults() {
    let lines = settings_lines(&json!({}), &specs());
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("0 recorded fields"));
    for input in [json!(null), json!([]), json!("text")] {
        let lines = settings_lines(&input, &specs());
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("not an object"));
    }
}

#[test]
fn aliases_do_not_borrow_help_for_a_different_recorded_key() {
    let mut spec = specs().remove(0);
    spec.aliases.push("threads".into());
    let text = settings_lines(&json!({"threads":2}), &[spec]).join("\n");
    assert!(text.contains("RECORDED BINDINGS") && text.contains("Threads (threads)"));
    assert!(!text.contains("Maximum concurrent workers"));
}

#[test]
fn control_characters_in_unknown_keys_and_values_remain_inert_visible_text() {
    let text = settings_lines(&json!({"owned\n\u{1b}[31m":"line\n\u{1b}[0m"}), &[]).join("\n");
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("\\u001b") && text.contains("line\\n"));
    assert!(text.contains("owned\\n"));
}

#[test]
fn legacy_execution_values_remain_visible_without_offering_excluded_actions() {
    let spec = OptionSpec::new(
        "autoPatch",
        OptionType::Bool,
        "Generate patches automatically.",
    );
    for value in [false, true] {
        let input = json!({"autoPatch":value,"maxIterations":3,"pocExecution":false});
        let before = input.clone();
        let text = settings_lines(&input, std::slice::from_ref(&spec)).join("\n");
        assert!(text.contains("LEGACY EXECUTION FIELDS"));
        assert!(text.contains("offers no target execution, reproducer or patch actions"));
        assert!(text.contains(&format!("(autoPatch)\nValue: {value}")));
        assert!(text.contains("(maxIterations)\nValue: 3"));
        assert!(text.contains("(pocExecution)\nValue: false"));
        assert!(!text.contains("Generate patches automatically"));
        assert_eq!(input, before);
    }
}

#[test]
fn recorded_secret_limits_use_live_descriptor_help_without_adding_defaults() {
    let registry = kuzushi_core::modules::ModuleRegistry::with_v2_builtins();
    let descriptor = registry.resolve_tool("sast:scan").unwrap();
    let input = json!({"secretScanMaxEntries":8,"secretScanMaxTotalBytes":1024,
        "secretScanMaxFileBytes":1024,"secretScanMaxFindings":10});
    let before = input.clone();
    let text = settings_lines(&input, &descriptor.options).join("\n");
    assert!(text.contains("ADVANCED SETTINGS"));
    for (key, value) in input.as_object().unwrap() {
        assert!(text.contains(&format!("({key})\nValue: {value}")));
        let spec = descriptor
            .options
            .iter()
            .find(|spec| spec.name == *key)
            .unwrap();
        assert!(text.contains(&spec.description));
    }
    assert_eq!(input, before);
    assert!(!text.contains("Value: 536870912"));
}
