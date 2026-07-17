use super::*;

#[test]
fn literal_backtab_and_two_stroke_chord_parse() {
    assert_eq!(
        parse_stroke("backtab").unwrap(),
        KeyStroke {
            code: StrokeCode::BackTab,
            modifiers: KeyModifiers::NONE,
        }
    );
    assert_eq!(parse_sequence("g p").unwrap().strokes.len(), 2);
}

#[test]
fn duplicate_binding_in_one_context_rejects_the_whole_map() {
    let map = RuntimeKeymap::from_config(&[
        KeybindingOverrideConfig {
            context: "workbench".to_string(),
            action: "cycle_phase".to_string(),
            bindings: vec!["x".to_string()],
        },
        KeybindingOverrideConfig {
            context: "workbench".to_string(),
            action: "previous_phase".to_string(),
            bindings: vec!["x".to_string()],
        },
    ]);
    assert!(map.error().is_some());
    assert!(map.overrides.is_empty());
}

#[test]
fn empty_bindings_explicitly_unbind_an_action() {
    let map = RuntimeKeymap::from_config(&[KeybindingOverrideConfig {
        context: "workbench".to_string(),
        action: "cycle_phase".to_string(),
        bindings: Vec::new(),
    }]);

    assert!(map.error().is_none());
    assert!(map.overrides_action("workbench", "cycle_phase"));
    let bindings = map.apply_view_overrides(
        ShellView::Workbench,
        vec![ViewKeybinding {
            trigger: HotkeyTrigger::BackTab,
            hint: "Shift+Tab".to_string(),
            label: "phase".to_string(),
            action: ViewHotkeyAction::WorkbenchPageNext,
        }],
    );
    assert!(bindings.is_empty());
    assert!(map
        .binding_labels("workbench", "cycle_phase", &["Shift+Tab"])
        .is_empty());
}

#[test]
fn binding_labels_are_the_runtime_dispatch_source() {
    let map = RuntimeKeymap::from_config(&[KeybindingOverrideConfig {
        context: "question".to_string(),
        action: "Submit".to_string(),
        bindings: vec!["ctrl+s".to_string(), "g s".to_string()],
    }]);

    assert_eq!(
        map.binding_labels("question", "submit", &["Enter"]),
        ["ctrl+s", "g s"]
    );
}
