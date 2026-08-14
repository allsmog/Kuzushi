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

/// Run Focus's Esc-leave affordance is the Activity view's `Back` binding, and
/// the `run_focus` context exposes no `back` action to rebind or unbind it —
/// which is why `push_run_focus_leave_hint` resolves its key from the composed
/// view keymap instead of `binding_labels("run_focus", "back", …)`. If `back`
/// is ever added to this context, the hint keeps following dispatch through
/// `view_back_key`; this test only pins the current surface.
#[test]
fn run_focus_context_exposes_no_back_action() {
    let map = RuntimeKeymap::from_config(&[KeybindingOverrideConfig {
        context: "run_focus".to_string(),
        action: "back".to_string(),
        bindings: vec!["q".to_string()],
    }]);

    assert!(map
        .error()
        .is_some_and(|error| error.contains("unknown keybinding action")));
    assert!(map.overrides.is_empty());
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
