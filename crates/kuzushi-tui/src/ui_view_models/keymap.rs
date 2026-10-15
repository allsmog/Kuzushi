use super::{cost_model, format_session_cost};
use crate::{
    KeymapBindingRow, KeymapFooter, KeymapSection, KeymapSnapshot, KeymapStatus, ShellApp,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeymapModel {
    pub(crate) status: KeymapStatus,
    pub(crate) event_time: String,
    pub(crate) sections: Vec<KeymapSection>,
    pub(crate) note: String,
    pub(crate) footer: KeymapFooter,
}

pub(crate) fn keymap_model(app: &ShellApp) -> KeymapModel {
    app.keymap_snapshot()
        .cloned()
        .map(KeymapModel::from)
        .unwrap_or_else(|| default_keymap_model(app))
}

impl From<KeymapSnapshot> for KeymapModel {
    fn from(snapshot: KeymapSnapshot) -> Self {
        Self {
            status: snapshot.status,
            event_time: snapshot.event_time,
            sections: snapshot.sections,
            note: snapshot.note,
            footer: snapshot.footer,
        }
    }
}

fn default_keymap_model(app: &ShellApp) -> KeymapModel {
    let note = app
        .ui()
        .keymap_error()
        .map(|error| format!("operator keymap invalid; defaults retained · {error}"))
        .unwrap_or_else(|| {
            "the footer and this view are generated from the effective action keymap".to_string()
        });
    KeymapModel {
        status: default_status(app),
        event_time: "--:--:--".to_string(),
        sections: default_keymap_sections(app),
        note,
        footer: default_footer(app),
    }
}

fn default_status(app: &ShellApp) -> KeymapStatus {
    KeymapStatus {
        target: app
            .target()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        ctx: "not built".to_string(),
        model: app
            .config()
            .model
            .clone()
            .unwrap_or_else(|| "unconfigured".to_string()),
        module: "help".to_string(),
        cost: default_cost(app),
    }
}

fn default_cost(app: &ShellApp) -> String {
    cost_model(app)
        .budget_status
        .map(|status| status.cells[1].clone())
        .unwrap_or_else(|| format_session_cost(0.0))
}

pub(crate) fn default_keymap_sections(app: &ShellApp) -> Vec<KeymapSection> {
    let mut sections = vec![
        active_view_keymap_section(app),
        global_keymap_section(),
        navigation_keymap_section(),
        dispatch_keymap_section(),
        lifecycle_keymap_section(),
    ];
    if let Some(section) = operator_override_section(app) {
        sections.push(section);
    }
    sections
}

fn operator_override_section(app: &ShellApp) -> Option<KeymapSection> {
    let rows = app
        .config()
        .operator
        .keybindings
        .iter()
        .map(|entry| {
            let keys = if entry.bindings.is_empty() {
                "unbound".to_string()
            } else {
                entry.bindings.join(" · ")
            };
            KeymapBindingRow::new(
                keys,
                format!("{}.{} · operator override", entry.context, entry.action),
            )
        })
        .collect::<Vec<_>>();
    (!rows.is_empty()).then(|| {
        KeymapSection::new(
            "OPERATOR OVERRIDES",
            "effective bindings loaded from global operator config",
            rows,
        )
    })
}

fn global_keymap_section() -> KeymapSection {
    section(
        "GLOBAL",
        "shell and input controls",
        &[
            ("help", "open help"),
            ("Tab", "complete prompt input"),
            ("Ctrl-C  ·  Ctrl-D", "exit idle shell · cancel active work"),
            (
                "Ctrl-L",
                "clear console (keeps state · audit log untouched)",
            ),
            ("Ctrl-G", "command palette · all commands fuzzy-find"),
            ("Ctrl-P  ·  Ctrl-N", "history previous · next"),
            ("Ctrl-R", "recall last command · prefix-search history"),
            (
                "Ctrl-↑  ·  Ctrl-↓",
                "autonomy dial: raise · lower the tool-dispatch ceiling",
            ),
            ("Esc", "contextual back / dismiss / clear field"),
        ],
    )
}

fn navigation_keymap_section() -> KeymapSection {
    section(
        "NAVIGATION",
        "list views · findings · runs · diffs",
        &[
            ("j  ·  k", "down  ·  up"),
            ("g  ·  G", "top  ·  bottom"),
            ("PgDn  ·  PgUp", "page down  ·  up"),
            ("enter", "open / drill in"),
        ],
    )
}

fn dispatch_keymap_section() -> KeymapSection {
    section(
        "DISPATCH",
        "commands you reach for daily",
        &[
            (
                "/map · /scan · /review · /prove · /fix",
                "open the exact phase planner",
            ),
            ("/full [target]", "guided Map → Scan workflow"),
            (
                "/use <module>",
                "enter a module · /use sast · /use ndiff cve-…",
            ),
            ("/run <module>", "one-shot a module without entering it"),
            ("/show <kind>", "/show runs · /show options · /show aliases"),
            ("/set · /setg", "session option · global default"),
            ("/use threat-model", "plan or update v3"),
            (
                "/use patch <id>",
                "draft a patch from a finding · staged · operator confirms",
            ),
            (
                "/use verify <id>",
                "sandbox-prove a finding · canary in · verdict out",
            ),
        ],
    )
}

fn lifecycle_keymap_section() -> KeymapSection {
    section(
        "LIFECYCLE",
        "session state",
        &[
            ("/history", "session command history"),
            ("/resume", "resume a saved Kuzushi session"),
            ("/load", "load a saved session"),
            ("/cost", "set or read cost controls"),
        ],
    )
}

fn active_view_keymap_section(app: &ShellApp) -> KeymapSection {
    let origin = app
        .router
        .overlay_origin()
        .unwrap_or(crate::ShellView::Keymap);
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    rows.extend(
        origin_view_bindings(app, origin)
            .into_iter()
            .filter(|binding| seen.insert((binding.key.clone(), binding.label.clone())))
            .map(|binding| KeymapBindingRow::new(binding.key, binding.label)),
    );
    rows.extend([
        KeymapBindingRow::new("back", "leave the originating screen"),
        KeymapBindingRow::new("/keys", "open this complete control map"),
    ]);
    KeymapSection::new(format!("VIEW · {origin:?}"), "navigation controls", rows)
}

fn origin_view_bindings(
    app: &ShellApp,
    origin: crate::ShellView,
) -> Vec<super::keybindings::FooterKeybinding> {
    if origin == crate::ShellView::Options {
        return super::keybindings::options_browser_keybindings(app);
    }
    app.view_keybindings_for_view(origin)
        .into_iter()
        .map(|binding| super::keybindings::FooterKeybinding {
            key: binding.hint,
            label: binding.label,
        })
        .collect()
}

fn section(name: &str, blurb: &str, rows: &[(&str, &str)]) -> KeymapSection {
    KeymapSection::new(
        name,
        blurb,
        rows.iter()
            .map(|(keys, action)| KeymapBindingRow::new(*keys, *action))
            .collect(),
    )
}

fn default_footer(app: &ShellApp) -> KeymapFooter {
    KeymapFooter {
        stage: "help · keymap".to_string(),
        findings: app.findings_total_count(),
        keybinds: vec![
            ("j/k".to_string(), "row".to_string()),
            ("Esc/q".to_string(), "close".to_string()),
        ],
        prompt_module: "help".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{parse_command, ShellCommand};
    use kuzushi_core::V2Config;

    #[test]
    fn keymap_model_uses_route_owned_snapshot() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.replace_keymap_snapshot_for_test(Some(snapshot()));

        let model = keymap_model(&app);

        assert_eq!(model.event_time, "12:00:00");
        assert_eq!(model.sections[0].name, "ROUTE");
        assert_eq!(model.footer.prompt_module, "keys");
    }

    #[test]
    fn default_keymap_advertised_command_examples_parse() {
        for command in [
            "help",
            "/map",
            "/scan",
            "/review",
            "/prove",
            "/fix",
            "/full .",
            "/use sast",
            "/run sast:scan",
            "/show runs",
            "/show options",
            "/show aliases",
            "/set scanner semgrep",
            "/setg scanner semgrep",
            "/use threat-model",
            "/use patch",
            "/use verify",
            "/history",
            "/resume saved-session",
            "/load saved-session",
            "/cost",
            "/keys",
        ] {
            assert!(
                !matches!(parse_command(command), ShellCommand::Unknown(_)),
                "advertised keymap command should parse: {command}"
            );
        }
    }

    #[test]
    fn default_keymap_lists_every_originating_workbench_control() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(crate::ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Prove));
        app.set_shell_view(crate::ShellView::Keymap);

        let model = keymap_model(&app);
        let section = model.sections.first().expect("originating view section");
        let keys = section
            .rows
            .iter()
            .map(|row| row.keys.as_str())
            .collect::<Vec<_>>();

        assert_eq!(section.name, "VIEW · Workbench");
        assert!(keys.contains(&"v"), "{keys:?}");
        assert!(keys.contains(&"x"), "{keys:?}");
        assert!(keys.contains(&"c"), "{keys:?}");
        assert!(!keys.contains(&"d"), "{keys:?}");
        assert!(!keys.contains(&"←/→"), "{keys:?}");
        assert!(keys.contains(&"/keys"), "{keys:?}");
        assert!(!model.note.contains("doesn't do anything"));
    }

    fn snapshot() -> KeymapSnapshot {
        KeymapSnapshot {
            status: KeymapStatus {
                target: "target".to_string(),
                ctx: "ctx".to_string(),
                model: "model".to_string(),
                module: "keys".to_string(),
                cost: "$0.00".to_string(),
            },
            event_time: "12:00:00".to_string(),
            sections: vec![KeymapSection::new(
                "ROUTE",
                "owned",
                vec![KeymapBindingRow::new("?", "help")],
            )],
            note: "note".to_string(),
            footer: KeymapFooter {
                stage: "keymap".to_string(),
                findings: 0,
                keybinds: Vec::new(),
                prompt_module: "keys".to_string(),
            },
        }
    }
    #[test]
    fn options_keymap_matches_selection_and_the_open_field_editor() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = ShellApp::new(V2Config::default(), None);
        app.show_options(
            Some("context:build".into()),
            crate::app::OptionsFilter::Advanced,
        );
        app.router.options_browser_mut().selected = Some("enrichment".into());
        app.set_shell_view(crate::ShellView::Keymap);
        let rows = &keymap_model(&app).sections[0].rows;
        assert!(rows
            .iter()
            .any(|row| row.keys == "Enter" && row.action == "edit"));
        assert!(rows
            .iter()
            .any(|row| row.keys == "↑/↓ j/k" && row.action == "option"));
        assert!(rows
            .iter()
            .any(|row| row.keys == "PgUp/Dn" && row.action == "details"));
        assert!(rows.iter().any(|row| row.keys == "s/a/m"));
        assert!(!rows.iter().any(|row| row.action == "scroll"));
        app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.tool_option_editor_open());
        app.set_shell_view(crate::ShellView::Keymap);
        let rows = &keymap_model(&app).sections[0].rows;
        assert!(rows
            .iter()
            .any(|row| row.keys == "Enter/Ctrl+S" && row.action == "save session"));
        assert!(rows
            .iter()
            .any(|row| row.keys == "Esc" && row.action == "keep draft"));
        assert!(!app.has_running_work());
    }
}
