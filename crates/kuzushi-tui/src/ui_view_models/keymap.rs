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
    KeymapModel {
        status: default_status(app),
        event_time: "--:--:--".to_string(),
        sections: default_keymap_sections(app),
        note: "the footer shows primary controls · this keymap lists every active control for the originating screen".to_string(),
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
    vec![
        global_keymap_section(),
        navigation_keymap_section(),
        dispatch_keymap_section(),
        lifecycle_keymap_section(),
        active_view_keymap_section(app),
    ]
}

fn global_keymap_section() -> KeymapSection {
    section(
        "GLOBAL",
        "work everywhere",
        &[
            ("help", "open help"),
            ("Tab", "complete prompt input"),
            ("Ctrl-C  ·  Ctrl-D", "quit (with confirm if dirty)"),
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
            ("Esc", "cancel field / close overlay / interrupt streaming"),
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
            ("/scan", "sast umbrella · semgrep + secrets + agentic"),
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
    let mut rows = vec![KeymapBindingRow::new("F2", "enter navigation mode")];
    rows.extend(
        app.view_keybindings_for_view(origin)
            .into_iter()
            .filter(|binding| !(binding.hint == "Esc" && binding.label == "back"))
            .filter(|binding| seen.insert((binding.hint, binding.label)))
            .map(|binding| KeymapBindingRow::new(binding.hint, binding.label)),
    );
    rows.extend([
        KeymapBindingRow::new("Esc", "return to prompt mode"),
        KeymapBindingRow::new("back", "leave the originating screen"),
        KeymapBindingRow::new("/keys", "open this complete control map"),
    ]);
    KeymapSection::new(
        format!("VIEW · {origin:?}"),
        "complete navigation controls for the screen behind this keymap",
        rows,
    )
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
            "/scan",
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
        app.set_shell_view(crate::ShellView::Keymap);

        let model = keymap_model(&app);
        let section = model.sections.last().expect("originating view section");
        let keys = section
            .rows
            .iter()
            .map(|row| row.keys.as_str())
            .collect::<Vec<_>>();

        assert_eq!(section.name, "VIEW · Workbench");
        assert!(keys.contains(&"v"), "{keys:?}");
        assert!(keys.contains(&"x"), "{keys:?}");
        assert!(keys.contains(&"c"), "{keys:?}");
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
}
