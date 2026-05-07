use std::collections::BTreeSet;

use anyhow::{Context, Result};
use kuzushi_core::{OptionScope, OptionTarget};

use crate::commands::{SastTaskCommand, SastTaskModeCommand};

use super::{SastTaskMode, SastTaskRow, ShellApp, ShellView};

impl ShellApp {
    pub(super) fn show_sast_tasks(&mut self) {
        if self.registry.resolve_tool("sast:scan").is_none() {
            self.log("error", "SAST module is not loaded. Next: modules");
            return;
        }
        self.focused_module = Some("sast".to_string());
        self.shell_view = ShellView::SastTasks;
        self.log("tasks", self.sast_task_summary_line());
    }

    pub(super) fn handle_sast_task_command(&mut self, command: SastTaskCommand) {
        if self.registry.resolve_tool("sast:scan").is_none() {
            self.log("error", "SAST module is not loaded. Next: modules");
            return;
        }

        let result = match command {
            SastTaskCommand::Block(raw_id) => self.block_sast_task(&raw_id),
            SastTaskCommand::Allow(raw_id) => self.allow_sast_task(&raw_id),
            SastTaskCommand::Toggle(raw_id) => {
                let raw_id = raw_id.unwrap_or_else(|| {
                    self.sast_task_rows()
                        .into_iter()
                        .find(|row| row.toggleable)
                        .map(|row| row.id.to_string())
                        .unwrap_or_else(|| "semgrep".to_string())
                });
                self.toggle_sast_task(&raw_id)
            }
            SastTaskCommand::Mode(mode) => self.set_sast_task_mode(mode),
            SastTaskCommand::Reset => self.reset_sast_tasks(),
        };

        self.shell_view = ShellView::SastTasks;
        self.focused_module = Some("sast".to_string());
        match result {
            Ok(message) => self.log("tasks", message),
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(super) fn block_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let mut disabled = self.current_disabled_sast_tasks();
        disabled.insert(task.id.to_string());
        self.write_sast_task_list_option("disabledTasks", disabled.into_iter().collect());

        let mut manual = self.current_manual_sast_tasks();
        manual.remove(task.id);
        self.write_sast_task_list_option("tasks", manual.into_iter().collect());

        Ok(format!(
            "Blocked SAST task capability: {}. {}",
            task.id,
            self.sast_task_summary_line()
        ))
    }

    pub(super) fn allow_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let mut disabled = self.current_disabled_sast_tasks();
        disabled.remove(task.id);
        self.write_sast_task_list_option("disabledTasks", disabled.into_iter().collect());

        if self.current_sast_task_mode() == SastTaskMode::Manual {
            let mut manual = self.current_manual_sast_tasks();
            manual.insert(task.id.to_string());
            self.write_sast_task_list_option("tasks", manual.into_iter().collect());
        }

        Ok(format!(
            "Allowed SAST task capability: {}. {}",
            task.id,
            self.sast_task_summary_line()
        ))
    }

    pub(super) fn toggle_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let disabled = self.current_disabled_sast_tasks();
        let manual = self.current_manual_sast_tasks();
        if disabled.contains(task.id)
            || (self.current_sast_task_mode() == SastTaskMode::Manual && !manual.contains(task.id))
        {
            self.allow_sast_task(task.id)
        } else {
            self.block_sast_task(task.id)
        }
    }

    pub(super) fn set_sast_task_mode(&mut self, mode: SastTaskModeCommand) -> Result<String> {
        let next_mode = match mode {
            SastTaskModeCommand::Auto => SastTaskMode::Auto,
            SastTaskModeCommand::Manual => SastTaskMode::Manual,
            SastTaskModeCommand::Toggle => match self.current_sast_task_mode() {
                SastTaskMode::Auto => SastTaskMode::Manual,
                SastTaskMode::Manual => SastTaskMode::Auto,
            },
        };

        match next_mode {
            SastTaskMode::Auto => {
                self.option_store.set_value(
                    OptionScope::Session,
                    OptionTarget::Tool("sast:scan".to_string()),
                    "taskMode",
                    serde_json::json!("auto"),
                );
                self.option_store.unset_value(
                    OptionScope::Session,
                    &OptionTarget::Tool("sast:scan".to_string()),
                    "tasks",
                );
            }
            SastTaskMode::Manual => {
                let manual = self.manual_tasks_or_current_auto_selection();
                if manual.is_empty() {
                    anyhow::bail!(
                        "manual SAST task mode needs at least one task. Valid task IDs: {}",
                        valid_sast_task_ids().join(", ")
                    );
                }
                self.option_store.set_value(
                    OptionScope::Session,
                    OptionTarget::Tool("sast:scan".to_string()),
                    "taskMode",
                    serde_json::json!("manual"),
                );
                self.write_sast_task_list_option("tasks", manual);
            }
        }

        Ok(format!(
            "SAST task mode: {}. {}",
            match next_mode {
                SastTaskMode::Auto => "auto + denylist",
                SastTaskMode::Manual => "manual allowlist",
            },
            self.sast_task_summary_line()
        ))
    }

    pub(super) fn reset_sast_tasks(&mut self) -> Result<String> {
        let target = OptionTarget::Tool("sast:scan".to_string());
        for key in ["taskMode", "tasks", "disabledTasks"] {
            self.option_store
                .unset_value(OptionScope::Session, &target, key);
        }
        Ok(format!(
            "SAST task selection reset. {}",
            self.sast_task_summary_line()
        ))
    }

    pub(crate) fn sast_task_rows(&self) -> Vec<SastTaskRow> {
        let mode = self.current_sast_task_mode();
        let disabled = self.current_disabled_sast_tasks();
        let manual = self.current_manual_sast_tasks();

        SAST_TASK_CAPABILITIES
            .iter()
            .map(|task| {
                let blocked = disabled.contains(task.id);
                let selected = if blocked {
                    false
                } else if mode == SastTaskMode::Manual {
                    manual.contains(task.id)
                } else {
                    task.default_enabled
                };
                let state = if blocked {
                    "[ ]"
                } else if selected {
                    "[x]"
                } else {
                    "[A]"
                };
                let source = if blocked {
                    "blocked"
                } else if mode == SastTaskMode::Manual {
                    "manual"
                } else if task.default_enabled {
                    "default"
                } else {
                    "available"
                };
                SastTaskRow {
                    id: task.id,
                    scan_task: task.scan_task,
                    cost: task.cost,
                    notes: task.notes,
                    toggleable: task.toggleable,
                    selected,
                    state,
                    source,
                }
            })
            .collect()
    }

    fn sast_task_summary_line(&self) -> String {
        let rows = self.sast_task_rows();
        let enabled = rows.iter().filter(|row| row.selected).count();
        let blocked = rows.iter().filter(|row| row.source == "blocked").count();
        let mode = match self.current_sast_task_mode() {
            SastTaskMode::Auto => "auto + denylist",
            SastTaskMode::Manual => "manual allowlist",
        };
        format!(
            "{mode}; {enabled}/{} enabled; {blocked} blocked. Next: /task toggle <id> or /scan",
            rows.len()
        )
    }

    fn current_sast_task_mode(&self) -> SastTaskMode {
        let values = self.option_store.effective_stored_values("sast:scan");
        match values.get("taskMode").and_then(serde_json::Value::as_str) {
            Some("manual") => SastTaskMode::Manual,
            _ => SastTaskMode::Auto,
        }
    }

    fn current_disabled_sast_tasks(&self) -> BTreeSet<String> {
        let values = self.option_store.effective_stored_values("sast:scan");
        read_task_list_value(values.get("disabledTasks"))
            .into_iter()
            .filter_map(|task| resolve_sast_task(&task).map(|task| task.id.to_string()))
            .collect()
    }

    fn current_manual_sast_tasks(&self) -> BTreeSet<String> {
        let values = self.option_store.effective_stored_values("sast:scan");
        read_task_list_value(values.get("tasks"))
            .into_iter()
            .filter_map(|task| resolve_sast_task(&task).map(|task| task.id.to_string()))
            .collect()
    }

    fn manual_tasks_or_current_auto_selection(&self) -> Vec<String> {
        let manual = self.current_manual_sast_tasks();
        if !manual.is_empty() {
            return manual.into_iter().collect();
        }

        let disabled = self.current_disabled_sast_tasks();
        SAST_TASK_CAPABILITIES
            .iter()
            .filter(|task| task.default_enabled && !disabled.contains(task.id))
            .map(|task| task.id.to_string())
            .collect()
    }

    fn write_sast_task_list_option(&mut self, name: &str, values: Vec<String>) {
        let target = OptionTarget::Tool("sast:scan".to_string());
        if values.is_empty() {
            self.option_store
                .unset_value(OptionScope::Session, &target, name);
        } else {
            self.option_store.set_value(
                OptionScope::Session,
                target,
                name,
                serde_json::Value::String(values.join(",")),
            );
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SastTaskCapability {
    id: &'static str,
    scan_task: &'static str,
    cost: &'static str,
    notes: &'static str,
    default_enabled: bool,
    native_scan: bool,
    toggleable: bool,
}

const SAST_TASK_CAPABILITIES: &[SastTaskCapability] = &[
    SastTaskCapability {
        id: "semgrep",
        scan_task: "semgrep",
        cost: "low",
        notes: "pattern scanner",
        default_enabled: true,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "codeql",
        scan_task: "codeql",
        cost: "high",
        notes: "semantic query scanner",
        default_enabled: false,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "dep-hygiene",
        scan_task: "dep-hygiene",
        cost: "low",
        notes: "dependency manifest hygiene",
        default_enabled: true,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "secret-scan",
        scan_task: "secret-scan",
        cost: "low",
        notes: "local secret patterns",
        default_enabled: true,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "iac-scan",
        scan_task: "iac-scan",
        cost: "low",
        notes: "IaC misconfiguration scanner",
        default_enabled: true,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "agentic",
        scan_task: "agentic",
        cost: "high",
        notes: "model-backed detector set; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "carlini-threat-hunt",
        scan_task: "carlini-threat-hunt",
        cost: "high",
        notes: "actor-driven hunt; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "taint-iris",
        scan_task: "taint-iris",
        cost: "high",
        notes: "source-to-sink analysis; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "taint-iris-next",
        scan_task: "taint-iris-next",
        cost: "high",
        notes: "next taint workflow; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "systems-hunt",
        scan_task: "systems-hunt",
        cost: "high",
        notes: "systems invariant hunt; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
];

pub(super) fn valid_sast_task_ids() -> Vec<&'static str> {
    SAST_TASK_CAPABILITIES.iter().map(|task| task.id).collect()
}

fn unknown_sast_task_message(raw_id: &str) -> String {
    format!(
        "unknown SAST task {raw_id:?}. Valid task IDs: {}. Next: /tasks",
        valid_sast_task_ids().join(", ")
    )
}

fn resolve_sast_task(raw_id: &str) -> Option<&'static SastTaskCapability> {
    let normalized = raw_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    let normalized = match normalized.as_str() {
        "agentic-sast" | "agentic-sast:scan" => "agentic",
        "semgrep:scan" => "semgrep",
        "codeql:scan" => "codeql",
        "dep-hygiene:check" => "dep-hygiene",
        "secret-scan:scan" | "secrets" => "secret-scan",
        "iac-scan:scan" => "iac-scan",
        "carlini" | "threat-hunt" | "carlini-threat-hunt:run" => "carlini-threat-hunt",
        "taint" | "iris" | "taint-iris:hunt" => "taint-iris",
        "taint-next" | "iris-next" | "taint-iris-next:hunt" => "taint-iris-next",
        "systems" | "systems-hunt:systems-hunt" => "systems-hunt",
        other => other,
    };
    SAST_TASK_CAPABILITIES
        .iter()
        .find(|task| task.id == normalized || task.scan_task == normalized)
}

pub(super) fn parse_native_scan_tasks(input: &serde_json::Value) -> Result<Option<Vec<String>>> {
    let mode = input
        .get("taskMode")
        .or_else(|| input.get("task_mode"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("auto");
    if !matches!(mode, "auto" | "manual") {
        anyhow::bail!("scan taskMode must be auto or manual");
    }

    let requested = read_task_list_value(input.get("tasks"));
    let disabled = read_task_list_value(
        input
            .get("disabledTasks")
            .or_else(|| input.get("disabled_tasks")),
    );
    let disabled = disabled
        .iter()
        .filter_map(|task| resolve_sast_task(task).map(|task| task.id))
        .collect::<BTreeSet<_>>();

    let selected = if !requested.is_empty() {
        requested
    } else if !disabled.is_empty() {
        SAST_TASK_CAPABILITIES
            .iter()
            .filter(|task| task.default_enabled && !disabled.contains(task.id))
            .map(|task| task.id.to_string())
            .collect()
    } else {
        Vec::new()
    };

    if mode == "manual" && selected.is_empty() {
        anyhow::bail!("scan taskMode=manual requires at least one task. Next: /task mode auto");
    }
    if selected.is_empty() {
        return Ok(None);
    }

    let mut native_tasks = Vec::new();
    let mut unsupported = Vec::new();
    for raw in selected {
        let Some(task) = resolve_sast_task(&raw) else {
            anyhow::bail!("{}", unknown_sast_task_message(&raw));
        };
        if task.native_scan {
            native_tasks.push(task.scan_task.to_string());
        } else {
            unsupported.push(task.id);
        }
    }
    if !unsupported.is_empty() {
        anyhow::bail!(
            "scan supports native tasks only; unsupported here: {}. Next: run sast:scan",
            unsupported.join(", ")
        );
    }
    if native_tasks.is_empty() {
        anyhow::bail!("scan selected no native tasks. Next: /tasks or run sast:scan");
    }

    Ok(Some(native_tasks))
}

fn read_task_list_value(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn toggle_sast_task_blocks_enabled_tasks_and_allows_disabled_tasks() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let blocked = app.toggle_sast_task("semgrep").unwrap();
        assert!(blocked.contains("Blocked SAST task"));
        assert!(app.current_disabled_sast_tasks().contains("semgrep"));

        let allowed = app.toggle_sast_task("semgrep").unwrap();
        assert!(allowed.contains("Allowed SAST task"));
        assert!(!app.current_disabled_sast_tasks().contains("semgrep"));
    }

    #[test]
    fn toggle_sast_task_reports_unknown_ids_actionably() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let error = app.toggle_sast_task("made-up").unwrap_err().to_string();
        assert!(error.contains("unknown SAST task"));
    }
}
