use super::*;

impl ShellApp {
    pub fn handle_command(&mut self, command: ShellCommand) {
        let previous_view = self.shell_view.clone();
        if let Some(effects) = self.reduce_command_effects(&command) {
            self.execute_effects(effects);
            self.discard_stashed_input_after_view_change(&previous_view);
            return;
        }
        for handler in COMMAND_HANDLERS {
            if handler(self, &command) {
                self.discard_stashed_input_after_view_change(&previous_view);
                return;
            }
        }
    }

    pub fn submit_line(&mut self, raw: &str) {
        let trimmed = raw.trim();
        // Empty / whitespace-only Enter is a no-op (P-NEW-3): logging an empty
        // `>` bullet just clutters the 2-row transcript with rows the operator
        // never asked for.
        if trimmed.is_empty() {
            return;
        }
        self.last_cleared_input = None;
        self.log(">", raw.to_string());
        let history_effects = self.reduce_remember_command(trimmed);
        self.execute_effects(history_effects);
        if self.handle_subverb_query(trimmed) {
            return;
        }
        if self.handle_editor_local_command(trimmed) {
            return;
        }
        self.handle_command(parse_command(raw));
    }

    /// `<group-verb> ?` lists the verb's sub-verbs inline. Editor-local so it
    /// adds no `ShellCommand` route; the listing comes from the same
    /// `subverb_listing` table Tab-completion uses, so they never drift.
    fn handle_subverb_query(&mut self, trimmed: &str) -> bool {
        let stripped = trimmed.strip_prefix('/').unwrap_or(trimmed);
        let mut words = stripped.split_whitespace();
        let (Some(verb), Some("?"), None) = (words.next(), words.next(), words.next()) else {
            return false;
        };
        let Some(subverbs) = subverb_listing(verb) else {
            return false;
        };
        self.log(verb, format!("sub-verbs: {}", subverbs.join(", ")));
        true
    }

    pub(crate) fn reduce_remember_command(&mut self, trimmed: &str) -> Vec<ShellEffect> {
        self.command_history.push(trimmed.to_string());
        if self.command_history.len() > COMMAND_HISTORY_CAP {
            let overflow = self.command_history.len() - COMMAND_HISTORY_CAP;
            self.command_history.drain(0..overflow);
        }
        if self.history_file_path().is_some() {
            vec![ShellEffect::PersistCommandHistory]
        } else {
            Vec::new()
        }
    }

    fn handle_editor_local_command(&mut self, trimmed: &str) -> bool {
        if self.handle_prompt_editor_local_command(trimmed) {
            return true;
        }
        self.handle_tune_local_command(trimmed)
    }

    fn handle_prompt_editor_local_command(&mut self, trimmed: &str) -> bool {
        if !matches!(self.shell_view, ShellView::PromptsEditor)
            || trimmed.starts_with('/')
            || !self.is_bare_prompt_verb(trimmed)
        {
            return false;
        }
        self.handle_prompt_verb(trimmed);
        true
    }

    fn handle_tune_local_command(&mut self, trimmed: &str) -> bool {
        if !matches!(self.shell_view, ShellView::Tune)
            || trimmed.starts_with('/')
            || !self.is_bare_tune_verb(trimmed)
        {
            return false;
        }
        self.handle_tune_verb(trimmed);
        true
    }

    pub(crate) fn is_bare_prompt_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "edit" | "show" | "diff" | "reset" | "set" | "list")
    }

    pub(crate) fn is_bare_tune_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "show" | "set" | "reset")
    }

    fn discard_stashed_input_after_view_change(&mut self, previous_view: &ShellView) {
        if &self.shell_view != previous_view {
            self.last_cleared_input = None;
        }
    }
}

pub(crate) fn handle_home_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Home = command else {
        return false;
    };
    app.focused_module = None;
    app.catalog_route.collapse();
    app.shell_view = ShellView::Home;
    app.log("home", "showing Kuzushi cockpit");
    true
}

pub(crate) fn handle_help_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Help(query) = command else {
        return false;
    };
    app.shell_view = ShellView::Help;
    app.router.help_mut().open(query.clone());
    app.log("help", help_log_summary(query.as_deref()));
    true
}

fn help_log_summary(query: Option<&str>) -> String {
    query.map_or_else(compact_help_summary, |query| {
        format!("filtered command reference for `{query}`")
    })
}

pub(crate) fn handle_back_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Back = command else {
        return false;
    };
    app.go_back();
    true
}

pub(crate) fn handle_cancel_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Cancel = command else {
        return false;
    };
    if !app.request_active_abort() {
        app.log("cancel", "no active scan/tool/agent to cancel");
    }
    true
}

pub(crate) fn handle_modules_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Modules = command else {
        return false;
    };
    app.shell_view = ShellView::Catalog;
    app.catalog_route.expand();
    app.router.modules_mut().open();
    let count = app.registry.modules().count();
    app.log(
        "module",
        format!(
            "showing {count} {}",
            if count == 1 { "module" } else { "modules" }
        ),
    );
    true
}

pub(crate) fn handle_recommend_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Recommend = command else {
        return false;
    };
    let effects = app.reduce_recommend();
    app.execute_effects(effects);
    true
}

pub(crate) fn handle_tools_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tools(filter) = command else {
        return false;
    };
    app.shell_view = ShellView::Tools;
    app.router.tools_mut().open(filter.clone());
    let model = crate::ui_view_models::tools_model(app);
    let suffix = filter
        .as_ref()
        .map(|query| format!(" matching {query:?}"))
        .unwrap_or_default();
    app.log(
        "tool",
        format!(
            "showing {} of {} {}{}",
            model.visible_count,
            model.total_count,
            if model.total_count == 1 {
                "tool"
            } else {
                "tools"
            },
            suffix
        ),
    );
    true
}

pub(crate) fn handle_health_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Health = command else {
        return false;
    };
    app.shell_view = ShellView::Health;
    app.scroll_offset = 0;
    let model = crate::ui_view_models::health_model(app);
    app.log("health", model.summary);
    true
}

pub(crate) fn handle_workbench_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Workbench(pane) = command else {
        return false;
    };
    app.open_workbench(*pane);
    true
}

pub(crate) fn handle_aim_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Aim(focus) = command else {
        return false;
    };
    let effects = app.reduce_aim(focus);
    app.execute_effects(effects);
    true
}

pub(crate) fn handle_findings_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    match command {
        ShellCommand::Findings => {
            app.show_findings();
            true
        }
        ShellCommand::FindingsFilter(expression) => {
            app.shell_view = ShellView::Workbench;
            app.workbench_focus = crate::app::WorkbenchPane::Findings;
            app.refresh_findings_filtered(expression);
            true
        }
        _ => false,
    }
}

pub(crate) fn handle_component_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Component(selection) = command else {
        return false;
    };
    app.apply_component_selection(selection.as_deref());
    true
}

pub(crate) fn handle_pwn_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Pwn(command) = command else {
        return false;
    };
    app.handle_pwn_command(command);
    true
}

pub(crate) fn handle_project_model_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ProjectModel = command else {
        return false;
    };
    app.shell_view = ShellView::ProjectModel;
    app.scroll_offset = 0;
    app.log("project", "showing project model aggregate");
    true
}

pub(crate) fn handle_strategy_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Strategy(command) = command else {
        return false;
    };
    app.open_strategy_queue();
    app.apply_strategy_command(command);
    true
}

pub(crate) fn handle_open_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Open(id) = command else {
        return false;
    };
    app.open_finding(id);
    true
}
