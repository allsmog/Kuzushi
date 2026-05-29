use super::*;

impl ShellApp {
    pub fn handle_command(&mut self, command: ShellCommand) {
        for handler in COMMAND_HANDLERS {
            if handler(self, &command) {
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
        self.log(">", raw.to_string());
        self.remember_command(trimmed);
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

    fn remember_command(&mut self, trimmed: &str) {
        self.command_history.push(trimmed.to_string());
        if self.command_history.len() > COMMAND_HISTORY_CAP {
            let overflow = self.command_history.len() - COMMAND_HISTORY_CAP;
            self.command_history.drain(0..overflow);
        }
        self.persist_command_history();
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
}

pub(crate) fn handle_home_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Home = command else {
        return false;
    };
    app.focused_module = None;
    app.catalog_expanded = false;
    app.shell_view = ShellView::Home;
    app.log("home", "showing Kuzushi cockpit");
    true
}

pub(crate) fn handle_help_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Help = command else {
        return false;
    };
    app.shell_view = ShellView::Help;
    app.help_scroll = 0;
    app.log("help", compact_help_summary());
    true
}

pub(crate) fn handle_back_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Back = command else {
        return false;
    };
    app.go_back();
    true
}

pub(crate) fn handle_modules_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Modules = command else {
        return false;
    };
    app.shell_view = ShellView::Catalog;
    app.catalog_expanded = true;
    app.modules_scroll = 0;
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
    app.shell_view = ShellView::Recommend;
    app.log("recommend", "latest module recommendations");
    true
}

pub(crate) fn handle_tools_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tools = command else {
        return false;
    };
    app.shell_view = ShellView::Tools;
    app.tools_scroll = 0;
    let count = app.registry.tools().count();
    app.log(
        "tool",
        format!(
            "showing {count} {}",
            if count == 1 { "tool" } else { "tools" }
        ),
    );
    true
}

pub(crate) fn handle_findings_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Findings = command else {
        return false;
    };
    app.show_findings();
    true
}

pub(crate) fn handle_pwn_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Pwn(command) = command else {
        return false;
    };
    app.handle_pwn_command(command);
    true
}

pub(crate) fn handle_open_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Open(id) = command else {
        return false;
    };
    app.open_finding(id);
    true
}
