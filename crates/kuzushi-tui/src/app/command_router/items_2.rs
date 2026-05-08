use super::prelude::*;
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
        // Empty / whitespace-only Enter is a no-op. Logging an empty `>`
        // bullet just clutters the 2-row transcript with `· ` rows the
        // operator never asked for.
        if trimmed.is_empty() {
            return;
        }
        self.log(">", raw.to_string());
        self.command_history.push(trimmed.to_string());
        if self.command_history.len() > 200 {
            let overflow = self.command_history.len() - 200;
            self.command_history.drain(0..overflow);
        }
        if matches!(self.shell_view, ShellView::PromptsEditor)
            && !trimmed.is_empty()
            && !trimmed.starts_with('/')
            && self.is_bare_prompt_verb(trimmed)
        {
            self.handle_prompt_verb(trimmed);
            return;
        }
        if matches!(self.shell_view, ShellView::Tune)
            && !trimmed.is_empty()
            && !trimmed.starts_with('/')
            && self.is_bare_tune_verb(trimmed)
        {
            self.handle_tune_verb(trimmed);
            return;
        }
        self.handle_command(parse_command(raw));
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
    app.log(
        "module",
        format!("showing {} module(s)", app.registry.modules().count()),
    );
    true
}

pub(crate) fn handle_tools_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tools = command else {
        return false;
    };
    app.shell_view = ShellView::Tools;
    app.tools_scroll = 0;
    app.log(
        "tool",
        format!("showing {} tool(s)", app.registry.tools().count()),
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

pub(crate) fn handle_open_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Open(id) = command else {
        return false;
    };
    app.open_finding(id);
    true
}
