use super::*;

impl ShellApp {
    /// Pop the most recent entry off `nav_history` and switch to it.
    /// Falls back to `Home` only when the stack is empty (e.g. first
    /// command after boot). The stack is maintained by `sync_view_change`
    /// — every transition into a new view pushes the prior view here.
    pub(crate) fn go_back(&mut self) {
        let target = self.nav_history.pop().unwrap_or(ShellView::Home);
        if matches!(target, ShellView::Home) {
            self.focused_module = None;
            self.catalog_expanded = false;
        }
        self.shell_view = target;
    }

    /// Label the destination of `back` so the keybind footer can read
    /// `back tools`, `back findings`, etc. Returns the lowercase short
    /// label of the top of `nav_history`, or `"home"` when empty.
    pub(crate) fn back_destination_label(&self) -> &'static str {
        match self.nav_history.last() {
            Some(ShellView::Home) => "home",
            Some(ShellView::Catalog) => "modules",
            Some(ShellView::Module) => "module",
            Some(ShellView::ModuleRun) => "run",
            Some(ShellView::Findings) => "findings",
            Some(ShellView::Finding) => "finding",
            Some(ShellView::Help) => "help",
            Some(ShellView::Tools) => "tools",
            Some(ShellView::Config) => "config",
            Some(ShellView::Auth) => "auth",
            Some(ShellView::Options(_)) => "options",
            Some(ShellView::SastTasks) => "tasks",
            Some(ShellView::Context) => "context",
            Some(ShellView::Workspace) => "workspace",
            Some(ShellView::KnowledgeBase) => "kb",
            Some(ShellView::History) => "history",
            Some(ShellView::Story) => "story",
            Some(ShellView::Runs) => "runs",
            Some(ShellView::Replay(_)) => "replay",
            Some(ShellView::Trace(_)) => "trace",
            Some(ShellView::Activity) => "activity",
            Some(ShellView::Recommend) => "recommend",
            Some(ShellView::Quickstart) => "quickstart",
            Some(ShellView::Threat(_)) => "threats",
            Some(ShellView::ThreatEditor) => "threats edit",
            Some(ShellView::PromptsEditor) => "prompts",
            Some(ShellView::Tune) => "tune",
            Some(ShellView::ActorDetail(_)) => "actor",
            Some(ShellView::AgentChat) => "agent",
            Some(ShellView::Cost) => "cost",
            Some(ShellView::Patch(_)) => "patch",
            Some(ShellView::Pwn) => "pwn",
            Some(ShellView::FailureHandoff) => "handoff",
            None => "home",
        }
    }
}
