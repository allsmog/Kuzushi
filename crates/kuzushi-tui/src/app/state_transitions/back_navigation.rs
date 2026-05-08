use super::*;

impl ShellApp {
    pub(crate) fn go_back(&mut self) {
        self.shell_view = match self.shell_view {
            ShellView::Finding => ShellView::Findings,
            ShellView::Findings
            | ShellView::Help
            | ShellView::Quickstart
            | ShellView::Config
            | ShellView::Tools
            | ShellView::Runs
            | ShellView::Replay(_)
            | ShellView::Trace(_)
            | ShellView::History
            | ShellView::Story
            | ShellView::Auth
            | ShellView::Cost
            | ShellView::Patch(_)
            | ShellView::Threat(_)
            | ShellView::ThreatEditor => ShellView::Catalog,
            ShellView::Tune
            | ShellView::PromptsEditor
            | ShellView::Options(_)
            | ShellView::SastTasks
            | ShellView::Context
            | ShellView::Workspace
            | ShellView::KnowledgeBase
            | ShellView::AgentChat => {
                if self.focused_module.is_some() {
                    ShellView::Module
                } else {
                    ShellView::Catalog
                }
            }
            ShellView::ActorDetail(_) => ShellView::ModuleRun,
            ShellView::ModuleRun | ShellView::Module => ShellView::Catalog,
            ShellView::Catalog => ShellView::Catalog,
        };
    }
}
