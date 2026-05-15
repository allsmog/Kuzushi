use super::*;

impl ShellApp {
    pub(crate) fn go_back(&mut self) {
        let target = back_target_view(self.shell_view.clone(), self.focused_module.is_some());
        if matches!(target, ShellView::Home) {
            self.focused_module = None;
            self.catalog_expanded = false;
        }
        self.shell_view = target;
    }
}

fn back_target_view(view: ShellView, has_focused_module: bool) -> ShellView {
    if matches!(view, ShellView::Finding) {
        return ShellView::Findings;
    }
    back_target_after_finding(view, has_focused_module)
}

fn back_target_after_finding(view: ShellView, has_focused_module: bool) -> ShellView {
    if returns_to_module(&view) {
        return module_or_catalog(has_focused_module);
    }
    if matches!(view, ShellView::ActorDetail(_)) {
        return ShellView::ModuleRun;
    }
    ShellView::Home
}

fn returns_to_module(view: &ShellView) -> bool {
    matches!(
        view,
        ShellView::Tune
            | ShellView::PromptsEditor
            | ShellView::Options(_)
            | ShellView::SastTasks
            | ShellView::Context
            | ShellView::Workspace
            | ShellView::KnowledgeBase
            | ShellView::AgentChat
    )
}

fn module_or_catalog(has_focused_module: bool) -> ShellView {
    if has_focused_module {
        ShellView::Module
    } else {
        ShellView::Home
    }
}

fn returns_to_catalog(view: &ShellView) -> bool {
    matches!(
        view,
        ShellView::Findings
            | ShellView::Help
            | ShellView::Quickstart
            | ShellView::Config
            | ShellView::Tools
            | ShellView::Runs
            | ShellView::Replay(_)
            | ShellView::Trace(_)
            | ShellView::Activity
            | ShellView::History
            | ShellView::Story
            | ShellView::Auth
            | ShellView::Cost
            | ShellView::Patch(_)
            | ShellView::Pwn
            | ShellView::Threat(_)
            | ShellView::ThreatEditor
            | ShellView::ModuleRun
            | ShellView::Module
            | ShellView::Home
            | ShellView::Catalog
    )
}
