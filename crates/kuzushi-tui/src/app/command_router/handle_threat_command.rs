use super::*;
use kuzushi_core::workspace::findings_since_filter_expression;
use std::path::Path;

pub(crate) fn handle_threat_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Threat(view) = command else {
        return false;
    };
    app.shell_view = ShellView::Threat(*view);
    app.log("view", format!("threats {}", threat_view_label(*view)));
    true
}

pub(crate) fn handle_threat_regen_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatRegen = command else {
        return false;
    };
    app.start_threat_regen();
    true
}

pub(crate) fn handle_threat_ask_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatAsk(question) = command else {
        return false;
    };
    app.start_threat_ask(question);
    true
}

pub(crate) fn handle_threat_apply_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatApply = command else {
        return false;
    };
    app.apply_pending_threat_patch();
    true
}

pub(crate) fn handle_threat_reject_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatReject = command else {
        return false;
    };
    app.discard_pending_threat_patch();
    true
}

pub(crate) fn handle_threat_editor_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatEditor = command else {
        return false;
    };
    app.shell_view = ShellView::ThreatEditor;
    app.log("view", "threats edit");
    true
}

pub(crate) fn handle_prompts_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Prompts = command else {
        return false;
    };
    app.shell_view = ShellView::PromptsEditor;
    app.log("view", "prompts");
    true
}

pub(crate) fn handle_prompt_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Prompt(raw) = command else {
        return false;
    };
    app.shell_view = ShellView::PromptsEditor;
    app.handle_prompt_verb(raw);
    true
}

pub(crate) fn handle_actor_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Actor(index) = command else {
        return false;
    };
    app.shell_view = ShellView::ActorDetail(*index);
    app.log("actor", index.to_string());
    true
}

pub(crate) fn handle_show_runs_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ShowRuns = command else {
        return false;
    };
    app.shell_view = ShellView::Runs;
    app.log("runs", "recent runs");
    true
}

pub(crate) fn handle_run_diff_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::RunDiff { left, right } = command else {
        return false;
    };
    app.shell_view = ShellView::RunDiff {
        left: left.clone(),
        right: right.clone(),
    };
    app.scroll_offset = 0;
    app.log("runs", format!("comparing {left} -> {right}"));
    true
}

pub(crate) fn handle_show_aliases_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ShowAliases(prefix) = command else {
        return false;
    };
    app.show_aliases(prefix.as_deref());
    true
}

pub(crate) fn handle_since_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Since(reference) = command else {
        return false;
    };
    let expression = match findings_since_filter_expression(app.target.as_deref(), reference) {
        Ok(expression) => expression,
        Err(error) => {
            app.log(
                "error",
                with_next_step(error.to_string(), "target <path> then since <ref>"),
            );
            return true;
        }
    };
    app.shell_view = ShellView::Workbench;
    app.workbench_focus = crate::app::WorkbenchPane::Findings;
    app.refresh_findings_filtered(&expression);
    true
}

pub(crate) fn handle_replay_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Replay(run_id) = command else {
        return false;
    };
    let Some(resolved) = resolve_run_selector(app, run_id, "replay") else {
        return true;
    };
    app.shell_view = ShellView::Replay(resolved.clone());
    app.log("replay", resolved);
    true
}

fn resolve_run_selector(app: &mut ShellApp, selector: &str, verb: &str) -> Option<String> {
    if selector != "latest" {
        return Some(selector.to_string());
    }
    let Some(target) = app.target.as_deref() else {
        app.log(
            "error",
            format!("{verb} latest needs a target. Next: target <path> or show runs"),
        );
        return None;
    };
    let latest_path = crate::ui_view_models::ui_latest_run_path(Some(target));
    let text = match std::fs::read_to_string(&latest_path) {
        Ok(text) => text,
        Err(error) => {
            app.log(
                "error",
                format!(
                    "could not read latest run pointer {}: {error}. Next: show runs",
                    latest_path.display()
                ),
            );
            return None;
        }
    };
    let run_id = text.trim();
    if run_id.is_empty() {
        app.log(
            "error",
            format!(
                "latest run pointer {} is empty. Next: show runs",
                latest_path.display()
            ),
        );
        return None;
    }
    Some(run_id.to_string())
}
