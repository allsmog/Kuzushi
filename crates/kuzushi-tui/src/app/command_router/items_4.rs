use super::prelude::*;
use super::*;

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
    app.shell_view = ShellView::Findings;
    app.log("since", reference);
    true
}

pub(crate) fn handle_replay_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Replay(run_id) = command else {
        return false;
    };
    app.shell_view = ShellView::Replay(run_id.clone());
    app.log("replay", run_id);
    true
}
