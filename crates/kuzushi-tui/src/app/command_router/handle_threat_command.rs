use super::*;
use std::path::Path;
use std::process::Command;

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
    let expression = match since_filter_expression(app.target.as_deref(), reference) {
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

fn since_filter_expression(target: Option<&Path>, reference: &str) -> anyhow::Result<String> {
    let reference = normalized_since_ref(reference)?;
    let target = target.ok_or_else(|| anyhow::anyhow!("since requires an active target"))?;
    if let Some(sha) = resolve_git_ref(target, reference) {
        return Ok(format!("rev:{sha}"));
    }
    if looks_like_sha_prefix(reference) {
        return Ok(format!("rev:{}", reference.to_ascii_lowercase()));
    }
    Ok(format!("branch:{}", reference.to_ascii_lowercase()))
}

fn normalized_since_ref(reference: &str) -> anyhow::Result<&str> {
    let reference = reference.trim();
    if reference.is_empty() {
        anyhow::bail!("since needs a git ref");
    }
    if reference.split_whitespace().count() > 1 {
        anyhow::bail!("since git ref cannot contain whitespace");
    }
    Ok(reference)
}

fn resolve_git_ref(target: &Path, reference: &str) -> Option<String> {
    let commit_spec = format!("{reference}^{{commit}}");
    git_stdout(
        target,
        &["rev-parse", "--verify", "--quiet", commit_spec.as_str()],
    )
}

fn git_stdout(target: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn looks_like_sha_prefix(reference: &str) -> bool {
    reference.len() >= 7 && reference.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(crate) fn handle_replay_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Replay(run_id) = command else {
        return false;
    };
    app.shell_view = ShellView::Replay(run_id.clone());
    app.log("replay", run_id);
    true
}
