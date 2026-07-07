use super::*;

pub(crate) fn parse_nested_shell_command(
    verb: &str,
    args: &[&str],
    original: &str,
) -> Option<ShellCommand> {
    let command = match verb {
        "options" => options_command(args, OptionsFilter::Standard),
        "findings" | "f" => parse_findings_command(args),
        "auth" => parse_auth_command(args),
        "threats" => parse_threat_command(args),
        "show" => parse_show_command(args, original),
        "run" => parse_run_command(args.to_vec()),
        "set" => parse_set_command(false, args.to_vec()),
        "setg" => parse_set_command(true, args.to_vec()),
        "unset" => parse_unset_command(false, args.to_vec()),
        "unsetg" => parse_unset_command(true, args.to_vec()),
        "task" => parse_task_command(args.to_vec()),
        "context" => parse_context_command(args.to_vec()),
        "project" => parse_project_command(args),
        "runs" => parse_runs_command(args),
        "strategy" | "strategies" => parse_strategy_command(args),
        "decision" | "review" => parse_review_decision_command(args),
        "patch" => parse_patch_command(args),
        "workspace" => parse_workspace_command(args.to_vec()),
        "pwn" => parse_pwn_command(args),
        _ => return None,
    };
    Some(command)
}

fn parse_runs_command(args: &[&str]) -> ShellCommand {
    match args {
        [] => ShellCommand::ShowRuns,
        ["diff", left, right] | ["compare", left, right] => ShellCommand::RunDiff {
            left: (*left).to_string(),
            right: (*right).to_string(),
        },
        ["diff" | "compare", ..] => ShellCommand::Unknown("runs diff".to_string()),
        [other, ..] => ShellCommand::Unknown(format!("runs {other}")),
    }
}

fn parse_project_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        None | Some("model") => ShellCommand::ProjectModel,
        Some(other) => ShellCommand::Unknown(format!("project {other}")),
    }
}

fn parse_strategy_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        None | Some("queue") => ShellCommand::Strategy(StrategyCommand::Show),
        Some("approve") | Some("accept") | Some("keep") => args
            .get(1)
            .map(|id| ShellCommand::Strategy(StrategyCommand::Approve((*id).to_string())))
            .unwrap_or_else(|| {
                ShellCommand::Strategy(StrategyCommand::Unsupported("strategy approve".to_string()))
            }),
        Some("reject") | Some("deny") | Some("skip") => args
            .get(1)
            .map(|id| ShellCommand::Strategy(StrategyCommand::Reject((*id).to_string())))
            .unwrap_or_else(|| {
                ShellCommand::Strategy(StrategyCommand::Unsupported("strategy reject".to_string()))
            }),
        Some("fire") | Some("run") => ShellCommand::Strategy(StrategyCommand::Fire),
        Some("correct") | Some("correction") => parse_strategy_correction_command(args),
        Some(other) => {
            ShellCommand::Strategy(StrategyCommand::Unsupported(format!("strategy {other}")))
        }
    }
}

fn parse_strategy_correction_command(args: &[&str]) -> ShellCommand {
    let Some(id) = args.get(1) else {
        return ShellCommand::Strategy(StrategyCommand::Unsupported(
            "strategy correct".to_string(),
        ));
    };
    let mut scope = StrategyCorrectionCommandScope::Run;
    let mut before_reason = Vec::new();
    let mut reason = Vec::new();
    let mut reading_reason = false;
    for token in args.iter().skip(2) {
        match *token {
            "--workspace" => scope = StrategyCorrectionCommandScope::Workspace,
            "--run" => scope = StrategyCorrectionCommandScope::Run,
            "--reason" => reading_reason = true,
            value if reading_reason => reason.push(value),
            value => before_reason.push(value),
        }
    }
    let to_strategy = before_reason.join(" ");
    if to_strategy.trim().is_empty() {
        return ShellCommand::Strategy(StrategyCommand::Unsupported(
            "strategy correct".to_string(),
        ));
    }
    ShellCommand::Strategy(StrategyCommand::Correct {
        id: (*id).to_string(),
        to_strategy,
        reason: (!reason.is_empty()).then(|| reason.join(" ")),
        scope,
    })
}

fn parse_review_decision_command(args: &[&str]) -> ShellCommand {
    let Some(verdict) = args.first().copied() else {
        return ShellCommand::ReviewDecision(ReviewDecisionCommand::Unsupported(
            "decision".to_string(),
        ));
    };
    let reason = args.get(1..).unwrap_or_default().join(" ");
    if reason.trim().is_empty() {
        return ShellCommand::ReviewDecision(ReviewDecisionCommand::Unsupported(format!(
            "decision {verdict}"
        )));
    }
    ShellCommand::ReviewDecision(ReviewDecisionCommand::Record {
        verdict: verdict.to_string(),
        reason,
    })
}

fn parse_patch_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        Some("apply") => ShellCommand::Patch(PatchCommand::Apply),
        Some("reject" | "discard") => ShellCommand::Patch(PatchCommand::Reject),
        Some("regen" | "regenerate") => ShellCommand::Patch(PatchCommand::Regen {
            style: parse_patch_regen_style(args.get(1..).unwrap_or_default()),
        }),
        Some(other) => ShellCommand::Patch(PatchCommand::Unsupported(format!("patch {other}"))),
        None => ShellCommand::Patch(PatchCommand::Unsupported("patch".to_string())),
    }
}

fn parse_patch_regen_style(args: &[&str]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(token) = iter.next() {
        if let Some(style) = token.strip_prefix("--style=") {
            return non_empty_style(style);
        }
        if *token == "--style" {
            return iter.next().and_then(|style| non_empty_style(style));
        }
    }
    None
}

fn non_empty_style(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub(crate) fn options_command(args: &[&str], filter: OptionsFilter) -> ShellCommand {
    ShellCommand::Options {
        tool: args.first().map(|value| (*value).to_string()),
        filter,
    }
}

pub(crate) fn parse_findings_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        Some("filter") => {
            let expression = args.get(1..).unwrap_or_default().join(" ");
            if expression.trim().is_empty() {
                ShellCommand::Unknown("findings filter".to_string())
            } else {
                ShellCommand::FindingsFilter(expression)
            }
        }
        Some("export") => parse_workspace_findings_export_args(
            args.get(1..).unwrap_or_default(),
            "findings export",
        ),
        Some(other) => ShellCommand::Unknown(format!("findings {other}")),
        None => ShellCommand::Findings,
    }
}

fn parse_pwn_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        None => ShellCommand::Pwn(PwnCommand::Show),
        Some("target") => args
            .get(1)
            .map(|path| ShellCommand::Pwn(PwnCommand::Target(PathBuf::from(path))))
            .unwrap_or_else(|| {
                ShellCommand::Pwn(PwnCommand::Unsupported("pwn target".to_string()))
            }),
        Some("profile") => ShellCommand::Pwn(PwnCommand::Profile),
        Some("reverse") => ShellCommand::Pwn(PwnCommand::Reverse(
            args.get(1).map(|value| (*value).to_string()),
        )),
        Some("auto") => ShellCommand::Pwn(PwnCommand::Auto),
        Some("state") => ShellCommand::Pwn(PwnCommand::State),
        Some("candidates") => {
            let target = args.get(1..).unwrap_or_default().join(" ");
            if target.trim().is_empty() {
                ShellCommand::Pwn(PwnCommand::Unsupported("pwn candidates".to_string()))
            } else {
                ShellCommand::Pwn(PwnCommand::Candidates(target))
            }
        }
        Some(other) => ShellCommand::Pwn(PwnCommand::Unsupported(format!("pwn {other}"))),
    }
}
