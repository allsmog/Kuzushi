use super::*;

pub(crate) fn parse_nested_shell_command(
    verb: &str,
    args: &[&str],
    original: &str,
) -> Option<ShellCommand> {
    let command = match verb {
        "options" | "findings" | "f" | "export" => parse_finding_surface_command(verb, args),
        "recon:import" | "recon-import" => parse_recon_import_command(args),
        "recon" => return parse_recon_nested_command(args),
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
        "jobs" => parse_jobs_command(args),
        "campaign" | "campaigns" | "batch" | "coverage" => {
            parse_campaign_surface_command(verb, args)
        }
        "queue" => parse_queue_command(args),
        "relationships" | "groups" | "lessons" | "goals" => parse_relationship_view(verb, args),
        "strategy" | "strategies" => parse_strategy_command(args),
        "decision" | "review" => parse_review_decision_command(args),
        "proof" => parse_proof_command(args),
        "dismiss" => parse_dismiss_command(args),
        "suppress" | "x" => parse_suppress_command(args),
        "verify" | "v" => parse_verify_command(args),
        "patch" => parse_patch_command(args),
        "workspace" => parse_workspace_command(args.to_vec()),
        "pwn" => parse_pwn_command(args),
        _ => return None,
    };
    Some(command)
}

fn parse_relationship_view(verb: &str, args: &[&str]) -> ShellCommand {
    match verb {
        "groups" => ShellCommand::ShowFindingGroups,
        "lessons" => ShellCommand::ShowLessons,
        "goals" => ShellCommand::ShowGoalReview(args.first().map(|id| (*id).to_string())),
        _ => ShellCommand::ShowRelationships,
    }
}

fn parse_finding_surface_command(verb: &str, args: &[&str]) -> ShellCommand {
    match verb {
        "options" => options_command(args, OptionsFilter::Standard),
        "export" => parse_workspace_findings_export_args(args),
        _ => parse_findings_command(args),
    }
}

fn parse_campaign_surface_command(verb: &str, args: &[&str]) -> ShellCommand {
    match verb {
        "campaign" | "campaigns" => parse_campaign_command(args),
        "batch" => parse_batch_command(args),
        _ => ShellCommand::ShowCoverage,
    }
}

fn parse_batch_command(args: &[&str]) -> ShellCommand {
    match args {
        ["clear"] => ShellCommand::ClearBatchScope,
        [batch_id] => ShellCommand::BatchResults((*batch_id).to_string()),
        _ => ShellCommand::Unknown("batch <id>|clear".to_string()),
    }
}

fn parse_recon_nested_command(args: &[&str]) -> Option<ShellCommand> {
    (args.first() == Some(&"import"))
        .then(|| parse_recon_import_command(args.get(1..).unwrap_or_default()))
}

fn parse_proof_command(args: &[&str]) -> ShellCommand {
    let ["defer", reference, rest @ ..] = args else {
        return ShellCommand::Unknown("proof defer <finding> --reason <text>".to_string());
    };
    let reason = rest.strip_prefix(&["--reason"]).unwrap_or(rest).join(" ");
    if reason.trim().is_empty() {
        return ShellCommand::Unknown("proof defer <finding> --reason <text>".to_string());
    }
    ShellCommand::ProofDeferral {
        reference: (*reference).to_string(),
        reason,
    }
}

fn parse_recon_import_command(args: &[&str]) -> ShellCommand {
    let Some(tool) = args.first() else {
        return ShellCommand::RunTool {
            tool: Some("recon:import".to_string()),
            input: None,
        };
    };
    let path = args.get(1..).unwrap_or_default().join(" ");
    if path.trim().is_empty() {
        return ShellCommand::RunTool {
            tool: Some("recon:import".to_string()),
            input: Some(serde_json::json!({ "tool": tool }).to_string()),
        };
    }
    ShellCommand::RunTool {
        tool: Some("recon:import".to_string()),
        input: Some(serde_json::json!({ "tool": tool, "path": path }).to_string()),
    }
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

fn parse_jobs_command(args: &[&str]) -> ShellCommand {
    match args {
        [] | ["list"] => ShellCommand::ShowJobs,
        ["-k", id] | ["kill", id] | ["cancel", id] => ShellCommand::CancelJob((*id).to_string()),
        ["-k"] | ["kill"] | ["cancel"] => ShellCommand::Unknown("jobs -k <id>".to_string()),
        [other, ..] => ShellCommand::Unknown(format!("jobs {other}")),
    }
}

fn parse_campaign_command(args: &[&str]) -> ShellCommand {
    match args {
        [] | ["list"] => ShellCommand::ShowCampaigns(None),
        [id] => ShellCommand::ShowCampaigns(Some((*id).to_string())),
        [other, ..] => ShellCommand::Unknown(format!("campaign {other}")),
    }
}

fn parse_queue_command(args: &[&str]) -> ShellCommand {
    let rest = args.join(" ");
    if rest.trim().is_empty() {
        ShellCommand::ShowJobs
    } else {
        ShellCommand::QueueCommand(rest)
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
        Some("inspect") if args.len() == 2 => {
            ShellCommand::Strategy(StrategyCommand::Inspect(args[1].to_owned()))
        }
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

fn parse_dismiss_command(args: &[&str]) -> ShellCommand {
    let Some(reason) = args.first().copied() else {
        return ShellCommand::ReviewDecision(ReviewDecisionCommand::Unsupported(
            "dismiss".to_string(),
        ));
    };
    let note = args.get(1..).unwrap_or_default().join(" ");
    if note.trim().is_empty() {
        return ShellCommand::ReviewDecision(ReviewDecisionCommand::Unsupported(format!(
            "dismiss {reason}"
        )));
    }
    ShellCommand::ReviewDecision(ReviewDecisionCommand::Dismiss {
        reason: reason.to_string(),
        note,
    })
}

fn parse_suppress_command(args: &[&str]) -> ShellCommand {
    let Some(reference) = args.first() else {
        return unsupported_suppress();
    };
    let mut reason = Vec::new();
    let mut author = "operator".to_string();
    let mut days = 90_u64;
    let mut index = 1;
    while index < args.len() {
        match args[index] {
            "--reason" => index += collect_suppress_reason(args, index + 1, &mut reason),
            "--author" => {
                let Some(value) = args.get(index + 1) else {
                    return unsupported_suppress();
                };
                author = (*value).to_string();
                index += 2;
            }
            "--days" => {
                let Some(value) = args.get(index + 1).and_then(|value| value.parse().ok()) else {
                    return unsupported_suppress();
                };
                days = value;
                index += 2;
            }
            _ => return unsupported_suppress(),
        }
    }
    if reason.is_empty() {
        return unsupported_suppress();
    }
    ShellCommand::ReviewDecision(ReviewDecisionCommand::Suppress {
        reference: (*reference).to_string(),
        reason: reason.join(" "),
        author,
        days,
    })
}

fn collect_suppress_reason(args: &[&str], start: usize, reason: &mut Vec<String>) -> usize {
    let mut index = start;
    while index < args.len() && !matches!(args[index], "--author" | "--days") {
        reason.push(args[index].to_string());
        index += 1;
    }
    index.saturating_sub(start).saturating_add(1)
}

fn unsupported_suppress() -> ShellCommand {
    ShellCommand::ReviewDecision(ReviewDecisionCommand::Unsupported(
        "suppress <id> --reason <text> [--author operator] [--days 90]".to_string(),
    ))
}

/// `verify <F-alias|fingerprint>` — the keypath the finding detail and help
/// advertise. Desugars into the ordinary `run` machinery (`verify` resolves
/// to `verify:finding`; its `fingerprint` option accepts a stable alias), so
/// the advertised one-step path is a deterministic verb instead of falling
/// into the Workbench phase-intent planner.
fn parse_verify_command(args: &[&str]) -> ShellCommand {
    let [reference] = args else {
        return ShellCommand::Unknown("verify <finding>".to_string());
    };
    finding_reference_tool_run("verify:finding", reference)
}

fn finding_reference_tool_run(tool: &str, reference: &str) -> ShellCommand {
    ShellCommand::RunTool {
        tool: Some(tool.to_string()),
        input: Some(serde_json::json!({ "fingerprint": reference }).to_string()),
    }
}

/// A bare finding reference (`F-0001`, `fi_…`, or a long fingerprint) — used
/// to disambiguate `patch <finding>` from an unknown patch subverb.
fn looks_like_finding_reference(value: &str) -> bool {
    let alias = value.len() >= 3
        && (value.starts_with("F-") || value.starts_with("f-"))
        && value[2..].chars().all(|ch| ch.is_ascii_digit());
    alias || value.starts_with("fi_") || value.chars().count() >= 12
}

fn parse_patch_command(args: &[&str]) -> ShellCommand {
    match args.first().copied() {
        Some("apply") => ShellCommand::Patch(PatchCommand::Apply),
        Some("reject" | "discard") => ShellCommand::Patch(PatchCommand::Reject),
        Some("regen" | "regenerate") => ShellCommand::Patch(PatchCommand::Regen {
            style: parse_patch_regen_style(args.get(1..).unwrap_or_default()),
        }),
        // `patch F-0001` — the finding detail's advertised remediation
        // keypath; routes through `run` like `verify <finding>`.
        Some(reference) if args.len() == 1 && looks_like_finding_reference(reference) => {
            finding_reference_tool_run("patch:finding", reference)
        }
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
        Some("filter") => parse_findings_filter(args.get(1..).unwrap_or_default()),
        Some("since") => args
            .get(1)
            .map(|reference| ShellCommand::Since((*reference).to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown("findings since <ref>".to_string())),
        Some("export") => parse_workspace_findings_export_args(args.get(1..).unwrap_or_default()),
        Some(other) => ShellCommand::Unknown(format!("findings {other}")),
        None => ShellCommand::Findings,
    }
}

fn parse_findings_filter(args: &[&str]) -> ShellCommand {
    let expression = args.join(" ");
    match expression.trim() {
        "" => ShellCommand::Unknown("findings filter".to_string()),
        "clear" => ShellCommand::Findings,
        _ => ShellCommand::FindingsFilter(expression),
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
