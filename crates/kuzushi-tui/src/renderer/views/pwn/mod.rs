use super::*;
pub(in crate::renderer) use super::*;
use std::path::PathBuf;

pub(crate) fn pwn_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let width = area.width;
    let view = &app.pwn_view;

    lines.push(blank());
    lines.push(divider("PWN TARGET / STATE", width));
    lines.push(detail("target", &path_or_dash(view.target.as_ref())));
    lines.push(detail("binary", &path_or_dash(view.binary.as_ref())));
    lines.push(detail("state", &path_or_dash(view.state_path.as_ref())));
    lines.push(detail(
        "profile",
        &profile_status(view.profile_snapshot.as_ref()),
    ));
    lines.push(detail(
        "model rounds",
        &auto_round_status(view.auto_solve_snapshot.as_ref()),
    ));

    lines.push(blank());
    lines.push(divider("EXPLOIT FACTS", width));
    append_primitives(&mut lines, view.state_snapshot.as_ref(), width);

    lines.push(blank());
    lines.push(divider("LLM ROUNDS", width));
    append_rounds(&mut lines, view.auto_solve_snapshot.as_ref(), width);

    lines.push(blank());
    lines.push(divider("REV.NG / REVERSE OBSERVATIONS", width));
    append_reverse_observations(&mut lines, &view.reverse_snapshots, width);

    lines.push(blank());
    lines.push(divider("NEXT ACTIONS", width));
    lines.push(muted(
        "pwn profile · pwn reverse [function] · pwn auto · pwn state · pwn candidates <target>",
    ));
    lines.push(keybind_hint_line(&[
        ("j/k", "scroll"),
        ("pwn auto", "observe/replan"),
        ("pwn candidates", "review gate"),
    ]));
    lines
}

fn append_primitives(
    lines: &mut Vec<Line<'static>>,
    state: Option<&serde_json::Value>,
    width: u16,
) {
    let primitives = state
        .and_then(|state| state.get("primitives"))
        .and_then(serde_json::Value::as_array);
    let Some(primitives) = primitives.filter(|items| !items.is_empty()) else {
        lines.push(muted("No primitives recorded yet."));
        return;
    };
    for primitive in primitives.iter().take(8) {
        let kind = primitive
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let confidence = primitive
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "-".to_string());
        let remote = primitive
            .get("remoteSafe")
            .or_else(|| primitive.get("remote_safe"))
            .and_then(serde_json::Value::as_bool)
            .map(|value| if value { "remote-safe" } else { "local-only" })
            .unwrap_or("unknown");
        let evidence = primitive
            .get("evidence")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        lines.push(Line::from(vec![
            Span::styled(format!("   {kind:<20}"), theme::label()),
            Span::styled(format!(" conf {confidence:<4} "), theme::muted()),
            Span::styled(format!("{remote:<12} "), theme::accent()),
            Span::raw(fit(evidence, width.saturating_sub(44) as usize)),
        ]));
    }
}

fn append_rounds(lines: &mut Vec<Line<'static>>, auto: Option<&serde_json::Value>, width: u16) {
    let iterations = auto
        .and_then(|auto| auto.pointer("/llmPlanner/iterations"))
        .and_then(serde_json::Value::as_array);
    let Some(iterations) = iterations.filter(|items| !items.is_empty()) else {
        lines.push(muted("No auto-solve rounds recorded yet."));
        return;
    };
    for iteration in iterations.iter().take(6) {
        let round = iteration
            .get("round")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let actions = iteration
            .pointer("/decision/actions")
            .and_then(serde_json::Value::as_array)
            .map(|actions| {
                actions
                    .iter()
                    .filter_map(action_label)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "-".to_string());
        lines.push(Line::from(vec![
            Span::styled(format!("   round {round:<2} "), theme::label()),
            Span::raw(fit(&actions, width.saturating_sub(13) as usize)),
        ]));
    }
}

fn append_reverse_observations(
    lines: &mut Vec<Line<'static>>,
    snapshots: &[serde_json::Value],
    width: u16,
) {
    if snapshots.is_empty() {
        lines.push(muted("No reverse observations cached yet."));
        return;
    }
    for snapshot in snapshots.iter().rev().take(5) {
        let function = snapshot
            .get("function")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("whole binary");
        let ok = snapshot
            .pointer("/revng/ok")
            .and_then(serde_json::Value::as_bool)
            .map(|value| if value { "revng ok" } else { "revng error" })
            .unwrap_or("revng n/a");
        let dangerous = snapshot
            .get("dangerousIo")
            .and_then(serde_json::Value::as_array)
            .map(|items| items.len())
            .unwrap_or(0);
        lines.push(Line::from(vec![
            Span::styled(format!("   {ok:<12} "), theme::accent()),
            Span::styled(fit(function, 28), theme::label()),
            Span::styled(format!(" · dangerous IO {dangerous:<2} "), theme::muted()),
        ]));
        if let Some(excerpt) = snapshot
            .pointer("/revng/output")
            .and_then(serde_json::Value::as_str)
        {
            lines.push(Line::from(vec![
                Span::raw("      "),
                Span::styled(
                    fit(excerpt.trim(), width.saturating_sub(6) as usize),
                    theme::muted(),
                ),
            ]));
        }
    }
}

fn action_label(action: &serde_json::Value) -> Option<String> {
    let operation = action.get("operation")?.as_str()?;
    let function = action.get("function").and_then(serde_json::Value::as_str);
    Some(match function {
        Some(function) => format!("{operation}:{function}"),
        None => operation.to_string(),
    })
}

fn profile_status(profile: Option<&serde_json::Value>) -> String {
    profile
        .map(|profile| {
            let arch = profile
                .get("arch")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown arch");
            let needed = profile
                .get("needed")
                .and_then(serde_json::Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0);
            format!("{arch} · {needed} needed librar(y/ies)")
        })
        .unwrap_or_else(|| "not run".to_string())
}

fn auto_round_status(auto: Option<&serde_json::Value>) -> String {
    auto.and_then(|auto| auto.pointer("/llmPlanner/iterations"))
        .and_then(serde_json::Value::as_array)
        .map(|items| format!("{} iteration(s)", items.len()))
        .unwrap_or_else(|| "not run".to_string())
}

fn path_or_dash(path: Option<&PathBuf>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "-".to_string())
}
