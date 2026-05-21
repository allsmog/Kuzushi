use super::*;
pub(in crate::renderer) use super::*;
use crate::ui_view_models::{
    pwn_dashboard_model, PwnPrimitiveRow, PwnReverseObservationRow, PwnRoundRow,
};

pub(crate) fn pwn_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let width = area.width;
    let model = pwn_dashboard_model(app);

    lines.push(blank());
    lines.push(divider("PWN TARGET / STATE", width));
    lines.push(detail("target", &model.target));
    lines.push(detail("binary", &model.binary));
    lines.push(detail("state", &model.state));
    lines.push(detail("profile", &model.profile_status));
    lines.push(detail("model rounds", &model.auto_round_status));

    lines.push(blank());
    lines.push(divider("EXPLOIT FACTS", width));
    append_primitives(&mut lines, &model.primitives, width);

    lines.push(blank());
    lines.push(divider("LLM ROUNDS", width));
    append_rounds(&mut lines, &model.rounds, width);

    lines.push(blank());
    lines.push(divider("REV.NG / REVERSE OBSERVATIONS", width));
    append_reverse_observations(&mut lines, &model.reverse_observations, width);

    lines.push(blank());
    lines.push(divider("NEXT ACTIONS", width));
    lines.push(muted(
        "pwn profile · pwn reverse [function] · pwn auto · pwn state · pwn candidates <target>",
    ));
    lines.push(keybind_hint_line(&[
        ("j/k", "scroll"),
        ("pwn auto", "observe and replan"),
        ("pwn candidates", "review approval gate"),
    ]));
    lines
}

fn append_primitives(lines: &mut Vec<Line<'static>>, primitives: &[PwnPrimitiveRow], width: u16) {
    if primitives.is_empty() {
        lines.push(muted("       ∅  no exploit primitives recorded yet"));
        lines.push(muted(
            "       ▸ pwn profile           run a baseline target profile",
        ));
        lines.push(muted(
            "       ▸ pwn auto              let the agent observe and replan",
        ));
        lines.push(muted(
            "       ▸ pwn candidates        review the approval gate",
        ));
        let _ = width;
        return;
    }
    for primitive in primitives {
        lines.push(Line::from(vec![
            Span::styled(format!("   {:<20}", primitive.kind), theme::label()),
            Span::styled(
                format!(" conf {:<4} ", primitive.confidence),
                theme::muted(),
            ),
            Span::styled(format!("{:<12} ", primitive.remote), theme::accent()),
            Span::raw(fit(&primitive.evidence, width.saturating_sub(44) as usize)),
        ]));
    }
}

fn append_rounds(lines: &mut Vec<Line<'static>>, rounds: &[PwnRoundRow], width: u16) {
    if rounds.is_empty() {
        lines.push(muted("No auto-solve rounds recorded yet."));
        return;
    }
    for round in rounds {
        lines.push(Line::from(vec![
            Span::styled(format!("   round {:<2} ", round.round), theme::label()),
            Span::raw(fit(&round.actions, width.saturating_sub(13) as usize)),
        ]));
    }
}

fn append_reverse_observations(
    lines: &mut Vec<Line<'static>>,
    observations: &[PwnReverseObservationRow],
    width: u16,
) {
    if observations.is_empty() {
        lines.push(muted("No reverse observations cached yet."));
        return;
    }
    for observation in observations {
        lines.push(Line::from(vec![
            Span::styled(format!("   {:<12} ", observation.status), theme::accent()),
            Span::styled(fit(&observation.function, 28), theme::label()),
            Span::styled(
                format!(" · dangerous IO {:<2} ", observation.dangerous_io),
                theme::muted(),
            ),
        ]));
        if let Some(excerpt) = &observation.excerpt {
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
