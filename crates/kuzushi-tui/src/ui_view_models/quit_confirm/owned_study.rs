use super::*;

pub(super) fn warning(app: &ShellApp) -> Option<&'static str> {
    app.runtime_state.has_owned_dispatcher().then_some(
        "Exit requests cancellation. The owned study may continue until its dispatcher stops.",
    )
}

pub(super) fn sections(
    app: &ShellApp,
    mut sections: Vec<QuitConfirmSection>,
) -> Vec<QuitConfirmSection> {
    if let Some(section) = study_section(app) {
        sections.insert(1.min(sections.len()), section);
    }
    sections
}

fn study_section(app: &ShellApp) -> Option<QuitConfirmSection> {
    if !app.runtime_state.has_owned_dispatcher() {
        return None;
    }
    let mut rows = match app.runtime_state.owned_dispatcher_origin() {
        Some((target, campaign)) => vec![
            format!("Study: {campaign}"),
            format!("Target: {}", target.display()),
        ],
        None => vec!["Owned study identity unavailable; Stop cannot be authenticated.".into()],
    };
    rows.push("Cost: unknown (owned study). Check its recorded allowance.".into());
    rows.push(if app.runtime_state.owned_dispatcher_stop_requested() {
        "Stop requested; child exit is not yet recorded.".into()
    } else {
        "Exit requests cooperative Stop for this owned study.".into()
    });
    Some(QuitConfirmSection::new("OWNED STUDY", rows))
}
