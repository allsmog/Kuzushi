use super::*;

pub(super) fn action_rows(state: &ScopeReviewState, selected: usize) -> (Vec<String>, usize) {
    let matches = state.matching_actions();
    let cursor = matches
        .iter()
        .position(|index| *index == selected)
        .unwrap_or(0);
    let rows: Vec<_> = matches
        .into_iter()
        .map(|index| SCOPE_ACTIONS[index].into())
        .collect();
    if rows.is_empty() {
        return (vec!["No matching actions".into()], 0);
    }
    (rows, cursor)
}

pub(super) fn action_controls(state: &ScopeReviewState) -> [&'static str; 2] {
    if state.menu_search.is_some() {
        return [
            "Type filter · ↑↓ choose · PgUp/Dn",
            "Enter select · Esc clear search",
        ];
    }
    [
        "↑↓ choose · Enter select",
        "/ search · PgUp/Dn read · Esc back",
    ]
}

pub(super) fn choice_controls(state: &ScopeReviewState) -> Option<[&'static str; 2]> {
    if state.menu.is_some() {
        return Some(action_controls(state));
    }
    state
        .merge_target
        .map(|_| ["↑↓ choose · Enter select", "Esc back · no scans start"])
}

pub(super) fn search_detail(state: &ScopeReviewState) -> Option<Vec<String>> {
    state.menu?;
    state.menu_search.as_ref()?;
    if !state.matching_actions().is_empty() {
        return None;
    }
    Some(vec![
        "No action selected. Enter does nothing. Edit the search or Esc to show all actions."
            .into(),
    ])
}

pub(crate) fn scope_search_label(state: &ScopeReviewState) -> Option<String> {
    state.menu?;
    Some(format!("Search: {}", state.menu_search.as_ref()?.text()))
}
