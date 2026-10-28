use super::{FooterKeybinding, ViewHotkeyAction};

type AliasGroup = (ViewHotkeyAction, String);

pub(super) fn compact_aliases(
    bindings: Vec<FooterKeybinding>,
    candidates: &[(String, ViewHotkeyAction)],
) -> Vec<FooterKeybinding> {
    let mut rows = Vec::new();
    for binding in bindings {
        let group = alias_group(&binding, candidates);
        append_alias(&mut rows, group, binding);
    }
    rows.into_iter().map(|(_, binding)| binding).collect()
}

fn alias_group(
    binding: &FooterKeybinding,
    candidates: &[(String, ViewHotkeyAction)],
) -> Option<AliasGroup> {
    let action = candidates.iter().find(|(key, _)| key == &binding.key)?.1;
    mergeable_action(action).map(|action| (action, binding.label.clone()))
}

fn mergeable_action(action: ViewHotkeyAction) -> Option<ViewHotkeyAction> {
    use ViewHotkeyAction::*;
    match action {
        CampaignBackToList => Some(CampaignBackToList),
        CampaignCursorPrevious | CampaignCursorNext => Some(CampaignCursorPrevious),
        _ => None,
    }
}

fn append_alias(
    rows: &mut Vec<(Option<AliasGroup>, FooterKeybinding)>,
    group: Option<AliasGroup>,
    binding: FooterKeybinding,
) {
    if let Some(key) = group.as_ref() {
        if let Some((_, existing)) = rows
            .iter_mut()
            .find(|(prior, _)| prior.as_ref() == Some(key))
        {
            existing.key.push('/');
            existing.key.push_str(&binding.key);
            return;
        }
    }
    rows.push((group, binding));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::keybindings::bind;

    #[test]
    fn equivalent_actions_share_a_hint_without_losing_the_configured_keys() {
        use ViewHotkeyAction::*;
        let candidates = vec![
            ("ctrl+h".into(), CampaignBackToList),
            ("q".into(), CampaignBackToList),
            ("j/k".into(), CampaignCursorPrevious),
            ("↑/↓".into(), CampaignCursorNext),
        ];
        let bindings = vec![
            bind("ctrl+h", "Scan"),
            bind("q", "Scan"),
            bind("j/k", "jobs"),
            bind("↑/↓", "jobs"),
        ];
        assert_eq!(
            compact_aliases(bindings, &candidates),
            vec![bind("ctrl+h/q", "Scan"), bind("j/k/↑/↓", "jobs")]
        );
    }

    #[test]
    fn different_actions_labels_and_unknown_bindings_remain_distinct() {
        use ViewHotkeyAction::*;
        let candidates = vec![
            ("Esc".into(), CampaignBackToList),
            ("q".into(), CampaignBackToList),
            ("r".into(), CampaignRefresh),
        ];
        let bindings = vec![
            bind("Esc", "Scan"),
            bind("q", "jobs"),
            bind("r", "Scan"),
            bind("ctrl+p", "palette"),
            bind("ctrl+c", "exit"),
        ];
        assert_eq!(compact_aliases(bindings.clone(), &candidates), bindings);
    }
}
