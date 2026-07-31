//! Focus-gated attention notification policy: pure decisions, no IO. The
//! terminal adapter (`runtime/refresh_terminal_redraw_state.rs`) asks this
//! module whether a newly appeared attention item may leave the frame as a
//! bell + OSC 9 desktop notification.

use super::AttentionItem;
use std::collections::BTreeSet;

/// Whether the hosting terminal window has keyboard focus. `Unknown` until
/// the first focus event arrives (or forever, on terminals that never report
/// focus).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum FocusState {
    #[default]
    Unknown,
    Focused,
    Blurred,
}

/// Why a notification was suppressed — a structured answer to "why didn't I
/// get pinged", never a silent bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotifySkip {
    /// `ui.notify false`.
    Disabled,
    /// Focus is unreported; fail closed rather than ping an operator who may
    /// be looking straight at the screen.
    FocusUnknown,
    /// The operator is watching — the footer and title already show the item.
    Focused,
}

/// Out-of-frame signals fire only when the operator is provably elsewhere.
pub(crate) fn should_notify_blurred(enabled: bool, focus: FocusState) -> Result<(), NotifySkip> {
    if !enabled {
        return Err(NotifySkip::Disabled);
    }
    match focus {
        FocusState::Blurred => Ok(()),
        FocusState::Unknown => Err(NotifySkip::FocusUnknown),
        FocusState::Focused => Err(NotifySkip::Focused),
    }
}

/// One message for a batch of newly appeared attention items.
pub(crate) fn notification_message(new_items: &[&AttentionItem]) -> Option<String> {
    let first = new_items.first()?;
    if new_items.len() == 1 {
        return Some(first.kind.title().to_string());
    }
    Some(format!("{} items need attention", new_items.len()))
}

/// Return attention items that appeared since the previous broker snapshot.
/// Replacing the active-id set prevents redraw/refocus replays while allowing a
/// later, distinct gate to notify after the earlier item disappeared.
pub(crate) fn newly_appeared_attention<'a>(
    active_ids: &mut BTreeSet<String>,
    items: &'a [AttentionItem],
) -> Vec<&'a AttentionItem> {
    let new_items = items
        .iter()
        .filter(|item| !active_ids.contains(&item.id))
        .collect();
    *active_ids = items.iter().map(|item| item.id.clone()).collect();
    new_items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{AttentionKind, AttentionRoute};

    #[test]
    fn notify_fails_closed_while_focus_is_unknown() {
        assert_eq!(
            should_notify_blurred(true, FocusState::Unknown),
            Err(NotifySkip::FocusUnknown)
        );
    }

    #[test]
    fn notify_fires_only_when_blurred() {
        assert_eq!(should_notify_blurred(true, FocusState::Blurred), Ok(()));
        assert_eq!(
            should_notify_blurred(true, FocusState::Focused),
            Err(NotifySkip::Focused)
        );
    }

    #[test]
    fn disabled_wins_over_focus_state() {
        assert_eq!(
            should_notify_blurred(false, FocusState::Blurred),
            Err(NotifySkip::Disabled)
        );
    }

    #[test]
    fn single_item_message_names_the_kind() {
        let item = AttentionItem {
            id: "approval".to_string(),
            kind: AttentionKind::Approval,
            route: AttentionRoute::Confirmation,
        };

        assert_eq!(
            notification_message(&[&item]).as_deref(),
            Some("APPROVAL REQUIRED")
        );
    }

    #[test]
    fn batch_message_counts_items() {
        let approval = AttentionItem {
            id: "approval".to_string(),
            kind: AttentionKind::Approval,
            route: AttentionRoute::Confirmation,
        };
        let question = AttentionItem {
            id: "question".to_string(),
            kind: AttentionKind::OperatorQuestion,
            route: AttentionRoute::Activity,
        };

        assert_eq!(
            notification_message(&[&approval, &question]).as_deref(),
            Some("2 items need attention")
        );
    }

    #[test]
    fn empty_batch_produces_no_message() {
        assert_eq!(notification_message(&[]), None);
    }

    #[test]
    fn resolved_attention_id_can_notify_when_it_reappears() {
        let item = AttentionItem {
            id: "approval".to_string(),
            kind: AttentionKind::Approval,
            route: AttentionRoute::Confirmation,
        };
        let mut active_ids = BTreeSet::new();

        assert_eq!(
            newly_appeared_attention(&mut active_ids, std::slice::from_ref(&item)).len(),
            1
        );
        assert!(newly_appeared_attention(&mut active_ids, std::slice::from_ref(&item)).is_empty());
        assert!(newly_appeared_attention(&mut active_ids, &[]).is_empty());
        assert_eq!(
            newly_appeared_attention(&mut active_ids, std::slice::from_ref(&item)).len(),
            1
        );
    }
}
