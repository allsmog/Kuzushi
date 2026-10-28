use super::*;

const CAMPAIGN_LIVE_REFRESH: std::time::Duration = std::time::Duration::from_secs(3);

impl ShellApp {
    /// While the deck is open and its dispatcher is still working, re-read the
    /// recorded queue every few seconds so job states move from `planned` to
    /// `running` to `completed` live instead of only when the dispatcher exits.
    pub(crate) fn poll_live_campaign_progress(&mut self, now: std::time::Instant) -> bool {
        let deck = self.router.campaign();
        let watching = self.shell_view() == ShellView::Campaign && deck.dispatcher_pid.is_some();
        let due = deck
            .live_refreshed_at
            .is_none_or(|last| now.duration_since(last) >= CAMPAIGN_LIVE_REFRESH);
        if !(watching && due) {
            return false;
        }
        self.router.campaign_mut().live_refreshed_at = Some(now);
        let Some(target) = self.target_path_buf().cloned() else {
            return false;
        };
        let (campaigns, unreadable) = load_campaign_snapshots(&target);
        self.replace_campaign_snapshots(campaigns, unreadable);
        self.restore_dispatcher_failure_notice();
        true
    }
}
