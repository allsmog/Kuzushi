use super::*;

pub(super) const CAMPAIGN_LIVE_REFRESH: std::time::Duration = std::time::Duration::from_secs(3);

impl ShellApp {
    /// While the deck is open and its dispatcher is still working, re-read the
    /// recorded queue every few seconds so job states move from `planned` to
    /// `running` to `completed` live instead of only when the dispatcher exits.
    ///
    /// The re-read goes through the ordinary deck refresh, so an interactive
    /// shell schedules it on the bounded view-reader pool rather than reading
    /// disk on the tick path. An in-flight read is never restarted.
    pub(crate) fn poll_live_campaign_progress(&mut self, now: std::time::Instant) -> bool {
        if !self.live_campaign_refresh_due(now) || self.target().is_none() {
            return false;
        }
        self.router.campaign_mut().live_refreshed_at = Some(now);
        self.refresh_campaign_deck();
        true
    }

    fn live_campaign_refresh_due(&self, now: std::time::Instant) -> bool {
        let deck = self.router.campaign();
        let watching = self.shell_view() == ShellView::Campaign && deck.dispatcher_pid.is_some();
        let due = deck
            .live_refreshed_at
            .is_none_or(|last| now.duration_since(last) >= CAMPAIGN_LIVE_REFRESH);
        watching && due && !self.campaign_history_loading()
    }
}
