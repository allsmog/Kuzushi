//! One cooperative Stop path for the deck, global cancel and exit.
use super::*;

impl ShellApp {
    pub(crate) fn request_owned_dispatcher_stop(&mut self) -> bool {
        match self.runtime_state.request_dispatcher_stop() {
            Ok(pid) => {
                self.record_owned_dispatcher_stop(pid);
                true
            }
            Err(error) => {
                let message = format!("Stop unavailable: {error:#}");
                self.router.campaign_mut().notice = Some(message.clone());
                self.set_error_notice("study-stop", message);
                false
            }
        }
    }

    fn record_owned_dispatcher_stop(&mut self, pid: u32) {
        let message = format!("Stop requested for dispatcher {pid}; saving partial work");
        let deck = self.router.campaign_mut();
        deck.dispatcher_stop_requested = true;
        deck.notice = Some(message.clone());
        if let Some((target, campaign)) = self.runtime_state.owned_dispatcher_origin() {
            self.log(
                "study",
                format!(
                    "Stop requested for {campaign} at {} (dispatcher {pid}); saving partial work",
                    target.display()
                ),
            );
        }
        self.set_warn_notice("study-stop", message);
    }

    pub(super) fn clear_owned_dispatcher_stop_notice(&mut self) {
        if self
            .advisory()
            .notice
            .as_ref()
            .is_some_and(|notice| notice.source == "study-stop")
        {
            self.clear_notice();
        }
    }
}
