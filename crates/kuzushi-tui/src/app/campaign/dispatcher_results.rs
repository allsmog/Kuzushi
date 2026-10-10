use super::*;

impl ShellApp {
    pub(super) fn collect_dispatcher_exit(&mut self) -> bool {
        let Some(exit) = self.runtime_state.reap_exited_dispatcher() else {
            return false;
        };
        self.router.campaign_mut().dispatcher_pid = None;
        self.router.campaign_mut().dispatcher_stop_requested = false;
        if exit.status.success() {
            return true;
        }
        let Some((target, campaign)) = exit.origin else {
            self.log("campaign", format!("dispatcher exited: {}", exit.status));
            return true;
        };
        let message = dispatcher_failure_message(&target, &campaign, exit.status);
        self.log("campaign", &message);
        self.router.campaign_mut().dispatcher_failure = Some((target, campaign, message));
        true
    }

    pub(super) fn restore_dispatcher_failure_notice(&mut self) {
        let Some((target, campaign, message)) = self.router.campaign().dispatcher_failure.clone()
        else {
            return;
        };
        if self.router.campaign().notice.as_deref() == Some(message.as_str()) {
            self.router.campaign_mut().notice = None;
        }
        if self.dispatcher_failure_is_selected(&target, &campaign) {
            self.router.campaign_mut().notice = Some(message);
        }
    }

    fn dispatcher_failure_is_selected(&self, target: &Path, campaign: &str) -> bool {
        self.target() == Some(target)
            && self
                .router
                .campaign()
                .selected_campaign()
                .is_some_and(|selected| selected.campaign_id == campaign)
    }
}

#[cfg(test)]
mod tests;

fn dispatcher_failure_message(
    target: &Path,
    campaign: &str,
    status: std::process::ExitStatus,
) -> String {
    let cause = match kuzushi_core::capabilities::campaign::read_campaign_dispatcher_error(
        target, campaign,
    ) {
        Ok(Some(cause)) => cause,
        Ok(None) => "No failure explanation was recorded.".into(),
        Err(error) => format!("Failure explanation unavailable: {error}"),
    };
    format!("{cause}\nDispatcher stopped ({status}).\nReview the recorded failure and current source before launching again. Details: campaigns/{campaign}/logs/dispatcher.log")
}
