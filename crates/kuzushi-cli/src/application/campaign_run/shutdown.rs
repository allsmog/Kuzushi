//! Stop forwarding for one exclusive dispatcher session.
use kuzushi_core::capabilities::campaign::CampaignDispatcherControl;
use std::time::Duration;
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum StopCause {
    #[default]
    Running,
    Operator,
    Interrupted,
}

impl StopCause {
    pub(super) fn requested(self) -> bool {
        self != Self::Running
    }

    pub(super) fn outcome(self) -> super::policy::JobOutcome {
        match self {
            Self::Operator => super::policy::JobOutcome::Canceled,
            _ => super::policy::JobOutcome::Interrupted,
        }
    }
}

pub(super) fn spawn(control: CampaignDispatcherControl) -> watch::Receiver<StopCause> {
    let (tx, rx) = watch::channel(StopCause::Running);
    tokio::spawn(watch_stop(control, tx));
    rx
}

async fn watch_stop(control: CampaignDispatcherControl, tx: watch::Sender<StopCause>) {
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    loop {
        let stop = tokio::select! {
            _ = tx.closed() => return,
            signal = tokio::signal::ctrl_c() => Some(signal.map_or(StopCause::Interrupted, |_| StopCause::Operator)),
            _ = poll.tick() => requested_cause(&control),
        };
        if let Some(cause) = stop {
            eprintln!("campaign: Stop requested; stopping children and saving partial work");
            let _ = tx.send(cause);
            return;
        }
    }
}

pub(super) fn requested_cause(control: &CampaignDispatcherControl) -> Option<StopCause> {
    match control.stop_requested() {
        Ok(requested) => requested.then_some(StopCause::Operator),
        Err(error) => {
            eprintln!("campaign: invalid Stop control; stopping safely: {error:#}");
            Some(StopCause::Interrupted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::capabilities::campaign::{
        acquire_dispatcher_lease, request_campaign_dispatcher_stop,
    };

    #[tokio::test]
    async fn session_stop_wakes_the_dispatcher_and_closed_receiver_finishes_the_watch() {
        let root = tempfile::tempdir().unwrap();
        let lease = acquire_dispatcher_lease(root.path(), "stop-test").unwrap();
        let mut rx = spawn(lease.control());
        request_campaign_dispatcher_stop(root.path(), "stop-test", std::process::id()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*rx.borrow(), StopCause::Operator);
        let (tx, rx) = watch::channel(StopCause::Running);
        drop(rx);
        tokio::time::timeout(Duration::from_secs(2), watch_stop(lease.control(), tx))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn prior_session_requests_do_not_stop_a_new_session() {
        let root = tempfile::tempdir().unwrap();
        let lease = acquire_dispatcher_lease(root.path(), "stop-test").unwrap();
        request_campaign_dispatcher_stop(root.path(), "stop-test", std::process::id()).unwrap();
        drop(lease);
        let next = acquire_dispatcher_lease(root.path(), "stop-test").unwrap();
        assert_eq!(requested_cause(&next.control()), None);
        std::fs::write(
            kuzushi_core::capabilities::campaign::campaign_dir(root.path(), "stop-test")
                .join("dispatcher-stop.json"),
            "{}",
        )
        .unwrap();
        assert_eq!(
            requested_cause(&next.control()),
            Some(StopCause::Interrupted)
        );
    }
}
