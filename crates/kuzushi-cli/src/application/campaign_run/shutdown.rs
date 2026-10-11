//! Stop forwarding for one exclusive dispatcher session.
use kuzushi_core::capabilities::campaign::CampaignDispatcherControl;
use std::time::Duration;
use tokio::sync::watch;

pub(super) fn spawn(control: CampaignDispatcherControl) -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    tokio::spawn(watch_stop(control, tx));
    rx
}

async fn watch_stop(control: CampaignDispatcherControl, tx: watch::Sender<bool>) {
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    loop {
        let stop = tokio::select! {
            _ = tx.closed() => return,
            _ = tokio::signal::ctrl_c() => true,
            _ = poll.tick() => requested_or_invalid(&control),
        };
        if stop {
            eprintln!("campaign: Stop requested; stopping children and saving partial work");
            let _ = tx.send(true);
            return;
        }
    }
}

pub(super) fn requested_or_invalid(control: &CampaignDispatcherControl) -> bool {
    match control.stop_requested() {
        Ok(requested) => requested,
        Err(error) => {
            eprintln!("campaign: invalid Stop control; stopping safely: {error:#}");
            true
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
        assert!(*rx.borrow());
        let (tx, rx) = watch::channel(false);
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
        assert!(!requested_or_invalid(&next.control()));
        std::fs::write(
            kuzushi_core::capabilities::campaign::campaign_dir(root.path(), "stop-test")
                .join("dispatcher-stop.json"),
            "{}",
        )
        .unwrap();
        assert!(requested_or_invalid(&next.control()));
    }
}
