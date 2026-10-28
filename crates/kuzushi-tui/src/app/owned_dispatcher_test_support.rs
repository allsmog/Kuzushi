use super::ShellApp;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

pub(crate) struct HeldDispatcher<'a> {
    app: &'a mut ShellApp,
    root: tempfile::TempDir,
}

impl<'a> HeldDispatcher<'a> {
    pub(crate) fn hold(app: &'a mut ShellApp) -> Self {
        let root = tempfile::tempdir().unwrap();
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let owner = serde_json::json!({"schemaVersion": 1,
            "sessionId": uuid::Uuid::new_v4().to_string(),
            "campaignId": "held-dispatcher", "pid": child.id()});
        app.runtime_state
            .hold_dispatcher(child, root.path().into(), "held-dispatcher".into());
        let held = Self { app, root };
        std::fs::create_dir_all(held.directory()).unwrap();
        std::fs::write(
            held.directory().join("dispatcher-control.json"),
            owner.to_string(),
        )
        .unwrap();
        held.app.runtime_state.refresh_owned_study_allowance();
        held
    }

    /// Holds a study whose recorded campaign queue carries `budget_usd`.
    pub(crate) fn hold_with_campaign_budget(
        app: &'a mut ShellApp,
        budget_usd: Option<f64>,
    ) -> Self {
        let mut held = Self::hold(app);
        held.record_campaign(serde_json::json!({
            "campaignId": "held-dispatcher", "jobs": {}, "budgetUsd": budget_usd
        }));
        held
    }

    fn record_campaign(&mut self, queue: serde_json::Value) {
        use kuzushi_core::capabilities::campaign::{campaign_plan_path, campaign_queue_path};
        let (root, id) = (self.root.path(), "held-dispatcher");
        let plan = serde_json::json!({ "campaignId": id, "jobs": [] });
        std::fs::write(campaign_plan_path(root, id), plan.to_string()).unwrap();
        std::fs::write(campaign_queue_path(root, id), queue.to_string()).unwrap();
        self.app.runtime_state.refresh_owned_study_allowance();
    }

    pub(crate) fn directory(&self) -> PathBuf {
        kuzushi_core::capabilities::campaign::campaign_dir(self.root.path(), "held-dispatcher")
    }
}

impl Deref for HeldDispatcher<'_> {
    type Target = ShellApp;

    fn deref(&self) -> &Self::Target {
        self.app
    }
}

impl DerefMut for HeldDispatcher<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.app
    }
}

impl Drop for HeldDispatcher<'_> {
    fn drop(&mut self) {
        if let Some(mut child) = self.app.runtime_state.take_dispatcher_child() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
