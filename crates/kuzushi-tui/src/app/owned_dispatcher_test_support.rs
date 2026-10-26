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
        held
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
