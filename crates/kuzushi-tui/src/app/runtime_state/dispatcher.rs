//! Ownership of the detached child, independent of the selected target or row.
use super::RuntimeState;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Child;

pub(crate) struct DispatcherExit {
    pub origin: Option<(PathBuf, String)>,
    pub status: std::process::ExitStatus,
}

impl RuntimeState {
    pub(crate) fn owned_dispatcher_origin(&self) -> Option<(&std::path::Path, &str)> {
        self.dispatcher_child.as_ref()?;
        self.dispatcher_origin
            .as_ref()
            .map(|(target, id)| (target.as_path(), id.as_str()))
    }

    pub(crate) fn hold_dispatcher(&mut self, child: Child, target: PathBuf, campaign: String) {
        self.dispatcher_child = Some(child);
        self.dispatcher_origin = Some((target, campaign));
    }

    pub(crate) fn request_dispatcher_stop(&mut self) -> Result<u32> {
        let child = self
            .dispatcher_child
            .as_mut()
            .context("no dispatcher was launched from this deck")?;
        anyhow::ensure!(
            child.try_wait()?.is_none(),
            "dispatcher already exited; refresh its result"
        );
        let (target, campaign) = self
            .dispatcher_origin
            .as_ref()
            .context("dispatcher origin is unavailable; refusing Stop")?;
        let pid = child.id();
        kuzushi_core::capabilities::campaign::request_campaign_dispatcher_stop(
            target, campaign, pid,
        )?;
        Ok(pid)
    }

    #[cfg(test)]
    pub(crate) fn set_dispatcher_child(&mut self, child: Option<Child>) {
        self.dispatcher_child = child;
        self.dispatcher_origin = None;
    }

    #[cfg(test)]
    pub(crate) fn take_dispatcher_child(&mut self) -> Option<Child> {
        self.dispatcher_origin = None;
        self.dispatcher_child.take()
    }

    pub(crate) fn reap_exited_dispatcher(&mut self) -> Option<DispatcherExit> {
        let status = self.dispatcher_child.as_mut()?.try_wait().ok()??;
        self.dispatcher_child = None;
        Some(DispatcherExit {
            status,
            origin: self.dispatcher_origin.take(),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn stop_uses_the_owned_origin_and_keeps_the_child_until_it_exits() {
        let root = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let pid = child.id();
        let directory = kuzushi_core::capabilities::campaign::campaign_dir(root.path(), "original");
        std::fs::create_dir_all(&directory).unwrap();
        let owner = serde_json::json!({ "schemaVersion": 1, "sessionId": uuid::Uuid::new_v4().to_string(), "campaignId": "original", "pid": pid });
        std::fs::write(directory.join("dispatcher-control.json"), owner.to_string()).unwrap();
        let mut state = RuntimeState::default();
        state.hold_dispatcher(child, root.path().into(), "original".into());
        assert_eq!(state.request_dispatcher_stop().unwrap(), pid);
        assert_eq!(state.request_dispatcher_stop().unwrap(), pid);
        assert!(state.reap_exited_dispatcher().is_none());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(directory.join("dispatcher-stop.json")).unwrap()
            )
            .unwrap(),
            owner
        );
        child = state.take_dispatcher_child().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        state.set_dispatcher_child(Some(child));
        assert!(state.request_dispatcher_stop().is_err());
        assert!(state.reap_exited_dispatcher().is_some());
    }

    #[test]
    fn a_pid_without_the_owned_child_is_never_used_for_stop() {
        let mut state = RuntimeState::default();
        assert!(state.request_dispatcher_stop().is_err());
    }

    #[test]
    fn reaping_retains_exit_status_and_original_target_then_clears_ownership() {
        let root = tempfile::tempdir().unwrap();
        for (command, success) in [("true", true), ("false", false)] {
            let mut child = std::process::Command::new(command).spawn().unwrap();
            child.wait().unwrap();
            let mut state = RuntimeState::default();
            state.hold_dispatcher(child, root.path().into(), "original".into());
            let exit = state.reap_exited_dispatcher().unwrap();
            assert_eq!(exit.status.success(), success);
            assert_eq!(exit.origin, Some((root.path().into(), "original".into())));
            assert!(state.reap_exited_dispatcher().is_none());
            assert!(state.request_dispatcher_stop().is_err());
        }
    }
}
