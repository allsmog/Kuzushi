use super::*;

/// How often an open replay of an unfinished run re-reads its artifacts.
const LIVE_REPLAY_REFRESH: Duration = Duration::from_secs(2);

impl ShellApp {
    /// A replay opened on a run that is still executing (a detached campaign
    /// job, for instance) re-reads its lifecycle every few seconds, keeping the
    /// previous read on screen until the new one lands, so model calls and
    /// agent actions appear as they happen. When the run finishes, every cached
    /// artifact is read once more so the replay can switch to its result. A
    /// reader parked at the bottom keeps following new rows; one who scrolled
    /// up is left in place.
    pub(crate) fn poll_live_replay(&mut self, now: Instant) -> bool {
        let Some((target, finished)) = self.open_replay_run() else {
            return false;
        };
        let mut changed = self.follow_live_replay_tail();
        if finished {
            if self.router.replay_mut().live_refreshed_at.take().is_some() {
                self.refresh_replay_run(&target);
                changed = true;
            }
            return changed;
        }
        let due = self
            .router
            .replay()
            .live_refreshed_at
            .is_none_or(|last| now.duration_since(last) >= LIVE_REPLAY_REFRESH);
        if due {
            self.router.replay_mut().live_refreshed_at = Some(now);
            let run_id = self.router.replay().run_id_owned();
            self.workbench_cache()
                .borrow_mut()
                .mark_run_projection_stale(&target, &run_id);
            changed = true;
        }
        changed
    }

    /// The target of the open replay and whether its run published `done.json`.
    fn open_replay_run(&self) -> Option<(PathBuf, bool)> {
        if self.shell_view() != ShellView::Replay {
            return None;
        }
        let target = self.target_owned()?;
        let run_id = self.router.replay().run_id();
        if run_id.is_empty() {
            return None;
        }
        let finished = kuzushi_core::run_dir(&target, run_id)
            .join("done.json")
            .exists();
        Some((target, finished))
    }

    fn refresh_replay_run(&mut self, target: &std::path::Path) {
        let run_id = self.router.replay().run_id_owned();
        self.workbench_cache()
            .borrow_mut()
            .invalidate_one_run_cache(target, &run_id);
    }

    fn replay_projection_ready(&self) -> bool {
        let Some(target) = self.target() else {
            return false;
        };
        self.workbench_cache()
            .borrow()
            .run_projection_is_ready(target, self.router.replay().run_id())
    }

    fn follow_live_replay_tail(&mut self) -> bool {
        let replay = self.router.replay();
        if replay.live_tail_offset.is_none() && replay.live_refreshed_at.is_none() {
            // An ordinary replay of a finished run never follows.
            return false;
        }
        if !self.replay_projection_ready() {
            // A re-read in flight renders a short loading document; measuring
            // it would forget that the reader was parked at the bottom.
            return false;
        }
        let Some(bottom) = crate::renderer::run_artifact_max_scroll(self) else {
            return false;
        };
        let offset = self.router.default_scroll().offset();
        let previous = self.router.replay_mut().live_tail_offset.replace(bottom);
        let following = previous == Some(offset) && bottom > offset;
        if following {
            self.router.default_scroll_mut().set(bottom);
        }
        following
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn replay_of_run(done: bool) -> (tempfile::TempDir, ShellApp) {
        let root = tempfile::tempdir().unwrap();
        let run_dir = kuzushi_core::run_dir(root.path(), "run-live");
        std::fs::create_dir_all(&run_dir).unwrap();
        if done {
            std::fs::write(run_dir.join("done.json"), "{}").unwrap();
        }
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(root.path().to_path_buf()));
        app.open_replay_for_test("run-live");
        (root, app)
    }

    #[test]
    fn an_unfinished_run_refreshes_on_its_schedule() {
        let (_root, mut app) = replay_of_run(false);
        let start = Instant::now();

        assert!(app.poll_live_replay(start));
        assert!(!app.poll_live_replay(start + Duration::from_millis(500)));
        assert!(app.poll_live_replay(start + LIVE_REPLAY_REFRESH));
    }

    #[test]
    fn a_finished_run_is_not_refreshed() {
        let (_root, mut app) = replay_of_run(true);

        assert!(!app.poll_live_replay(Instant::now()));
    }

    #[test]
    fn a_run_that_finishes_while_followed_is_read_once_more() {
        let (root, mut app) = replay_of_run(false);
        let start = Instant::now();
        assert!(app.poll_live_replay(start));
        let done = kuzushi_core::run_dir(root.path(), "run-live").join("done.json");
        std::fs::write(done, "{}").unwrap();

        assert!(app.poll_live_replay(start + Duration::from_millis(100)));
        assert!(!app.poll_live_replay(start + LIVE_REPLAY_REFRESH));
    }

    fn park_reader_at(app: &mut ShellApp, offset: u16) {
        app.router.replay_mut().live_tail_offset = Some(offset);
        app.router.default_scroll_mut().set(offset);
    }

    #[test]
    fn the_completion_reread_keeps_a_parked_reader_following() {
        let (root, mut app) = replay_of_run(false);
        let start = Instant::now();
        assert!(app.poll_live_replay(start));
        park_reader_at(&mut app, 40);
        let done = kuzushi_core::run_dir(root.path(), "run-live").join("done.json");
        std::fs::write(done, "{}").unwrap();

        assert!(app.poll_live_replay(start + Duration::from_millis(100)));
        assert!(!app.poll_live_replay(start + Duration::from_millis(200)));

        assert_eq!(app.router.replay().live_tail_offset, Some(40));
    }

    #[test]
    fn a_ready_projection_updates_the_followed_tail() {
        let (root, mut app) = replay_of_run(false);
        assert!(app.poll_live_replay(Instant::now()));
        park_reader_at(&mut app, 40);
        app.workbench_cache().borrow_mut().seed_run_projection_for_test(
            root.path(),
            "run-live",
            Err("unreadable".into()),
        );

        app.follow_live_replay_tail();

        assert_ne!(app.router.replay().live_tail_offset, Some(40));
    }
}
