use super::{AdvisoryState, ConfiguredKeyResult, PendingKeyChord, RuntimeKeymap, ShellView};
use crossterm::event::KeyEvent;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// A logical text position retained while a gallery row reflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GalleryTextAnchor {
    pub(crate) row: usize,
    pub(crate) characters: usize,
    pub(crate) identity: u64,
    pub(crate) tail: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GalleryReadingPosition {
    pub(crate) embedded: bool,
    pub(crate) page: crate::scene3d::VizPage,
    pub(crate) offset: u16,
    pub(crate) anchor: GalleryTextAnchor,
}

#[derive(Debug, Clone)]
pub(crate) struct UiPrefs {
    advisory: AdvisoryState,
    auto_open_activity: bool,
    auto_open_viz: bool,
    /// Persisted `ui.rail` policy: false = the operator hid the context rail.
    rail_enabled: bool,
    /// Ephemeral this-session override: an explicit `rail` show survives on
    /// terminals narrower than the automatic breakpoint.
    rail_force_open: bool,
    /// Persisted `ui.notify` policy for out-of-frame attention signals.
    notify_enabled: bool,
    /// Live terminal focus, from crossterm focus events; `Unknown` until the
    /// terminal reports (notifications fail closed on `Unknown`).
    terminal_focus: crate::app::FocusState,
    last_operator_interaction: Option<Instant>,
    spinner_phase: u8,
    last_spinner_advance: Option<Instant>,
    last_liveness_redraw: Option<Instant>,
    force_full_redraw: bool,
    should_quit: bool,
    viewport: TerminalViewport,
    gallery_reading: Option<GalleryReadingPosition>,
    runtime_keymap: RuntimeKeymap,
    pending_key_chord: Option<PendingKeyChord>,
    phase_result_cursor: Option<PhaseResultCursor>,
    keymap_home: Option<PathBuf>,
    keymap_config_fingerprint: Option<ConfigFingerprint>,
    last_keymap_check: Option<Instant>,
    typing_hint_shown: bool,
    last_external_sync: Option<Instant>,
    seen_config_diagnostics: BTreeSet<kuzushi_core::ConfigDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhaseResultCursor {
    attempt_id: String,
    index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigFingerprint {
    modified: Option<std::time::SystemTime>,
    len: u64,
}

impl UiPrefs {
    pub(crate) fn new(
        auto_open_activity: bool,
        auto_open_viz: bool,
        runtime_keymap: RuntimeKeymap,
    ) -> Self {
        let keymap_home = kuzushi_core::ConfigPaths::from_target(None)
            .ok()
            .map(|paths| paths.home_dir);
        let keymap_config_fingerprint = keymap_home
            .as_ref()
            .map(kuzushi_core::workspace_config_path)
            .and_then(|path| config_fingerprint(&path));
        Self {
            advisory: AdvisoryState::default(),
            auto_open_activity,
            auto_open_viz,
            rail_enabled: true,
            rail_force_open: false,
            notify_enabled: true,
            terminal_focus: crate::app::FocusState::default(),
            last_operator_interaction: None,
            spinner_phase: 0,
            last_spinner_advance: None,
            last_liveness_redraw: None,
            force_full_redraw: false,
            should_quit: false,
            viewport: TerminalViewport::default(),
            gallery_reading: None,
            runtime_keymap,
            pending_key_chord: None,
            phase_result_cursor: None,
            keymap_home,
            keymap_config_fingerprint,
            last_keymap_check: None,
            typing_hint_shown: false,
            last_external_sync: None,
            seen_config_diagnostics: BTreeSet::new(),
        }
    }

    /// One-shot gate for the first-keystroke typing hint: true exactly once
    /// per session, the first time it is consulted.
    pub(crate) fn take_typing_hint(&mut self) -> bool {
        !std::mem::replace(&mut self.typing_hint_shown, true)
    }

    pub(crate) fn apply_keymap_overrides(
        &self,
        view: ShellView,
        bindings: Vec<crate::app::state_transitions::ViewKeybinding>,
    ) -> Vec<crate::app::state_transitions::ViewKeybinding> {
        self.runtime_keymap.apply_view_overrides(view, bindings)
    }

    pub(crate) fn handle_configured_shell_key(
        &mut self,
        view: ShellView,
        key: KeyEvent,
        now: Instant,
        inactive_action: crate::app::state_transitions::ViewHotkeyAction,
    ) -> ConfiguredKeyResult {
        self.runtime_keymap.handle_shell_key(
            view,
            key,
            &mut self.pending_key_chord,
            now,
            inactive_action,
        )
    }

    pub(crate) fn handle_configured_context_key(
        &mut self,
        context: &str,
        key: KeyEvent,
        now: Instant,
    ) -> ConfiguredKeyResult {
        self.runtime_keymap
            .handle_context_key(context, key, &mut self.pending_key_chord, now)
    }

    pub(crate) fn keymap_error(&self) -> Option<&str> {
        self.runtime_keymap.error()
    }

    pub(crate) fn keymap_overrides_action(&self, context: &str, action: &str) -> bool {
        self.runtime_keymap.overrides_action(context, action)
    }

    pub(crate) fn keymap_binding_labels(
        &self,
        context: &str,
        action: &str,
        defaults: &[&str],
    ) -> Vec<String> {
        self.runtime_keymap
            .binding_labels(context, action, defaults)
    }

    pub(crate) fn phase_result_cursor_index(&self, attempt_id: &str, count: usize) -> usize {
        self.phase_result_cursor
            .as_ref()
            .filter(|cursor| cursor.attempt_id == attempt_id)
            .map_or(0, |cursor| cursor.index.min(count.saturating_sub(1)))
    }

    pub(crate) fn move_phase_result_cursor(
        &mut self,
        attempt_id: &str,
        count: usize,
        delta: isize,
    ) {
        if count == 0 {
            self.phase_result_cursor = None;
            return;
        }
        let current = self.phase_result_cursor_index(attempt_id, count);
        let index = (current as isize + delta).rem_euclid(count as isize) as usize;
        self.phase_result_cursor = Some(PhaseResultCursor {
            attempt_id: attempt_id.to_string(),
            index,
        });
    }

    pub(crate) fn clear_phase_result_cursor(&mut self) {
        self.phase_result_cursor = None;
    }

    pub(crate) fn replace_runtime_keymap(&mut self, keymap: RuntimeKeymap) -> Result<(), String> {
        if let Some(error) = keymap.error() {
            return Err(error.to_string());
        }
        self.runtime_keymap = keymap;
        self.pending_key_chord = None;
        Ok(())
    }

    pub(crate) fn poll_runtime_keymap(
        &mut self,
        now: Instant,
    ) -> Option<Result<ReloadedKeymap, String>> {
        if self
            .last_keymap_check
            .is_some_and(|previous| now.duration_since(previous) < Duration::from_secs(1))
        {
            return None;
        }
        self.last_keymap_check = Some(now);
        let home = self.keymap_home.clone()?;
        let path = kuzushi_core::workspace_config_path(&home);
        let fingerprint = config_fingerprint(&path);
        if fingerprint == self.keymap_config_fingerprint {
            return None;
        }
        self.keymap_config_fingerprint = fingerprint;
        let loaded =
            kuzushi_core::config::load_config_with_diagnostics(kuzushi_core::ConfigPaths {
                home_dir: home,
                target_dir: None,
            })
            .map_err(|error| error.to_string());
        let loaded = match loaded {
            Ok(loaded) => loaded,
            Err(error) => return Some(Err(error)),
        };
        let diagnostics = loaded.diagnostics;
        let bindings = loaded.config.operator.keybindings;
        let keymap = RuntimeKeymap::from_config(&bindings);
        if let Err(error) = self.replace_runtime_keymap(keymap) {
            return Some(Err(error));
        }
        Some(Ok(ReloadedKeymap {
            bindings,
            diagnostics,
        }))
    }

    pub(crate) fn take_new_config_diagnostics(
        &mut self,
        diagnostics: &[kuzushi_core::ConfigDiagnostic],
    ) -> Vec<kuzushi_core::ConfigDiagnostic> {
        diagnostics
            .iter()
            .filter(|diagnostic| self.seen_config_diagnostics.insert((*diagnostic).clone()))
            .cloned()
            .collect()
    }

    pub(crate) fn advisory(&self) -> &AdvisoryState {
        &self.advisory
    }

    pub(crate) fn advisory_mut(&mut self) -> &mut AdvisoryState {
        &mut self.advisory
    }

    pub(crate) fn auto_open_activity(&self) -> bool {
        self.auto_open_activity
    }

    pub(crate) fn set_auto_open_activity(&mut self, enabled: bool) {
        self.auto_open_activity = enabled;
    }

    pub(crate) fn auto_open_viz(&self) -> bool {
        self.auto_open_viz
    }

    pub(crate) fn set_auto_open_viz(&mut self, enabled: bool) {
        self.auto_open_viz = enabled;
    }

    pub(crate) fn rail_enabled(&self) -> bool {
        self.rail_enabled
    }

    pub(crate) fn set_rail_enabled(&mut self, enabled: bool) {
        self.rail_enabled = enabled;
    }

    pub(crate) fn rail_force_open(&self) -> bool {
        self.rail_force_open
    }

    pub(crate) fn set_rail_force_open(&mut self, force: bool) {
        self.rail_force_open = force;
    }

    pub(crate) fn notify_enabled(&self) -> bool {
        self.notify_enabled
    }

    pub(crate) fn set_notify_enabled(&mut self, enabled: bool) {
        self.notify_enabled = enabled;
    }

    pub(crate) fn terminal_focus(&self) -> crate::app::FocusState {
        self.terminal_focus
    }

    pub(crate) fn set_terminal_focus(&mut self, focus: crate::app::FocusState) {
        self.terminal_focus = focus;
    }

    pub(crate) fn record_operator_interaction(&mut self, now: Instant) {
        self.last_operator_interaction = Some(now);
    }

    pub(crate) fn operator_interaction_stamp(&self) -> Option<Instant> {
        self.last_operator_interaction
    }

    /// External writers (other sessions, detached campaigns) changing
    /// workspace state are real activity even though no local worker runs —
    /// the liveness badge must not claim "idle" while they churn.
    pub(crate) fn record_external_sync(&mut self, now: Instant) {
        self.last_external_sync = Some(now);
    }

    pub(crate) fn recent_external_sync(&self, grace: Duration) -> bool {
        self.last_external_sync
            .is_some_and(|at| at.elapsed() <= grace)
    }

    pub(crate) fn recent_operator_interaction(&self, grace: Duration) -> bool {
        self.last_operator_interaction
            .is_some_and(|at| at.elapsed() <= grace)
    }

    pub(crate) fn spinner_phase(&self) -> u8 {
        self.spinner_phase
    }

    #[cfg(test)]
    pub(crate) fn set_spinner_phase_for_test(&mut self, phase: u8) {
        self.spinner_phase = phase;
    }

    pub(crate) fn spinner_due(&self, now: Instant, frame: Duration) -> bool {
        self.last_spinner_advance
            .map(|prev| now.duration_since(prev) >= frame)
            .unwrap_or(true)
    }

    pub(crate) fn advance_spinner(&mut self, now: Instant) {
        self.spinner_phase = self.spinner_phase.wrapping_add(1);
        self.last_spinner_advance = Some(now);
    }

    pub(crate) fn reset_spinner(&mut self) -> bool {
        self.last_spinner_advance = None;
        if self.spinner_phase == 0 {
            return false;
        }
        self.spinner_phase = 0;
        true
    }

    pub(crate) fn liveness_redraw_due(&mut self, now: Instant, frame: Duration) -> bool {
        let due = self
            .last_liveness_redraw
            .map(|previous| now.duration_since(previous) >= frame)
            .unwrap_or(true);
        if due {
            self.last_liveness_redraw = Some(now);
        }
        due
    }

    pub(crate) fn clear_liveness_redraw(&mut self) {
        self.last_liveness_redraw = None;
    }

    #[cfg(test)]
    pub(crate) fn set_last_spinner_advance_for_test(&mut self, instant: Instant) {
        self.last_spinner_advance = Some(instant);
    }

    pub(crate) fn request_full_redraw(&mut self) {
        self.force_full_redraw = true;
    }

    #[cfg(test)]
    pub(crate) fn force_full_redraw(&self) -> bool {
        self.force_full_redraw
    }

    pub(crate) fn take_force_full_redraw(&mut self) -> bool {
        let requested = self.force_full_redraw;
        self.force_full_redraw = false;
        requested
    }

    pub(crate) fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub(crate) fn request_quit(&mut self) {
        self.should_quit = true;
    }

    pub(crate) fn viewport(&self) -> TerminalViewport {
        self.viewport
    }

    pub(crate) fn set_viewport(&mut self, viewport: TerminalViewport) {
        self.viewport = viewport;
    }

    pub(crate) fn gallery_reading(&self) -> Option<GalleryReadingPosition> {
        self.gallery_reading
    }

    pub(crate) fn set_gallery_reading(&mut self, position: Option<GalleryReadingPosition>) {
        self.gallery_reading = position;
    }
}

pub(crate) struct ReloadedKeymap {
    pub(crate) bindings: Vec<kuzushi_core::config::KeybindingOverrideConfig>,
    pub(crate) diagnostics: Vec<kuzushi_core::ConfigDiagnostic>,
}

fn config_fingerprint(path: &std::path::Path) -> Option<ConfigFingerprint> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(ConfigFingerprint {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_redraw_clock_advances_once_per_second() {
        let mut prefs = UiPrefs::new(true, true, RuntimeKeymap::default());
        let start = Instant::now();

        assert!(prefs.liveness_redraw_due(start, Duration::from_secs(1)));
        assert!(
            !prefs.liveness_redraw_due(start + Duration::from_millis(999), Duration::from_secs(1))
        );
        assert!(prefs.liveness_redraw_due(start + Duration::from_secs(1), Duration::from_secs(1)));
    }

    #[test]
    fn external_sync_recency_decays_after_the_grace_window() {
        let mut prefs = UiPrefs::new(true, true, RuntimeKeymap::default());
        assert!(!prefs.recent_external_sync(Duration::from_secs(3)));

        prefs.record_external_sync(Instant::now());
        assert!(prefs.recent_external_sync(Duration::from_secs(3)));
        assert!(!prefs.recent_external_sync(Duration::ZERO));
    }

    #[test]
    fn phase_result_cursor_wraps_and_resets_for_a_new_attempt() {
        let mut prefs = UiPrefs::new(true, true, RuntimeKeymap::default());

        prefs.move_phase_result_cursor("attempt-a", 3, -1);
        assert_eq!(prefs.phase_result_cursor_index("attempt-a", 3), 2);
        assert_eq!(prefs.phase_result_cursor_index("attempt-b", 3), 0);

        prefs.clear_phase_result_cursor();
        assert_eq!(prefs.phase_result_cursor_index("attempt-a", 3), 0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalViewport {
    pub(crate) columns: u16,
    pub(crate) rows: u16,
}

impl TerminalViewport {
    pub(crate) fn new(columns: u16, rows: u16) -> Self {
        Self {
            columns: columns.max(1),
            rows: rows.max(1),
        }
    }
}

impl Default for TerminalViewport {
    fn default() -> Self {
        Self {
            columns: 160,
            rows: 40,
        }
    }
}
