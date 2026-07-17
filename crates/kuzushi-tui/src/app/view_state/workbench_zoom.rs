use super::WorkbenchPane;

/// Transient full-body projection of one Workbench pane.
///
/// The focused pane remains the source of truth. While zoom is active, Tab
/// changes focus and the zoom follows it so navigation never changes the
/// underlying cockpit geometry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WorkbenchZoom {
    #[default]
    Off,
    Pane(WorkbenchPane),
}

impl WorkbenchZoom {
    pub(crate) fn pane(self) -> Option<WorkbenchPane> {
        match self {
            Self::Off => None,
            Self::Pane(pane) => Some(pane),
        }
    }

    pub(crate) fn toggle(&mut self, focus: WorkbenchPane) {
        *self = if self.pane().is_some() {
            Self::Off
        } else {
            Self::Pane(focus)
        };
    }

    pub(crate) fn follow_focus(&mut self, focus: WorkbenchPane) {
        if self.pane().is_some() {
            *self = Self::Pane(focus);
        }
    }

    pub(crate) fn show(&mut self, focus: WorkbenchPane) {
        *self = Self::Pane(focus);
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::Off;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_zoom_follows_focus_until_toggled_off() {
        let mut zoom = WorkbenchZoom::default();
        zoom.toggle(WorkbenchPane::Findings);
        zoom.follow_focus(WorkbenchPane::Details);
        assert_eq!(zoom.pane(), Some(WorkbenchPane::Details));

        zoom.toggle(WorkbenchPane::Details);
        zoom.follow_focus(WorkbenchPane::Source);
        assert_eq!(zoom.pane(), None);
    }
}
