use crate::ui_view_models::PhaseSurfaceId;

/// Transient full-body projection of one Workbench surface.
///
/// The focused surface remains the source of truth. While zoom is active, Tab
/// changes focus and the zoom follows it so navigation never changes the
/// underlying cockpit geometry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WorkbenchZoom {
    #[default]
    Off,
    Surface(PhaseSurfaceId),
}

impl WorkbenchZoom {
    pub(crate) fn surface(self) -> Option<PhaseSurfaceId> {
        match self {
            Self::Off => None,
            Self::Surface(surface) => Some(surface),
        }
    }

    pub(crate) fn toggle(&mut self, focus: PhaseSurfaceId) {
        *self = if self.surface().is_some() {
            Self::Off
        } else {
            Self::Surface(focus)
        };
    }

    pub(crate) fn follow_focus(&mut self, focus: PhaseSurfaceId) {
        if self.surface().is_some() {
            *self = Self::Surface(focus);
        }
    }

    pub(crate) fn show(&mut self, focus: PhaseSurfaceId) {
        *self = Self::Surface(focus);
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
        zoom.toggle(PhaseSurfaceId::ReviewQueue);
        zoom.follow_focus(PhaseSurfaceId::ReviewDetail);
        assert_eq!(zoom.surface(), Some(PhaseSurfaceId::ReviewDetail));

        zoom.toggle(PhaseSurfaceId::ReviewDetail);
        zoom.follow_focus(PhaseSurfaceId::MapReadiness);
        assert_eq!(zoom.surface(), None);
    }

    #[test]
    fn show_and_clear_are_idempotent_projections() {
        let mut zoom = WorkbenchZoom::default();
        zoom.show(PhaseSurfaceId::FixAttackTree);
        zoom.show(PhaseSurfaceId::FixAttackTree);
        assert_eq!(zoom.surface(), Some(PhaseSurfaceId::FixAttackTree));
        zoom.clear();
        zoom.clear();
        assert_eq!(zoom.surface(), None);
    }
}
