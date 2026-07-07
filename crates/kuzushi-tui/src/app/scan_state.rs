use super::ScanPanelState;

#[derive(Debug, Clone, Default)]
pub(crate) struct ScanState {
    current: Option<ScanPanelState>,
}

impl ScanState {
    pub(crate) fn current(&self) -> Option<&ScanPanelState> {
        self.current.as_ref()
    }

    pub(crate) fn current_mut(&mut self) -> Option<&mut ScanPanelState> {
        self.current.as_mut()
    }

    pub(crate) fn set(&mut self, current: Option<ScanPanelState>) {
        self.current = current;
    }
}
