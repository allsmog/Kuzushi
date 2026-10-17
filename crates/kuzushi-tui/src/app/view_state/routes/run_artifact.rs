#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ReadingPage {
    #[default]
    Result,
    Inputs,
    Receipt,
}

impl ReadingPage {
    fn next(self, reverse: bool, has_inputs: bool) -> Self {
        use ReadingPage::*;
        let pages: &[Self] = if has_inputs || self == Inputs {
            &[Result, Inputs, Receipt]
        } else {
            &[Result, Receipt]
        };
        let position = pages.iter().position(|page| *page == self).unwrap_or(0);
        let next = if reverse {
            position + pages.len() - 1
        } else {
            position + 1
        };
        pages[next % pages.len()]
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArtifactRouteState {
    run_id: String,
    pub(super) scroll_reset_pending: bool,
    page: ReadingPage,
    scrolls: [u16; 3],
}

impl RunArtifactRouteState {
    pub(crate) fn open(&mut self, run_id: impl Into<String>) {
        let run_id = run_id.into();
        if self.run_id != run_id {
            self.page = ReadingPage::Result;
            self.scrolls = [0; 3];
        }
        self.scroll_reset_pending |= self.run_id != run_id;
        self.run_id = run_id;
    }

    pub(crate) fn run_id(&self) -> &str {
        &self.run_id
    }

    pub(crate) fn run_id_owned(&self) -> String {
        self.run_id.clone()
    }

    pub(crate) fn full_receipt(&self) -> bool {
        self.page == ReadingPage::Receipt
    }

    pub(crate) fn inputs(&self) -> bool {
        self.page == ReadingPage::Inputs
    }

    pub(crate) fn cycle_page(&mut self, current: u16, reverse: bool, has_inputs: bool) -> u16 {
        self.scrolls[self.page as usize] = current;
        self.page = self.page.next(reverse, has_inputs);
        self.scrolls[self.page as usize]
    }

    #[cfg(test)]
    pub(crate) fn toggle_receipt(&mut self, current: u16) -> u16 {
        self.cycle_page(current, false, false)
    }
}
