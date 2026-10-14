use crate::app::{BatchScanConfigRow, ShellApp};
use crossterm::event::KeyCode;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum StudySourceView {
    #[default]
    Overview,
    Inputs,
    Settings,
    Options,
}

impl StudySourceView {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Inputs => "Inputs",
            Self::Settings => "Settings",
            Self::Options => "JSON",
        }
    }

    pub(crate) fn next(self, previous: bool) -> Self {
        const VIEWS: [StudySourceView; 4] = [
            StudySourceView::Overview,
            StudySourceView::Inputs,
            StudySourceView::Settings,
            StudySourceView::Options,
        ];
        let offset = if previous { VIEWS.len() - 1 } else { 1 };
        VIEWS[(self as usize + offset) % VIEWS.len()]
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct StudySourceState {
    pub(crate) selected: StudySourceView,
    form_scroll: [usize; 4],
    reader_scroll: [usize; 4],
}

impl StudySourceState {
    pub(super) fn switch(&mut self, previous: bool, form: &mut usize, reader: &mut Option<usize>) {
        let index = self.selected as usize;
        self.form_scroll[index] = *form;
        if let Some(scroll) = reader {
            self.reader_scroll[index] = *scroll;
        }
        self.selected = self.selected.next(previous);
        let next = self.selected as usize;
        *form = self.form_scroll[next];
        if reader.is_some() {
            *reader = Some(self.reader_scroll[next]);
        }
    }
}

impl ShellApp {
    pub(super) fn cycle_study_source_view(&mut self, code: KeyCode) -> bool {
        let Some(previous) = view_switch_direction(code) else {
            return false;
        };
        if self.study_notice_captures_escape() {
            return false;
        }
        let Some(config) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .filter(|config| config.selected_row() == BatchScanConfigRow::Context)
        else {
            return false;
        };
        config.source_view.switch(
            previous,
            &mut config.detail_scroll,
            &mut config.detail_reader_scroll,
        );
        true
    }
}

fn view_switch_direction(code: KeyCode) -> Option<bool> {
    match code {
        KeyCode::Tab => Some(false),
        KeyCode::BackTab => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
