use super::BatchScanConfig;
use crate::app::ShellApp;
use crate::ui_view_models::study_config::{
    study_config_area, study_detail_lines, study_reader_layout,
};
use crossterm::event::KeyCode;

impl ShellApp {
    pub(super) fn handle_study_read_key(&mut self, code: KeyCode) -> bool {
        if self.cycle_study_source_view(code) {
            return true;
        }
        if code == KeyCode::Char('z') {
            let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
                return false;
            };
            config.detail_reader_scroll = match config.detail_reader_scroll {
                Some(_) => None,
                None => Some(config.detail_scroll),
            };
            return true;
        }
        self.scroll_study_reader_line(code)
    }

    pub(super) fn close_study_reader(&mut self) -> bool {
        self.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .is_some_and(|config| config.detail_reader_scroll.take().is_some())
    }

    fn scroll_study_reader_line(&mut self, code: KeyCode) -> bool {
        let maximum = self.study_reader_maximum();
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return false;
        };
        let Some(scroll) = config.detail_reader_scroll.as_mut() else {
            return false;
        };
        let Some(offset) = reader_offset(code, (*scroll).min(maximum), maximum) else {
            return false;
        };
        *scroll = offset;
        true
    }

    fn study_reader_maximum(&self) -> usize {
        let viewport = self.viewport();
        let area = study_config_area(viewport.columns, viewport.rows);
        let detail = study_reader_layout(area, true).detail;
        crate::ui_view_models::study_config::study_projection(self).map_or(0, |config| {
            study_detail_lines(&config, detail.width as usize)
                .len()
                .saturating_sub(detail.height as usize)
        })
    }
}

pub(super) fn set_detail_scroll(config: &mut BatchScanConfig, offset: usize) {
    match config.detail_reader_scroll.as_mut() {
        Some(scroll) => *scroll = offset,
        None => config.detail_scroll = offset,
    }
}

fn reader_offset(code: KeyCode, current: usize, maximum: usize) -> Option<usize> {
    match code {
        KeyCode::Up => Some(current.saturating_sub(1)),
        KeyCode::Down => Some(current.saturating_add(1).min(maximum)),
        KeyCode::Home => Some(0),
        KeyCode::End => Some(maximum),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
