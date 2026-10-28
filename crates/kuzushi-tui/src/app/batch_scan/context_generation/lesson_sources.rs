use super::*;

impl ShellApp {
    pub(crate) fn lesson_source_reader_is_open(&self) -> bool {
        self.shell_view() == crate::app::ShellView::Campaign
            && self
                .context_generation()
                .is_some_and(|g| g.lesson_sources.is_some())
    }

    pub(super) fn handle_lesson_source_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        let generation = self.context_generation().filter(|g| g.is_lesson())?;
        if generation.lesson_sources.is_some() {
            self.read_lesson_source_key(code);
            return Some(InputUpdate::handled());
        }
        match code {
            KeyCode::Char('f') => self.open_lesson_source_file_picker(),
            KeyCode::Char('v') => self.inspect_lesson_source_bundle(),
            _ => return None,
        }
        Some(InputUpdate::handled())
    }

    fn inspect_lesson_source_bundle(&mut self) {
        let result = self.lesson_source_bundle_lines();
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let generation = config.context_generation.as_mut().unwrap();
        match result {
            Ok(lines) => {
                generation.lesson_sources = Some((std::sync::Arc::new(lines), generation.scroll));
                generation.scroll = 0;
            }
            Err(error) => {
                config.notice = Some(format!(
                    "Historical source inspection: {error:#}. No model request started."
                ))
            }
        }
    }

    fn lesson_source_bundle_lines(&self) -> Result<Vec<String>> {
        let generation = self.context_generation().context("Open the lesson plan")?;
        let input = generation
            .receipt
            .as_ref()
            .map_or(&generation.context_input, |r| &r.input);
        let missing = if generation.receipt.is_some() {
            "This plan has no saved supporting-source bundle. Use n, then f, for a separate draft with selected files"
        } else {
            "Choose supporting files with f, then prepare this draft to inspect their historical bytes and omissions"
        };
        let reference = input["sourceEvidenceRef"].as_str().context(missing)?;
        let target = self.target().context("Select a lesson target")?;
        let document = kuzushi_core::workspace::read_lesson_source_evidence(target, reference)?;
        Ok(crate::ui_view_models::context_generation::lesson_source_lines(&document))
    }

    fn read_lesson_source_key(&mut self, code: KeyCode) {
        if code == KeyCode::Esc {
            let generation = self
                .router
                .campaign_mut()
                .batch_scan_config
                .as_mut()
                .unwrap()
                .context_generation
                .as_mut()
                .unwrap();
            let (_, offset) = generation.lesson_sources.take().unwrap();
            generation.scroll = offset;
        } else if matches!(
            code,
            KeyCode::Up
                | KeyCode::Down
                | KeyCode::PageUp
                | KeyCode::PageDown
                | KeyCode::Home
                | KeyCode::End
        ) {
            self.scroll_context_generation(code);
        }
    }
}
