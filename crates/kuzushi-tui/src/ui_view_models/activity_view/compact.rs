use super::*;

pub(crate) struct CompactActivityChrome {
    pub(crate) header: Vec<String>,
    pub(crate) footer: Vec<String>,
}

impl RunFocusModel<'_> {
    pub(crate) fn compact_chrome(&self, width: u16, height: u16) -> Option<CompactActivityChrome> {
        if height > 16 || self.operator_question().is_some() {
            return None;
        }
        if self.route.steer_editor.is_some() || activity_abort_pending(self.app) {
            return None;
        }
        let mut header = vec![fit(&self.header().compact_title, usize::from(width))];
        header.extend(wrap_text(
            &format!("run {}", self.session.run_id),
            usize::from(width),
        ));
        Some(CompactActivityChrome {
            header,
            footer: self.compact_controls(width),
        })
    }

    fn compact_controls(&self, width: u16) -> Vec<String> {
        let footer = self.footer(width);
        let terminal = run_focus_is_terminal(self.app);
        let navigation = footer
            .hints
            .iter()
            .filter(|hint| primary_control(hint.plain_hint_text, terminal))
            .map(|hint| self.control_hint(hint))
            .collect::<Vec<_>>()
            .join(" · ");
        let interrupt = super::super::keybindings::interrupt_binding(self.app);
        let mut rows = wrap_text(&navigation, usize::from(width));
        rows.extend(wrap_text(
            &format!(
                "{} {} · {}",
                interrupt.key,
                interrupt.label,
                self.control_map_hint()
            ),
            usize::from(width),
        ));
        rows
    }

    fn control_map_hint(&self) -> String {
        let keys = self
            .app
            .ui()
            .keymap_binding_labels("global", "command_palette", &["Ctrl+G"]);
        if keys.is_empty() {
            return "keys command: all controls".to_string();
        }
        format!("{} → keys", keys.join("/"))
    }

    fn control_hint(&self, hint: &super::super::activity_footer::ActivityFooterHint) -> String {
        if self.notice_owns_leave(hint) {
            return "Esc dismiss".to_string();
        }
        let mut label = hint.plain_hint_text;
        if label == "scroll"
            && self.route.effective_pane_focus(self.session) == crate::PaneFocus::Left
        {
            label = "select";
        }
        format!("{} {label}", hint.plain_key_text)
    }

    fn notice_owns_leave(&self, hint: &super::super::activity_footer::ActivityFooterHint) -> bool {
        hint.plain_hint_text == "leave"
            && hint.plain_key_text == "Esc"
            && self.app.notice_captures_escape()
    }
}

fn primary_control(label: &str, terminal: bool) -> bool {
    match label {
        "scroll" | "pane" => true,
        "leave" => terminal,
        "background" => !terminal,
        _ => false,
    }
}
