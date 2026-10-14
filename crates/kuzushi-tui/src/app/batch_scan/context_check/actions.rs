use super::*;
use crate::ui_view_models::study_context::context_actions;
use crossterm::event::KeyCode;

impl ShellApp {
    pub(in crate::app::batch_scan) fn open_context_actions(&mut self) {
        self.edit_context_picker(|config| {
            config.context_picker.as_mut().unwrap().actions_selected = Some(0)
        });
    }

    pub(in crate::app::batch_scan) fn handle_context_actions_key(
        &mut self,
        code: KeyCode,
    ) -> Option<InputUpdate> {
        let selected = self.study_context_picker()?.actions_selected?;
        let action = menu_action(code, selected, &context_actions(self));
        match action {
            MenuAction::Move(selected) => self.edit_context_picker(|config| {
                config.context_picker.as_mut().unwrap().actions_selected = Some(selected)
            }),
            MenuAction::Close => self.close_context_actions(),
            MenuAction::Run(code) => {
                self.close_context_actions();
                return Some(self.handle_study_context_key(code));
            }
        }
        Some(InputUpdate::handled())
    }

    fn close_context_actions(&mut self) {
        self.edit_context_picker(|config| {
            config.context_picker.as_mut().unwrap().actions_selected = None
        });
    }
}

enum MenuAction {
    Move(usize),
    Close,
    Run(KeyCode),
}

fn menu_action(code: KeyCode, selected: usize, actions: &[(KeyCode, &str)]) -> MenuAction {
    if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
        return MenuAction::Close;
    }
    if code == KeyCode::Enter {
        return MenuAction::Run(actions[selected.min(actions.len() - 1)].0);
    }
    let delta = match code {
        KeyCode::Up | KeyCode::Char('k') => -1,
        KeyCode::Down | KeyCode::Char('j') => 1,
        _ => 0,
    };
    MenuAction::Move((selected as i64 + delta).clamp(0, actions.len() as i64 - 1) as usize)
}
