use super::{KeySequence, KeyStroke, StrokeCode};
use crate::app::state_transitions::ViewHotkeyAction;
use crate::app::{PhaseResultCommand, ShellView, WorkbenchPage};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl KeyStroke {
    pub(super) fn from_event(event: KeyEvent) -> Self {
        let modifiers = if event.code == KeyCode::BackTab {
            event.modifiers - KeyModifiers::SHIFT
        } else {
            event.modifiers
        };
        let code = match event.code {
            KeyCode::Char(ch) => StrokeCode::Char(ch),
            KeyCode::Enter => StrokeCode::Enter,
            KeyCode::Tab => StrokeCode::Tab,
            KeyCode::BackTab => StrokeCode::BackTab,
            KeyCode::Esc => StrokeCode::Esc,
            KeyCode::PageUp => StrokeCode::PageUp,
            KeyCode::PageDown => StrokeCode::PageDown,
            KeyCode::Up => StrokeCode::Up,
            KeyCode::Down => StrokeCode::Down,
            KeyCode::Left => StrokeCode::Left,
            KeyCode::Right => StrokeCode::Right,
            KeyCode::Home => StrokeCode::Home,
            KeyCode::End => StrokeCode::End,
            KeyCode::Delete => StrokeCode::Delete,
            KeyCode::Backspace => StrokeCode::Backspace,
            _ => StrokeCode::Char('\0'),
        };
        Self { code, modifiers }
    }
}

pub(super) fn parse_sequence(value: &str) -> Result<KeySequence, String> {
    let parts = value.split_whitespace().collect::<Vec<_>>();
    if !(1..=2).contains(&parts.len()) {
        return Err(format!(
            "keybinding {value:?} must contain one or two strokes"
        ));
    }
    let strokes = parts
        .into_iter()
        .map(parse_stroke)
        .collect::<Result<_, _>>()?;
    Ok(KeySequence {
        display: value.trim().to_string(),
        strokes,
    })
}

pub(super) fn parse_stroke(value: &str) -> Result<KeyStroke, String> {
    let (mut modifiers, raw) = parse_parts(value)?;
    let code = named_code(raw, &mut modifiers)?;
    Ok(KeyStroke { code, modifiers })
}

fn parse_parts(value: &str) -> Result<(KeyModifiers, &str), String> {
    let mut modifiers = KeyModifiers::NONE;
    let mut key = None;
    for part in value.split('+') {
        match part.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => modifiers.insert(KeyModifiers::CONTROL),
            "alt" => modifiers.insert(KeyModifiers::ALT),
            "shift" => modifiers.insert(KeyModifiers::SHIFT),
            _ if key.is_none() => key = Some(part),
            _ => return Err(format!("invalid key stroke {value:?}")),
        }
    }
    key.map(|key| (modifiers, key))
        .ok_or_else(|| format!("key stroke {value:?} has no key"))
}

fn named_code(raw: &str, modifiers: &mut KeyModifiers) -> Result<StrokeCode, String> {
    let code = match raw.to_ascii_lowercase().as_str() {
        "enter" => StrokeCode::Enter,
        "tab" => StrokeCode::Tab,
        "backtab" | "shift-tab" => {
            modifiers.remove(KeyModifiers::SHIFT);
            StrokeCode::BackTab
        }
        "esc" | "escape" => StrokeCode::Esc,
        "pageup" | "pgup" => StrokeCode::PageUp,
        "pagedown" | "pgdn" => StrokeCode::PageDown,
        "up" => StrokeCode::Up,
        "down" => StrokeCode::Down,
        "left" => StrokeCode::Left,
        "right" => StrokeCode::Right,
        "home" => StrokeCode::Home,
        "end" => StrokeCode::End,
        "delete" | "del" => StrokeCode::Delete,
        "backspace" => StrokeCode::Backspace,
        "space" => StrokeCode::Char(' '),
        _ if raw.chars().count() == 1 => StrokeCode::Char(raw.chars().next().unwrap()),
        _ => return Err(format!("unknown key name {raw:?}")),
    };
    Ok(code)
}

pub(super) fn canonical_context(value: &str) -> Result<&'static str, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "global" => Ok("global"),
        "composer" => Ok("composer"),
        "workbench" => Ok("workbench"),
        "phase_result" | "phase-result" => Ok("phase_result"),
        "question" => Ok("question"),
        "run_focus" | "runfocus" => Ok("run_focus"),
        "picker" => Ok("picker"),
        "report" => Ok("report"),
        "modal" => Ok("modal"),
        other => Err(format!("unknown keybinding context {other:?}")),
    }
}

pub(super) fn view_context(view: ShellView) -> Option<&'static str> {
    match view {
        ShellView::Workbench => Some("workbench"),
        ShellView::Activity => Some("run_focus"),
        ShellView::Report => Some("report"),
        ShellView::Catalog
        | ShellView::PlanningPicker
        | ShellView::TargetPicker
        | ShellView::FilePicker => Some("picker"),
        _ => Some("modal"),
    }
}

pub(super) fn action_from_id(context: &str, id: &str) -> Result<ViewHotkeyAction, String> {
    let id = id.trim().to_ascii_lowercase();
    let action = match context {
        "workbench" => workbench_action(&id),
        "phase_result" => phase_result_action(&id),
        "run_focus" => run_focus_action(&id),
        "question" => question_action(&id),
        "global" => global_action(&id),
        "composer" => composer_action(&id),
        "report" | "modal" | "picker" => utility_action(&id),
        _ => None,
    };
    action.ok_or_else(|| format!("unknown keybinding action {id:?} for context {context}"))
}

fn phase_result_action(id: &str) -> Option<ViewHotkeyAction> {
    let command = match id {
        "select" => PhaseResultCommand::Select,
        "continue" => PhaseResultCommand::Continue,
        "open" => PhaseResultCommand::Open,
        "refine" => PhaseResultCommand::Refine,
        "run_again" => PhaseResultCommand::RunAgain,
        "regenerate" => PhaseResultCommand::Regenerate,
        "discard" => PhaseResultCommand::Discard,
        _ => return None,
    };
    Some(ViewHotkeyAction::PhaseResult(command))
}

fn workbench_action(id: &str) -> Option<ViewHotkeyAction> {
    Some(match id {
        "cycle_phase" => ViewHotkeyAction::WorkbenchPageNext,
        "previous_phase" => ViewHotkeyAction::WorkbenchPagePrev,
        "cycle_pane" => ViewHotkeyAction::WorkbenchCyclePane,
        "previous_pane" => ViewHotkeyAction::WorkbenchCyclePanePrev,
        "open" => ViewHotkeyAction::WorkbenchOpen,
        "compare_observations" => ViewHotkeyAction::WorkbenchCompareObservations,
        "review_current_source" => ViewHotkeyAction::WorkbenchReviewCurrentSource,
        "map" => ViewHotkeyAction::WorkbenchPage(WorkbenchPage::Map),
        "scan" => ViewHotkeyAction::WorkbenchPage(WorkbenchPage::Scan),
        "review" => ViewHotkeyAction::WorkbenchPage(WorkbenchPage::Review),
        "report" => ViewHotkeyAction::WorkbenchReport,
        "prove" => ViewHotkeyAction::WorkbenchPage(WorkbenchPage::Prove),
        "fix" => ViewHotkeyAction::WorkbenchPage(WorkbenchPage::Fix),
        "next" => ViewHotkeyAction::WorkbenchScrollNext,
        "previous" => ViewHotkeyAction::WorkbenchScrollPrev,
        "first" => ViewHotkeyAction::WorkbenchScrollFirst,
        "last" => ViewHotkeyAction::WorkbenchScrollLast,
        "zoom" => ViewHotkeyAction::WorkbenchTogglePaneZoom,
        "visualize" => ViewHotkeyAction::WorkbenchOpenFocusedVisualization,
        _ => return None,
    })
}

fn run_focus_action(id: &str) -> Option<ViewHotkeyAction> {
    Some(match id {
        "cycle_pane" => ViewHotkeyAction::ActivityTabPaneFocus,
        "background" => ViewHotkeyAction::ActivityBackground,
        "steer" => ViewHotkeyAction::ActivitySteer,
        "pause_feed" => ViewHotkeyAction::ActivityTogglePause,
        "verbose" => ViewHotkeyAction::ActivityToggleVerbose,
        "focus" => ViewHotkeyAction::ActivityFocusSelected,
        _ => return None,
    })
}

fn question_action(id: &str) -> Option<ViewHotkeyAction> {
    Some(match id {
        "submit" => ViewHotkeyAction::QuestionSubmit,
        "cancel" => ViewHotkeyAction::QuestionCancel,
        "background" => ViewHotkeyAction::QuestionBackground,
        "next_option" => ViewHotkeyAction::QuestionNextOption,
        "previous_option" => ViewHotkeyAction::QuestionPreviousOption,
        "next_question" => ViewHotkeyAction::QuestionNext,
        "previous_question" => ViewHotkeyAction::QuestionPrevious,
        "other" => ViewHotkeyAction::QuestionOther,
        _ => return None,
    })
}

fn global_action(id: &str) -> Option<ViewHotkeyAction> {
    match id {
        "command_palette" => Some(ViewHotkeyAction::OpenCommandPalette),
        "help" => Some(ViewHotkeyAction::OpenHelp),
        _ => None,
    }
}
fn composer_action(id: &str) -> Option<ViewHotkeyAction> {
    match id {
        "navigate_mode" => Some(ViewHotkeyAction::EnterNavigateMode),
        "prompt_mode" => Some(ViewHotkeyAction::EnterPromptMode),
        "complete" => Some(ViewHotkeyAction::CompleteComposer),
        _ => None,
    }
}
fn utility_action(id: &str) -> Option<ViewHotkeyAction> {
    match id {
        "back" => Some(ViewHotkeyAction::Back),
        "scroll_up" => Some(ViewHotkeyAction::ViewScrollUp),
        "scroll_down" => Some(ViewHotkeyAction::ViewScrollDown),
        _ => None,
    }
}
