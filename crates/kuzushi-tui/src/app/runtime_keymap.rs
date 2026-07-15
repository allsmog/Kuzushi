use super::{ShellView, WorkbenchPage};
use crate::app::state_transitions::{HotkeyTrigger, ViewHotkeyAction, ViewKeybinding};
use crossterm::event::{KeyEvent, KeyModifiers};
use kuzushi_core::config::KeybindingOverrideConfig;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

mod parsing;
use parsing::{action_from_id, canonical_context, parse_sequence, parse_stroke, view_context};

const CHORD_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeKeymap {
    overrides: BTreeMap<(String, String), RuntimeBindingOverride>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct RuntimeBindingOverride {
    action: ViewHotkeyAction,
    sequences: Vec<KeySequence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeySequence {
    display: String,
    strokes: Vec<KeyStroke>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyStroke {
    code: StrokeCode,
    modifiers: KeyModifiers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StrokeCode {
    Char(char),
    Enter,
    Tab,
    BackTab,
    Esc,
    PageUp,
    PageDown,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    Delete,
    Backspace,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingKeyChord {
    context: String,
    first: KeyStroke,
    started_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfiguredKeyResult {
    NoMatch,
    Pending,
    Action(ViewHotkeyAction),
}

impl RuntimeKeymap {
    pub(crate) fn from_config(config: &[KeybindingOverrideConfig]) -> Self {
        match Self::parse(config) {
            Ok(keymap) => keymap,
            Err(error) => Self {
                overrides: BTreeMap::new(),
                error: Some(error),
            },
        }
    }

    fn parse(config: &[KeybindingOverrideConfig]) -> Result<Self, String> {
        let mut overrides = BTreeMap::new();
        let mut occupied = Vec::new();
        for entry in config {
            let (map_key, override_) = parse_override(entry, &mut occupied)?;
            insert_unique_override(&mut overrides, map_key, override_)?;
        }
        Ok(Self {
            overrides,
            error: None,
        })
    }

    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub(crate) fn overrides_action(&self, context: &str, action: &str) -> bool {
        self.overrides
            .contains_key(&(context.to_string(), action.to_ascii_lowercase()))
    }

    pub(crate) fn binding_labels(
        &self,
        context: &str,
        action: &str,
        defaults: &[&str],
    ) -> Vec<String> {
        self.overrides
            .get(&(context.to_string(), action.to_ascii_lowercase()))
            .map(|override_| {
                override_
                    .sequences
                    .iter()
                    .map(|sequence| sequence.display.clone())
                    .collect()
            })
            .unwrap_or_else(|| defaults.iter().map(|label| (*label).to_string()).collect())
    }

    pub(crate) fn apply_view_overrides(
        &self,
        view: ShellView,
        mut defaults: Vec<ViewKeybinding>,
    ) -> Vec<ViewKeybinding> {
        let Some(context) = view_context(view) else {
            return defaults;
        };
        let context_overrides = self
            .overrides
            .iter()
            .filter(|((candidate, _), _)| candidate == context)
            .collect::<Vec<_>>();
        if context_overrides.is_empty() {
            return defaults;
        }
        let mut configured = Vec::new();
        for ((_, action_id), override_) in context_overrides {
            let label = defaults
                .iter()
                .find(|binding| binding.action == override_.action)
                .map(|binding| binding.label.clone())
                .unwrap_or_else(|| action_id.replace('_', " "));
            defaults.retain(|binding| binding.action != override_.action);
            configured.extend(override_.sequences.iter().map(|sequence| ViewKeybinding {
                trigger: HotkeyTrigger::Never,
                hint: sequence.display.clone(),
                label: label.clone(),
                action: override_.action,
            }));
        }
        defaults.extend(configured);
        defaults
    }

    pub(crate) fn handle_shell_key(
        &self,
        view: ShellView,
        key: KeyEvent,
        pending: &mut Option<PendingKeyChord>,
        now: Instant,
    ) -> ConfiguredKeyResult {
        let mut contexts = vec!["global", "composer"];
        if let Some(context) = view_context(view) {
            contexts.push(context);
        }
        self.handle_contexts(&contexts, key, pending, now)
    }

    pub(crate) fn handle_context_key(
        &self,
        context: &str,
        key: KeyEvent,
        pending: &mut Option<PendingKeyChord>,
        now: Instant,
    ) -> ConfiguredKeyResult {
        self.handle_contexts(&[context], key, pending, now)
    }

    fn handle_contexts(
        &self,
        contexts: &[&str],
        key: KeyEvent,
        pending: &mut Option<PendingKeyChord>,
        now: Instant,
    ) -> ConfiguredKeyResult {
        let stroke = KeyStroke::from_event(key);
        if let Some(action) = self.take_chord_action(contexts, stroke, pending, now) {
            return ConfiguredKeyResult::Action(action);
        }
        for context in contexts {
            let result = self.context_key_result(context, stroke, pending, now);
            if result != ConfiguredKeyResult::NoMatch {
                return result;
            }
        }
        ConfiguredKeyResult::NoMatch
    }

    fn context_key_result(
        &self,
        context: &str,
        stroke: KeyStroke,
        pending: &mut Option<PendingKeyChord>,
        now: Instant,
    ) -> ConfiguredKeyResult {
        if let Some(action) = self.single_action(context, stroke) {
            return ConfiguredKeyResult::Action(action);
        }
        if !self.is_chord_prefix(context, stroke) {
            return ConfiguredKeyResult::NoMatch;
        }
        *pending = Some(PendingKeyChord {
            context: context.to_string(),
            first: stroke,
            started_at: now,
        });
        ConfiguredKeyResult::Pending
    }

    fn take_chord_action(
        &self,
        contexts: &[&str],
        stroke: KeyStroke,
        pending: &mut Option<PendingKeyChord>,
        now: Instant,
    ) -> Option<ViewHotkeyAction> {
        let chord = pending.take()?;
        let current_context = contexts.contains(&chord.context.as_str());
        let current_time = now.duration_since(chord.started_at) <= CHORD_TIMEOUT;
        (current_context && current_time)
            .then(|| self.chord_action(&chord.context, chord.first, stroke))
            .flatten()
    }

    fn matching_overrides<'a>(
        &'a self,
        context: &'a str,
    ) -> impl Iterator<Item = &'a RuntimeBindingOverride> + 'a {
        self.overrides
            .iter()
            .filter(move |((candidate, _), _)| candidate == context)
            .map(|(_, override_)| override_)
    }

    fn single_action(&self, context: &str, stroke: KeyStroke) -> Option<ViewHotkeyAction> {
        self.matching_overrides(context).find_map(|override_| {
            override_
                .sequences
                .iter()
                .any(|sequence| sequence.strokes.as_slice() == [stroke])
                .then_some(override_.action)
        })
    }

    fn chord_action(
        &self,
        context: &str,
        first: KeyStroke,
        second: KeyStroke,
    ) -> Option<ViewHotkeyAction> {
        self.matching_overrides(context).find_map(|override_| {
            override_
                .sequences
                .iter()
                .any(|sequence| sequence.strokes.as_slice() == [first, second])
                .then_some(override_.action)
        })
    }

    fn is_chord_prefix(&self, context: &str, stroke: KeyStroke) -> bool {
        self.matching_overrides(context).any(|override_| {
            override_.sequences.iter().any(|sequence| {
                sequence.strokes.len() == 2 && sequence.strokes.first() == Some(&stroke)
            })
        })
    }
}

fn parse_override(
    entry: &KeybindingOverrideConfig,
    occupied: &mut Vec<(String, Vec<KeyStroke>)>,
) -> Result<((String, String), RuntimeBindingOverride), String> {
    let context = canonical_context(&entry.context)?;
    let action_id = entry.action.trim().to_ascii_lowercase();
    let action = action_from_id(context, &action_id)?;
    let sequences = entry
        .bindings
        .iter()
        .map(|binding| parse_sequence(binding))
        .collect::<Result<Vec<_>, _>>()?;
    register_sequence_signatures(context, &sequences, occupied)?;
    Ok((
        (context.to_string(), action_id),
        RuntimeBindingOverride { action, sequences },
    ))
}

fn register_sequence_signatures(
    context: &str,
    sequences: &[KeySequence],
    occupied: &mut Vec<(String, Vec<KeyStroke>)>,
) -> Result<(), String> {
    for sequence in sequences {
        let signature = (context.to_string(), sequence.strokes.clone());
        if occupied.contains(&signature) {
            return Err(format!(
                "duplicate keybinding {} in context {context}",
                sequence.display
            ));
        }
        occupied.push(signature);
    }
    Ok(())
}

fn insert_unique_override(
    overrides: &mut BTreeMap<(String, String), RuntimeBindingOverride>,
    map_key: (String, String),
    override_: RuntimeBindingOverride,
) -> Result<(), String> {
    if overrides.contains_key(&map_key) {
        return Err(format!(
            "duplicate keybinding action {}.{}",
            map_key.0, map_key.1
        ));
    }
    overrides.insert(map_key, override_);
    Ok(())
}

#[cfg(test)]
mod tests;
