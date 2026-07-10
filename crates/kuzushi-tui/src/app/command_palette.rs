use crate::app::line_editor::{command_completion_head, subsequence_score};
use crate::commands::shell_command_specs;
use crate::{ShellApp, ShellView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PaletteEntryKind {
    Command,
    Tool,
    Module,
}

impl PaletteEntryKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Tool => "tool",
            Self::Module => "module",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PaletteEntry {
    pub(crate) label: String,
    pub(crate) description: String,
    pub(crate) insert_text: String,
    pub(crate) kind: PaletteEntryKind,
    aliases: Vec<String>,
}

impl ShellApp {
    pub(crate) fn open_command_palette(&mut self) {
        self.router.command_palette_mut().reset();
        self.set_shell_view(ShellView::CommandPalette);
    }

    pub(crate) fn palette_input(&mut self, ch: char) {
        self.router.command_palette_mut().push_query(ch);
    }

    pub(crate) fn palette_backspace(&mut self) {
        self.router.command_palette_mut().pop_query();
    }

    pub(crate) fn palette_move(&mut self, delta: isize) {
        let len = self.palette_matches().len();
        self.router.command_palette_mut().move_cursor(delta, len);
    }

    pub(crate) fn accept_palette(&mut self) {
        let cursor = self.router.command_palette().cursor();
        let insert_text = self
            .palette_matches()
            .get(cursor)
            .map(|entry| entry.insert_text.clone());
        if let Some(insert_text) = insert_text {
            self.set_input(insert_text);
        }
        self.close_palette();
    }

    pub(crate) fn close_palette(&mut self) {
        self.go_back();
    }

    pub(crate) fn palette_matches(&self) -> Vec<PaletteEntry> {
        let query = self.router.command_palette().query();
        let mut scored = self
            .palette_entries()
            .into_iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                palette_score(&entry, query).map(|score| (score, index, entry))
            })
            .collect::<Vec<_>>();
        scored.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
        scored.into_iter().map(|(_, _, entry)| entry).collect()
    }

    pub(crate) fn palette_entry_count(&self) -> usize {
        self.palette_entries().len()
    }

    fn palette_entries(&self) -> Vec<PaletteEntry> {
        let mut entries = command_entries();
        entries.extend(self.registry().tools().map(tool_entry));
        entries.extend(self.registry().modules().map(module_entry));
        entries
    }
}

fn command_entries() -> Vec<PaletteEntry> {
    shell_command_specs()
        .map(|spec| PaletteEntry {
            label: spec.command.to_string(),
            description: spec.description.to_string(),
            insert_text: command_completion_head(spec.command)
                .unwrap_or_else(|| spec.command.to_string()),
            kind: PaletteEntryKind::Command,
            aliases: spec.aliases.iter().map(|alias| alias.to_string()).collect(),
        })
        .collect()
}

fn tool_entry(tool: &kuzushi_core::ToolDescriptor) -> PaletteEntry {
    PaletteEntry {
        label: tool.name.clone(),
        description: tool.description.clone(),
        insert_text: format!("run {} ", tool.name),
        kind: PaletteEntryKind::Tool,
        aliases: Vec::new(),
    }
}

fn module_entry(module: &kuzushi_core::BuiltinModule) -> PaletteEntry {
    PaletteEntry {
        label: module.metadata().id.clone(),
        description: module.metadata().description.clone(),
        insert_text: format!("use {}", module.metadata().id),
        kind: PaletteEntryKind::Module,
        aliases: vec![module.metadata().name.clone()],
    }
}

fn palette_score(entry: &PaletteEntry, query: &str) -> Option<i32> {
    if query.is_empty() {
        return Some(0);
    }
    let label_score = weighted_match(&entry.label, query, 200).unwrap_or(i32::MIN);
    let alias_score = entry
        .aliases
        .iter()
        .filter_map(|alias| weighted_match(alias, query, 100))
        .max()
        .unwrap_or(i32::MIN);
    let description_score = weighted_match(&entry.description, query, 0).unwrap_or(i32::MIN);
    let best = label_score.max(alias_score).max(description_score);
    (best != i32::MIN).then_some(best)
}

fn weighted_match(value: &str, query: &str, weight: i32) -> Option<i32> {
    let score = subsequence_score(value, query)?;
    let prefix_bonus = value
        .to_ascii_lowercase()
        .starts_with(&query.to_ascii_lowercase())
        .then_some(300)
        .unwrap_or(0);
    Some(score + weight + prefix_bonus)
}
