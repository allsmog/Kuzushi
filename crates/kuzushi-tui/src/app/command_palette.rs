use crate::app::line_editor::{command_completion_head, subsequence_score};
use crate::app::ShellEffect;
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
    /// Section heading the entry groups under while browsing (empty query).
    pub(crate) category: &'static str,
    /// Shortest invocation form, shown as the row's discoverability hint
    /// (`?` for help, `m` for modules). Empty when the label is the shortest.
    pub(crate) hint: String,
    /// Whether Enter dispatches immediately. True for commands with no
    /// argument grammar and for module navigation; tools insert `run <tool> `
    /// so the operator confirms or extends the dispatch.
    pub(crate) executes: bool,
    aliases: Vec<String>,
}

impl ShellApp {
    pub(crate) fn open_command_palette(&mut self) {
        let entries = self.build_palette_entries();
        let palette = self.router.command_palette_mut();
        palette.reset();
        palette.set_entries(entries);
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

    /// Enter on a zero-argument command or module dispatches it directly —
    /// the palette is a command surface, not a typing aid. Arg-taking entries
    /// load the prompt so the operator finishes the invocation.
    pub(crate) fn accept_palette(&mut self) -> Vec<ShellEffect> {
        let cursor = self.router.command_palette().cursor();
        let Some(entry) = self.palette_matches().get(cursor).cloned() else {
            self.close_palette();
            return Vec::new();
        };
        self.close_palette();
        if entry.executes {
            return self.reduce_submitted_line(&entry.insert_text).effects;
        }
        self.set_input(entry.insert_text);
        Vec::new()
    }

    pub(crate) fn close_palette(&mut self) {
        self.go_back();
    }

    pub(crate) fn palette_matches(&self) -> Vec<PaletteEntry> {
        let palette = self.router.command_palette();
        let query = palette.query();
        let mut scored = palette
            .entries()
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                palette_score(entry, query).map(|score| (score, index, entry.clone()))
            })
            .collect::<Vec<_>>();
        scored.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
        scored.into_iter().map(|(_, _, entry)| entry).collect()
    }

    pub(crate) fn palette_entry_count(&self) -> usize {
        self.router.command_palette().entries().len()
    }

    /// Snapshot taken once at palette open — never rebuilt per keystroke.
    fn build_palette_entries(&self) -> Vec<PaletteEntry> {
        let mut entries = command_entries();
        entries.extend(self.registry().discoverable_tools().map(tool_entry));
        entries.extend(self.registry().discoverable_modules().map(module_entry));
        entries
    }
}

fn command_entries() -> Vec<PaletteEntry> {
    shell_command_specs()
        .map(|spec| {
            let head =
                command_completion_head(spec.command).unwrap_or_else(|| spec.command.to_string());
            PaletteEntry {
                label: spec.command.to_string(),
                description: spec.description.to_string(),
                executes: spec.command == head,
                insert_text: head,
                kind: PaletteEntryKind::Command,
                category: spec.category.label(),
                hint: shortest_alias(spec.command, spec.aliases),
                aliases: spec.aliases.iter().map(|alias| alias.to_string()).collect(),
            }
        })
        .collect()
}

/// The shortest way to invoke the command, when shorter than the command
/// itself — the palette doubles as alias discovery.
fn shortest_alias(command: &str, aliases: &[&str]) -> String {
    aliases
        .iter()
        .filter(|alias| !alias.starts_with('/'))
        .min_by_key(|alias| alias.len())
        .filter(|alias| alias.len() < command.len())
        .map(|alias| alias.to_string())
        .unwrap_or_default()
}

fn tool_entry(tool: &kuzushi_core::ToolDescriptor) -> PaletteEntry {
    PaletteEntry {
        label: tool.name.clone(),
        description: tool.description.clone(),
        insert_text: format!("run {} ", tool.name),
        kind: PaletteEntryKind::Tool,
        category: "TOOLS",
        hint: String::new(),
        executes: false,
        aliases: Vec::new(),
    }
}

fn module_entry(module: &kuzushi_core::BuiltinModule) -> PaletteEntry {
    PaletteEntry {
        label: module.metadata().id.clone(),
        description: module.metadata().description.clone(),
        insert_text: format!("use {}", module.metadata().id),
        kind: PaletteEntryKind::Module,
        category: "MODULES",
        hint: String::new(),
        executes: true,
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
