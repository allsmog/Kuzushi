use crate::app::line_editor::{command_completion_head, subsequence_score};
use crate::commands::{shell_command_specs, ShellCommandSpec};
use crate::{ShellApp, ShellView};

impl ShellApp {
    /// Open the fuzzy command palette, resetting its query and cursor.
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

    /// Load the selected command's canonical head into the prompt — never
    /// auto-execute, so the operator reviews (and completes any args) first.
    pub(crate) fn accept_palette(&mut self) {
        let cursor = self.router.command_palette().cursor();
        let head = self.palette_matches().get(cursor).map(|spec| {
            command_completion_head(spec.command).unwrap_or_else(|| spec.command.to_string())
        });
        if let Some(head) = head {
            self.set_input(head);
        }
        self.close_palette();
    }

    pub(crate) fn close_palette(&mut self) {
        self.go_back();
    }

    /// Specs whose command, aliases, or description fuzzy-match the query,
    /// ranked best-first (stable for ties).
    pub(crate) fn palette_matches(&self) -> Vec<&'static ShellCommandSpec> {
        let query = self.router.command_palette().query();
        let mut scored: Vec<(i32, usize, &'static ShellCommandSpec)> = shell_command_specs()
            .enumerate()
            .filter_map(|(idx, spec)| palette_score(spec, query).map(|score| (score, idx, spec)))
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        scored.into_iter().map(|(_, _, spec)| spec).collect()
    }
}

fn palette_score(spec: &ShellCommandSpec, query: &str) -> Option<i32> {
    std::iter::once(spec.command)
        .chain(spec.aliases.iter().copied())
        .chain(std::iter::once(spec.description))
        .filter_map(|haystack| subsequence_score(haystack, query))
        .max()
}
