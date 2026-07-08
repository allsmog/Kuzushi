use crate::ShellApp;
use kuzushi_core::modules::{ToolDescriptor, ToolPhase, ToolQuery};
use kuzushi_core::workspace::ToolShelf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolsModel {
    pub(crate) groups: Vec<ToolGroup>,
    pub(crate) visible_count: usize,
    pub(crate) total_count: usize,
    pub(crate) filter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolGroup {
    pub(crate) label: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) rows: Vec<ToolRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolRow {
    pub(crate) cells: [String; 3],
}

/// A scored `(module, tool)` pair used while grouping.
struct ScoredTool<'a> {
    tool: &'a ToolDescriptor,
    score: i32,
}

const YOUR_TOOLS_LABEL: &str = "YOUR TOOLS";

pub(crate) fn tools_model(app: &ShellApp) -> ToolsModel {
    let filter = app.router.tools().filter_clone();
    let shelf = app.tool_shelf();
    let query = filter
        .as_deref()
        .map(ToolQuery::parse)
        .transpose()
        .ok()
        .flatten();

    let matched = if filter.is_some() && query.is_none() {
        // A parse error yields no matches; the `find`/`tools` effect logs why.
        Vec::new()
    } else {
        scored_tools(app, query.as_ref(), shelf)
    };

    let groups = build_groups(&matched, shelf);
    let visible_count = groups
        .iter()
        .filter(|group| group.label != YOUR_TOOLS_LABEL)
        .map(|group| group.rows.len())
        .sum();
    ToolsModel {
        groups,
        visible_count,
        total_count: app.registry().tools_with_modules().count(),
        filter,
    }
}

fn scored_tools<'a>(
    app: &'a ShellApp,
    query: Option<&ToolQuery>,
    shelf: &ToolShelf,
) -> Vec<ScoredTool<'a>> {
    app.registry()
        .tools_with_modules()
        .filter(|(module, tool)| query.is_none_or(|q| q.matches(module, tool, shelf)))
        .map(|(module, tool)| ScoredTool {
            tool,
            score: query.and_then(|q| q.score(module, tool)).unwrap_or(0),
        })
        .collect()
}

fn build_groups(matched: &[ScoredTool<'_>], shelf: &ToolShelf) -> Vec<ToolGroup> {
    let mut groups = Vec::new();
    if let Some(shortlist) = shortlist_group(matched, shelf) {
        groups.push(shortlist);
    }
    for phase in ToolPhase::ORDER {
        if let Some(group) = phase_group(matched, phase) {
            groups.push(group);
        }
    }
    groups
}

fn shortlist_group(matched: &[ScoredTool<'_>], shelf: &ToolShelf) -> Option<ToolGroup> {
    let rows: Vec<ToolRow> = shelf
        .shortlist()
        .into_iter()
        .filter_map(|name| matched.iter().find(|scored| scored.tool.name == name))
        .map(|scored| shortlist_row(scored.tool, shelf))
        .collect();
    (!rows.is_empty()).then_some(ToolGroup {
        label: YOUR_TOOLS_LABEL,
        hint: "favorites and recently used",
        rows,
    })
}

fn phase_group(matched: &[ScoredTool<'_>], phase: ToolPhase) -> Option<ToolGroup> {
    let mut in_phase: Vec<&ScoredTool<'_>> = matched
        .iter()
        .filter(|scored| scored.tool.phase == phase)
        .collect();
    in_phase.sort_by(|a, b| b.score.cmp(&a.score).then(a.tool.name.cmp(&b.tool.name)));
    let rows: Vec<ToolRow> = in_phase.iter().map(|scored| tool_row(scored.tool)).collect();
    (!rows.is_empty()).then_some(ToolGroup {
        label: phase.label(),
        hint: phase.hint(),
        rows,
    })
}

fn shortlist_row(tool: &ToolDescriptor, shelf: &ToolShelf) -> ToolRow {
    let marker = if shelf.is_favorite(&tool.name) {
        "★ "
    } else {
        "  "
    };
    ToolRow {
        cells: [
            format!("{marker}{}", tool.name),
            concise_tool_description(&tool.description),
            tool_next_command(tool),
        ],
    }
}

fn tool_row(tool: &ToolDescriptor) -> ToolRow {
    ToolRow {
        cells: [
            tool.name.clone(),
            concise_tool_description(&tool.description),
            tool_next_command(tool),
        ],
    }
}

fn concise_tool_description(description: &str) -> String {
    description
        .split('.')
        .next()
        .unwrap_or(description)
        .trim()
        .to_string()
}

fn tool_next_command(tool: &ToolDescriptor) -> String {
    if tool.options.is_empty() {
        format!("run {}", tool.name)
    } else {
        format!("options {}", tool.name)
    }
}

#[cfg(test)]
mod tests;
