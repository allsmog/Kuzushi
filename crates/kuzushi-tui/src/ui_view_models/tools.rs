use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolsModel {
    pub(crate) rows: Vec<ToolRow>,
    pub(crate) total_count: usize,
    pub(crate) filter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolRow {
    pub(crate) cells: [String; 2],
}

pub(crate) fn tools_model(app: &ShellApp) -> ToolsModel {
    let filter = normalized_filter(app.tools_filter.as_deref());
    let tools = app.registry.tools().collect::<Vec<_>>();
    let rows = tools
        .iter()
        .filter(|tool| {
            filter.as_ref().map_or(true, |tokens| {
                tool_matches_filter(tool.name.as_str(), &tool.description, tokens)
            })
        })
        .map(|tool| ToolRow {
            cells: [tool.name.clone(), tool.description.clone()],
        })
        .collect();

    ToolsModel {
        rows,
        total_count: tools.len(),
        filter: app.tools_filter.clone(),
    }
}

fn normalized_filter(raw: Option<&str>) -> Option<Vec<String>> {
    let tokens = raw?
        .split_whitespace()
        .map(|token| token.to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    (!tokens.is_empty()).then_some(tokens)
}

fn tool_matches_filter(name: &str, description: &str, tokens: &[String]) -> bool {
    let haystack = format!("{name} {description}").to_ascii_lowercase();
    tokens.iter().all(|token| haystack.contains(token))
}

#[cfg(test)]
mod tests;
